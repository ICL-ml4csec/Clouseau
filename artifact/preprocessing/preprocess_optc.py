import json
import pandas as pd
import os
import sqlite3
import argparse

from io import StringIO
from datetime import datetime

def get_process_record(conn, pid):
    """
    Returns the first CREATE event record for a process instance with the given pid.
    Fields returned: (rowid, ts, pid, ppid, process_name, cmd_line)
    If no CREATE event is found, returns None.
    """
    cur = conn.execute("""
        SELECT rowid, ts, pid, ppid, process_name, cmd_line 
        FROM processes_logs 
        WHERE action = 'CREATE' AND pid = ?
        ORDER BY ts ASC LIMIT 1
    """, (pid,))
    return cur.fetchone()

def get_children(conn, parent_pid):
    """
    Returns a list of child process records (CREATE events only)
    for the given parent pid, ordered by timestamp.
    Each record is a tuple: (rowid, ts, pid, process_name, ppid)
    Note: We include ppid here to facilitate any additional processing.
    """
    cur = conn.execute("""
        SELECT rowid, ts, pid, process_name, ppid, cmd_line 
        FROM processes_logs 
        WHERE action = 'CREATE' AND ppid = ?
        ORDER BY ts ASC
    """, (parent_pid,))
    return cur.fetchall()

# --- Execution Tree Printing Functions ---

def print_lineage(conn, target_record):
    """
    Builds and prints the lineage (ancestor chain) for the given process record.
    The chain is built by repeatedly fetching the parent process via the ppid field.
    """
    ancestors = []
    current = target_record
    # current tuple: (rowid, ts, pid, ppid, process_name, cmd_line)
    while True:
        parent_pid = current[3]  # ppid
        if parent_pid is None:
            break
        parent_record = get_process_record(conn, parent_pid)
        if not parent_record:
            # Parent record not found (e.g. process created before collection window)
            break
        # Insert parent at beginning so that the oldest ancestor is first.
        if parse_ts(parent_record[1]) > parse_ts(current[1]):
            # If the parent was created after the current process, we hit a wall.
            break

        ancestors.insert(0, parent_record)
        current = parent_record

    print("Lineage (Ancestors):")
    for anc in ancestors:
        # Print format: "  <pid> - <process_name> - <timestamp>"
        print("  {} - {} - {} - {}".format(anc[2], anc[4], anc[1], anc[5]))
    # Print the target process with arrow, as the leaf of the lineage.
    print("--> {} - {} - {} - {}".format(target_record[2], target_record[4], target_record[1], target_record[5]))
    print("")

def print_descendants(conn, parent_pid, prefix=""):
    """
    Recursively prints the descendant tree starting from the given parent_pid.
    Uses a visual tree style with branching characters.
    """
    children = get_children(conn, parent_pid)
    if not children:
        return
    for idx, child in enumerate(children):
        # Determine the proper branch graphic.
        is_last = (idx == len(children) - 1)
        branch = "└── " if is_last else "├── "
        # Child record format: (rowid, ts, pid, process_name, ppid, cmd_line)
        line = prefix + branch + "{} - {} - {} - {}".format(child[2], child[3], child[1], child[5])
        print(line)
        # Prepare a new prefix for the next level:
        new_prefix = prefix + ("    " if is_last else "│   ")
        print_descendants(conn, child[2], new_prefix)

def print_execution_tree(conn, target_pid):
    """
    Prints the full execution tree for a target process id.
    This includes:
      - Ancestor lineage (parents).
      - Descendant tree (children and grandchildren).
    """
    target = get_process_record(conn, target_pid)
    if not target:
        print(f"No CREATE event found for pid {target_pid}. It may have been created outside the collection window.")
        return

    header = "=" * 40
    print(header)
    print(f"Execution Tree for Instance (pid {target[2]}):")
    print("")
    # Print the ancestor chain.
    print_lineage(conn, target)
    # Print the descendant tree.
    print("Descendant Tree:")
    # Print the target process at the root.
    print("{} - {} - {} - {}".format(target[2], target[4], target[1], target[5]))
    print_descendants(conn, target[2])
    print(header)

def create_ground_truth(con: sqlite3.Connection, mal_pids: str):
    artifacts_count = len(mal_pids.split(","))
    # Execute multiple SQL statements in one call using executescript

    con.executescript(f"""
        DROP TABLE IF EXISTS labels;
        CREATE TABLE labels AS SELECT DISTINCT pid, ppid, process_name FROM processes_logs;
        ALTER TABLE labels ADD COLUMN mal BOOL;
        UPDATE labels SET mal = FALSE;
        UPDATE labels SET mal = TRUE WHERE pid IN ({mal_pids});
    """)
    con.commit()

    # find their descendants and set them to malicious
    # repeat untill all descendants are set to malicious
    while True:
        # Update any process whose parent (ppid) is already malicious.
        cursor = con.execute("""
            UPDATE labels
            SET mal = TRUE
            WHERE mal = FALSE 
                AND ppid IN (SELECT DISTINCT pid FROM labels WHERE mal = TRUE)
        """)
        con.commit()
        updated = cursor.rowcount
        artifacts_count += updated
        #print(f"Rows updated in iteration: {updated}")
        # If no rows were updated in this iteration, break out of the loop.
        if updated == 0:
            break

    print(f"Total artifacts (malicious processes) found: {artifacts_count}")
    # Create the view that consolidates all logs
    con.executescript("""
        ALTER TABLE all_logs ADD COLUMN mal BOOL;
        UPDATE all_logs SET mal = FALSE;
        UPDATE all_logs SET mal = TRUE WHERE pid IN (SELECT pid FROM labels WHERE mal = TRUE);
    """)
    con.commit()

    # print all malicious events count
    cursor = con.execute("SELECT COUNT(*) FROM all_logs WHERE mal = 1")
    malicious_count = cursor.fetchone()[0]
    print(f"Total malicious events found: {malicious_count}")
    # print all benign events count
    cursor = con.execute("SELECT COUNT(*) FROM all_logs WHERE mal = 0")
    benign_count = cursor.fetchone()[0]
    print(f"Total benign events found: {benign_count}")

def parse_ts(ts_str: str) -> datetime:
    """
    Parse a timestamp string into a datetime object.
    """
    if '.' not in ts_str:
        return datetime.strptime(ts_str, "%H:%M:%S")
    else:
        return datetime.strptime(ts_str, "%H:%M:%S.%f")

def get_max_pid(conn: sqlite3.Connection) -> int:
    """
    Get the maximum pid currently in the database.
    This is used to generate new unique pids.
    """
    cur = conn.execute("SELECT MAX(pid) FROM processes_logs")
    max_pid = cur.fetchone()[0]
    return max_pid if max_pid is not None else 0

def update_reused_pids(conn: sqlite3.Connection):
    cur = conn.execute("""
        SELECT rowid, ts, pid, process_name
        FROM processes_logs
        WHERE action = 'CREATE'
        ORDER BY ts ASC
    """)
    creation_events = cur.fetchall()

    events_by_pid = {}
    for row in creation_events:
        rowid, ts, pid, proc_name = row
        events_by_pid.setdefault(pid, []).append((rowid, ts, parse_ts(ts), proc_name))
    
    pid_mapping = {}
    new_pid_counter = get_max_pid(conn) + 1

    for pid, events in events_by_pid.items():
        events.sort(key=lambda x: x[2])
        first_event = events[0]
        pid_mapping[(pid, first_event[1])] = (pid, first_event[3])
        conn.execute(
            "UPDATE processes_logs SET pid = ?, process_name = ? WHERE rowid = ?",
            (pid, first_event[3], first_event[0])
        )
        
        for event in events[1:]:
            rowid, create_ts, create_dt, canonical_proc_name = event
            new_pid = new_pid_counter
            new_pid_counter += 1
            pid_mapping[(pid, create_ts)] = (new_pid, canonical_proc_name)
            conn.execute(
                "UPDATE processes_logs SET pid = ?, process_name = ? WHERE rowid = ?",
                (new_pid, canonical_proc_name, rowid)
            )
            cur_term = conn.execute("""
                SELECT rowid, ts FROM processes_logs
                WHERE pid = ? AND action = 'TERMINATE' AND ts > ?
                ORDER BY ts ASC
                LIMIT 1
            """, (pid, create_ts))
            term_row = cur_term.fetchone()
            if term_row:
                term_rowid, term_ts = term_row
                conn.execute(
                    "UPDATE processes_logs SET pid = ?, process_name = ? WHERE rowid = ?",
                    (new_pid, canonical_proc_name, term_rowid)
                )
            print(f"PID {pid} reused at {create_ts}: updated to new pid {new_pid} with process_name '{canonical_proc_name}'")
    conn.commit()

    parent_instances = {}
    for pid, events in events_by_pid.items():
        if len(events) > 1:
            events.sort(key=lambda x: x[2])
            instances = []
            for event in events:
                rowid, create_ts, create_dt, canonical_proc_name = event
                new_pid, _ = pid_mapping[(pid, create_ts)]
                instances.append((create_dt, new_pid, canonical_proc_name))
            parent_instances[pid] = instances

        else:
            event = events[0]
            rowid, create_ts, create_dt, canonical_proc_name = event
            pid_mapping[(pid, create_ts)] = (pid, canonical_proc_name)
            parent_instances.setdefault(pid, []).append((create_dt, pid, canonical_proc_name))

    duplicate_pids = list(parent_instances.keys())
    if duplicate_pids:
        placeholders = ",".join("?" for _ in duplicate_pids)
        query = f"""
            SELECT rowid, ts, ppid
            FROM processes_logs
            WHERE ppid IN ({placeholders})
            ORDER BY ts ASC
        """
        cur = conn.execute(query, duplicate_pids)
        children = cur.fetchall()

        for child in children:
            child_rowid, child_ts, child_ppid = child
            child_time = parse_ts(child_ts)
            instances = parent_instances.get(child_ppid, [])
            chosen_new_pid = None
            for create_dt, assigned_pid, canonical_proc_name in instances:
                if create_dt <= child_time:
                    chosen_new_pid = assigned_pid
                else:
                    break
            if chosen_new_pid:
                conn.execute(
                    "UPDATE processes_logs SET ppid = ? WHERE rowid = ?",
                    (chosen_new_pid, child_rowid)
                )
        conn.commit()

    if duplicate_pids:
        table_names = ['file_logs', 'flow_logs', 'all_logs']
        for t in table_names:
            placeholders = ",".join("?" for _ in duplicate_pids)
            query = f"""
                SELECT rowid, ts, pid
                FROM {t}
                WHERE pid IN ({placeholders})
                ORDER BY ts ASC
            """
            cur = conn.execute(query, duplicate_pids)
            records = cur.fetchall()

            for record in records:
                record_rowid, record_ts, record_pid = record
                record_time = parse_ts(record_ts)
                instances = parent_instances.get(record_pid, [])
                chosen_new_pid = None
                chosen_canonical_name = None
                for create_dt, assigned_pid, canonical_proc_name in instances:
                    if create_dt <= record_time:
                        chosen_new_pid = assigned_pid
                        chosen_canonical_name = canonical_proc_name
                    else:
                        break
                if chosen_new_pid:
                    conn.execute(
                        f"UPDATE {t} SET pid = ?, process_name = ? WHERE rowid = ?",
                        (chosen_new_pid, chosen_canonical_name, record_rowid)
                    )
            conn.commit()

    print("All updates completed.")

def extract_dns_events(d: str) -> pd.DataFrame:
    files = []
    for fname in os.listdir(d):
        if fname.endswith(".log") and fname.startswith("dns."):
            files.append(os.path.join(d, fname))

    columns = None
    data_lines = []
    for fname in files:
        with open(fname, "r") as f:
            for line in f:
                if line.startswith("#fields"):
                    # Extract header names from the #fields line (skip the "#fields" token)
                    columns = line.split()[1:]
                elif line.startswith("#"):
                    # Skip other header lines
                    continue
                else:
                    if line.split()[13] != "A":
                        continue
                    data_lines.append(line)

                
    # If no data lines remain after filtering, return an empty DataFrame with the expected columns.
    if not data_lines or columns is None:
        return pd.DataFrame(columns=["query", "answers"])
    

    # Combine the filtered lines into a single string.
    data_str = "\n".join(data_lines)
    
    # Read the data into a DataFrame using a tab separator.
    df = pd.read_csv(StringIO(data_str), sep='\t', names=columns, header=None)
    dns_df = df[["query", "answers"]].copy()
    dns_df.dropna(subset=["query", "answers"], inplace=True)
    # drop duplicates
    dns_df.drop_duplicates(subset=["query", "answers"], inplace=True)
    # drop rows where answer is -
    dns_df.drop(dns_df[dns_df["answers"] == "-"].index, inplace=True)
    return dns_df

def extract_http_events(d: str, filter_str: str, incident_day: str) -> pd.DataFrame:
    files = []
    for fname in os.listdir(d):
        if fname.endswith(".log") and fname.startswith("http."):
            files.append(os.path.join(d, fname))

    columns = None
    data_lines = []
    for fname in files:
        with open(fname, "r") as f:
            for line in f:
                if line.startswith("#fields"):
                    # Extract header names from the #fields line (skip the "#fields" token)
                    columns = line.split()[1:]
                elif line.startswith("#"):
                    # Skip other header lines
                    continue
                else:
                    if filter_str in line:
                        data_lines.append(line)
    
    # Combine the filtered lines into a single string.
    data_str = "\n".join(data_lines)
    
    # Read the data into a DataFrame using a tab separator.
    df = pd.read_csv(StringIO(data_str), sep='\t', names=columns, header=None)
    df["ts"] = (pd.to_datetime(df["ts"], unit="s") - pd.Timedelta(hours=4))
    df = df[pd.to_datetime(df["ts"], unit="s").dt.strftime("%Y-%m-%d") == incident_day]
    df["ts"] = pd.to_datetime(df["ts"], unit="s").dt.strftime("%H:%M:%S")

    # Replace unset fields denoted by '-' with missing values.
    df.replace("-", pd.NA, inplace=True)
    
    # Return only the required columns.
    df_http = df[["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "host", "uri", "method", "request_body_len", "response_body_len"]]
    # rename df_http columns
    df_http.columns = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "host", "uri", "method", "request_body_len", "resp_body_len"]
    return df_http

def process_audit_line(line: str, ip_addr: str) -> dict:

    line = line.replace(r"\\Device\\HarddiskVolume1", "C:")
    line = line.replace(r"%SystemRoot%", "C:Windows")
    line = line.replace(r"%ProgramFiles%", "C:Program Files")
    line = line.replace(r"%ProgramFiles(x86)%", "C:Program Files (x86)")
    line = line.replace(r"\\??\\","")
    line = line.replace(r"\\\\?\\","")
    data = json.loads(line)

    # Only process lines from a specific day
    log_event = {}
    log_event['ts'] = data["timestamp"].split("T")[1].split("-")[0]
    log_event['pid'] = data["pid"]
    log_event['process_name'] = data["properties"].pop("image_path", None)
    log_event['type'] = "NA"

    #if data['object'] in ["THREAD", "MODULE", "TASK", "SHELL", "USER_SESSION", "REGISTRY"]:
    if data['object'] not in ["PROCESS", "FLOW", "FILE"]:
        return log_event

    if data['object'] == "PROCESS":
        if data['action'] not in ["CREATE", "TERMINATE"]:
            return log_event
        
        log_event['type'] = "PROCESS"
        log_event['user'] = data["principal"]
        log_event['action'] = data["action"]
        log_event['ppid'] = data["ppid"]
        log_event['cmd_line'] = data["properties"].pop("command_line", None)
        #log_event['parent_process'] = data["properties"].pop("parent_image_path", None)

    if data['object'] == "FLOW":
        if data['action'] not in ["MESSAGE"]:
            return log_event
        
        if ip_addr not in json.dumps(data["properties"]):
            return log_event
    
        src_ip = data["properties"].pop("src_ip", None)
        dst_ip = data["properties"].pop("dest_ip", None)
        src_port = data["properties"].pop("src_port", None)
        dst_port = data["properties"].pop("dest_port", None)
        direction = data["properties"].pop("direction", None)
        
        if direction == "outbound":
            log_event['ip'] = dst_ip
            log_event['port'] = dst_port
            log_event['host_address'] = src_ip
            log_event['host_port'] = src_port
        else:
            log_event['ip'] = src_ip
            log_event['port'] = src_port
            log_event['host_address'] = dst_ip
            log_event['host_port'] = dst_port

        # MESSAGE_FLOW
        log_event['type'] = "FLOW"
        log_event['direction'] = direction
        log_event['protocol'] = data["properties"].pop("l4protocol", None)
        log_event['size'] = int(data["properties"].pop("size", 0))


    if data['object'] == "FILE":
        if data['action'] not in ["CREATE", "DELETE", "WRITE", "READ", "RENAME"]:
            return log_event
        
        log_event['type'] = "FILE"
        log_event['action'] = data["action"]
        log_event['file_path'] = data["properties"].pop("file_path", None)
        log_event['size'] = int(data["properties"].pop("size", 0))

        if log_event['file_path'] is None:
            return log_event
        
        elif data['action'] == "RENAME":
            log_event['file_path'] += f' -> {data["properties"].pop("new_path", None)}'

    return log_event

def extract_ecar_events(dir: str, day_date: str, ip_addr: str, host_str: str) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    host_logs = []
    csv_rows_process = []
    csv_rows_flow = []
    csv_rows_files = []
    csv_rows = []

    for fname in os.listdir(dir):
        if fname.endswith(".json"):
            with open(os.path.join(dir, fname), "r") as f:
                for line in f:
                    if host_str in line and day_date in line:
                        host_logs.append(line)

    for line in host_logs:
        line_data = process_audit_line(line, ip_addr)
        csv_rows.append(line_data)
        if line_data is not None:
            if line_data['type'] == "PROCESS":
                csv_rows_process.append(line_data)
            elif line_data['type'] == "FLOW":
                csv_rows_flow.append(line_data)
            elif line_data['type'] == "FILE":
                csv_rows_files.append(line_data)

    print(f"total events: {len(csv_rows)}")
    print(f"total processes: {len(csv_rows_process)}")
    print(f"total flows: {len(csv_rows_flow)}")
    print(f"total files ops: {len(csv_rows_files)}")
    df_events = pd.DataFrame(csv_rows)[['ts', 'pid', 'process_name']]
    df_processes = pd.DataFrame(csv_rows_process)
    df_flow = pd.DataFrame(csv_rows_flow)
    df_files = pd.DataFrame(csv_rows_files)
    df_processes.drop(columns=['type'], inplace=True)
    df_flow.drop(columns=['type'], inplace=True)
    df_files.drop(columns=['type'], inplace=True)
    df_events.sort_values(by='ts', inplace=True)
    df_processes.sort_values(by='ts', inplace=True)
    df_flow.sort_values(by='ts', inplace=True)
    df_files.sort_values(by='ts', inplace=True)
    return df_events, df_processes, df_flow, df_files

def preprocess_opt_scenario(raw_files_path: str, db_path: str, ip_addr: str, incident_day: str, host_name: str, malicious_processes: list[int]):
    ecar_files = os.path.join(raw_files_path, "ecar")
    dns_files = os.path.join(raw_files_path, "bro")
    http_files = os.path.join(raw_files_path, "bro")
    df_events, df_process, df_flow, df_files = extract_ecar_events(ecar_files, incident_day, ip_addr, host_name)
    df_dns_result = extract_dns_events(dns_files)
    df_http_result = extract_http_events(http_files, ip_addr, incident_day)

    os.makedirs(db_path, exist_ok=True)
    with sqlite3.connect(os.path.join(db_path, 'scenario.db')) as con:
        df_process.to_sql("processes_logs", con=con, if_exists="replace", index=False)
        df_flow.to_sql("flow_logs", con=con, if_exists="replace", index=False)
        df_files.to_sql("file_logs", con=con, if_exists="replace", index=False)
        df_dns_result.to_sql("dns_logs", con=con, if_exists="replace", index=False)
        df_http_result.to_sql("http_logs", con=con, if_exists="replace", index=False)
        df_events.to_sql("all_logs", con=con, if_exists="replace", index=False)
        update_reused_pids(con)
        create_ground_truth(con, ",".join(map(str, malicious_processes)))



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Preprocess OPTC raw logs into SQLite DB for evaluation and benchmarking. "
    )
    parser.add_argument(
        "-r", "--raw-logs-path",
        dest="raw_logs_path",
        help="Path to OPTC raw logs directory (e.g. optc/)"
    )
    parser.add_argument(
        "-d", "--dest-path",
        dest="dest_logs_path",
        help="Destination directory for processed outputs (csvs and .db files)"
    )
    parser.add_argument(
        "--delete-existing",
        dest="delete_existing",
        action="store_true",
        help="If set, existing destination files will be removed before processing"
    )

    args = parser.parse_args()
    raw_logs_path = args.raw_logs_path if args.raw_logs_path else "optc"
    dest_logs_path = args.dest_logs_path if args.dest_logs_path else "scenarios"
    delete_existing = args.delete_existing if args.delete_existing else False

    ### GT for the scenarios
    # we use process ids to identify malicious processes
    # these ids are updated ones, as in the raw logs the processes ids are not unique
    # and are reused by the system (thanks Windows!).
    # during data preprocessing, we update the process ids to be unique
    # and we use these updated ids to identify malicious processes
    # Malicious processes are ones spawned by the malicious actor for pure malicios purpose
    # Tainted processes are legitimate processes exploited by malicious actor to perform malicious actions

    ### CASE 1
    m201_malicious = [ 
        6587, # cmd.exe, to execute runme.bat (VL8B5T3U)
        7258, # powershell.exe, spawns milion of processes to ping and find other hosts (LUAVR71T)
        ]

    m201_tainted = [
        3520, # firefox.exe opens news.com and downloads runme.bat
        ]

    ### CASE 2
    m501_malicious = [ 
        5244, # winword.exe opens payroll.docx and spawns powershell.exe that connects to news.com
        7740, 9703, # powershell.exe, cmd.exe spawining filetransfer.exe and connecting to news.com
        1748, # wmiprvse.exe, spawns 2 powershells.exe connecting 202.6.172.98 which spawns plink.exe
        ]

    m501_tainted = [
        8804, # login of admin user from DC1, obtained illegally
    ]


    ### CASE 3
    m051_malicious = [ 
        8402, # cKfGW.exe migrate to lsass.exe at 568
        5164, # csscript.exe spawned by 568, spawns many malicious processes
        4504, 8598, # Rerun of update.exe
    ]
    
    m051_tainted = [
        568, # lsass.exe, the process that is used to start cscript.exe, malicious actor migrated to it
    ]   

    cases_configs = {
        "opt1": {
            "name": "OPT1",
            "raw": os.path.join(raw_logs_path, "OPT1"),
            "dest": os.path.join(dest_logs_path, "OPT1"),
            "host": "SysClient0201.systemia.com",
            "ip": "142.20.56.202",
            "date": "2019-09-23",
            "malicious": m201_malicious,
            "tainted": m201_tainted
        },
        "opt2": {
            "name": "OPT2",
            "raw": os.path.join(raw_logs_path, "OPT2"),
            "dest": os.path.join(dest_logs_path, "OPT2"),
            "host": "SysClient0501.systemia.com",
            "ip": "142.20.57.246",
            "date": "2019-09-24",
            "malicious": m501_malicious,
            "tainted": m501_tainted
        },
        "opt3": {
            "name": "OPT3",
            "raw": os.path.join(raw_logs_path, "OPT3"),
            "dest": os.path.join(dest_logs_path, "OPT3"),
            "host": "SysClient0051.systemia.com",
            "ip": "142.20.56.52",
            "date": "2019-09-25",
            "malicious": m051_malicious,
            "tainted": m051_tainted
        }
    }

    if delete_existing:
        if os.path.exists(dest_logs_path):
            for case in cases_configs.values():
                if os.path.exists(case["dest"]):
                    os.rmdir(case["dest"])
    
    for case in cases_configs.values():
        preprocess_opt_scenario(
            case["raw"],
            case["dest"],
            case["ip"],
            case["date"],
            case["host"],
            case["malicious"]
        )