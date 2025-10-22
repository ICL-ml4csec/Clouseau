from datetime import datetime, timedelta, date
from typing import List, Tuple
from collections import defaultdict
import tldextract
import pandas as pd
import os
import sqlite3
import pytz
import shutil
import re
import argparse

# copy-pasta from ATLAS preprocess.py
def order_events(preprocessing_lines):
	preprocessing_lines.sort()
	for i in range(0, len(preprocessing_lines)):
		node = preprocessing_lines[i]
		if "a" in node[:node.find(',')]:
			preprocessing_lines[i] = str(int(node[:node.find('a')])) + node[node.find(','):] + "\n"
		elif "b" in node[:node.find(',')]:
			preprocessing_lines[i] = str(int(node[:node.find('b')])) + node[node.find(','):] + "\n"
		elif "c" in node[:node.find(',')]:
			preprocessing_lines[i] = str(int(node[:node.find('c')])) + node[node.find(','):] + "\n"

def is_matched(string, malicious_labels):
    for label in malicious_labels:
        if label in string:
            return True
    return False

# preprocess dns log
def pp_dns(preprocessing_lines, malicious_labels, path):
    log_file_path = path + '/dns'
    event_number = 1

    with open(log_file_path, 'r') as f:
        pre_out_line = ',' * 19
        for line in f:
            if not 'response' in line:
                continue
    
            out_line = ''
            splitted_line = line.split()
            no = splitted_line[0]
            time = splitted_line[1] + " " + splitted_line[2]
            ip_src = splitted_line[3]
            ip_dst = splitted_line[5]
            proto = splitted_line[6]
            length = splitted_line[7]
            info = ""
            for i in range(8, len(splitted_line)):
                info += splitted_line[i] + " "

            event_date = splitted_line[1]
            year, month, day = event_date.split('-')
            day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
            date_val = str(int(day_of_year) * 24 * 60 * 60)

            timestamp = time.split()[1].split('.')[0]
            h, m, s = timestamp.split(':')
            out_line += str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "a" + str(event_number)
            event_number += 1
            # queried domain
            q_domain = re.findall(r'response 0x\S+ A+ (\S+) ', info)
            if q_domain:
                out_line += ',' + q_domain[0]
            else:
                out_line += ','
    
            # resolved ip
            r_ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', info)
            if r_ip:
                out_line += ',' + r_ip[0]
            else:
                out_line += ','
    
            # remaining fields is empty
            for i in range(0, 17):
                out_line += ','
    
            # write lines out, remove adjacent duplicate entries
            if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
                matched = False
                if is_matched(out_line, malicious_labels):
                    matched = True
                if not ",,,,,,,,,,,,,,,,,,," in out_line:
                    if matched:
                        #wf.write(out_line + '-LD+\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LD+') #  + event_date + " " + timestamp
                    else:
                        #wf.write(out_line + '-LD-\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LD-') #  + event_date + " " + timestamp
                    pre_out_line = out_line

# preprocess audit log for windows x64 & x86
def pp_audit_w(preprocessing_lines, malicious_labels, path):
    timestamp = ""
    h, m, s = "", "", ""
    pid = 0
    ppid = 0
    new_pid = 0
    new_ppid = 0
    pname = ""
    first_iter = True
    d_ip = ""
    d_port = ""
    s_ip = ""
    s_port = ""
    acct = ""
    objname = ""
    log_file_path = path + '/security_events.txt'
    event_number = 1
    accesses_lines = False
    accesses = ""
    network_direction = ""
    process_parent = {}


    with open(log_file_path, 'r') as f:
        f.readline()
        single_line = []
        inside_accesses_block = False
        accesses = "Accesses:"
        for line in f:
            if line.lstrip().startswith("Accesses:") or inside_accesses_block:
                access_line = line
                if len(access_line.strip()) > 1:
                    if "Accesses:" in access_line:
                        inside_accesses_block = True
                        access_line = access_line.split("Accesses:")[1]
                    first_char_index = len(access_line) - len(access_line.lstrip())
                    access_line = access_line[first_char_index:]
                    last_char_index = len(access_line.rstrip())
                    access_line = access_line[:last_char_index]
                    access_line = access_line.replace(" ", "_")
                    accesses += "_" + access_line
                else:
                    inside_accesses_block = False
                    single_line.append(accesses)
                    accesses = "Accesses:"
            else:
                single_line.append(line)

    # then for each log entry, compute domain
    pre_out_line = ',' * 19
    for entry in reversed(single_line):
        out_line = ''

        # timestamp
        if entry.startswith("Audit Success") or entry.startswith("Audit Failure") or entry.startswith("Information"):
            event_date = ""
            date_val = ""

            # timestamp 64-bit
            if entry.startswith("Information"):
                event_date = entry.split()[1]
                month, day, year = event_date.split('/')
                day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
                date_val = str(int(day_of_year) * 24 * 60 * 60)

                timestamp = entry.split()[2]
                h, m, s = timestamp.split(':')
                if entry.split()[3] == "PM":
                    if 1 <= int(h) <= 11:
                        h = str(int(h) + 12)
                if entry.split()[3] == "AM":
                    if int(h) == 12:
                        h = "00"

            # timestamp 32-bit
            if entry.startswith("Audit Success") or entry.startswith("Audit Failure"):
                event_date = entry.split()[2]
                month, day, year = event_date.split('/')
                day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
                date_val = str(int(day_of_year) * 24 * 60 * 60)

                timestamp = entry.split()[3]
                h, m, s = timestamp.split(':')
                if entry.split()[4] == "PM":
                    if 1 <= int(h) <= 11:
                        h = str(int(h) + 12)
                if entry.split()[4] == "AM":
                    if int(h) == 12:
                        h = "00"

            out_line = str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "b" + str(event_number)
            event_number += 1

            # queried domain
            out_line += ','
    
            # resolved ip
            out_line += ','

            if pid in process_parent:
                ppid = process_parent[pid]
            else:
                ppid = 0

            # pid
            if pid != 0:
                out_line += ',' + str(pid)
            else:
                out_line += ','

            # ppid
            if ppid != 0:
                out_line += ',' + str(ppid)
            else:
                out_line += ','

            # pname
            if len(pname) > 0:
                out_line += ',' + pname
                pname = ""
            else:
                out_line += ','

            # Source ip
            if len(s_ip) > 0:
                out_line += ',' + s_ip
            else:
                out_line += ','

            if len(s_port) > 0:
                out_line += ',' + s_port
            else:
                out_line += ','

            # Destination ip
            if len(d_ip) > 0:
                out_line += ',' + d_ip
            else:
                out_line += ','

            if len(d_port) > 0:
                out_line += ',' + d_port
            else:
                out_line += ','

            # 7 fields are empty for audit log
            for i in range(0, 7):
                out_line += ','

            if len(acct) > 0:
                out_line += ',' + acct
            else:
                out_line += ','

            if len(objname) > 0:
                out_line += ',' + objname
            else:
                out_line += ','

            # network direction
            if len(network_direction) > 0:
                out_line += ',' + network_direction
            else:
                out_line += ','

            # write lines out, remove adjacent duplicate entries
            if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
                matched = False
                if is_matched(out_line, malicious_labels):
                    matched = True
                if out_line.startswith(","):
                    print("malformed!")
                if not ",,,,,,,,,,,,,,,,,,," in out_line:
                    if matched:
                        #wf.write(out_line + '-LA+\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LA+') #  + event_date + " " + timestamp
                    else:
                        #wf.write(out_line + '-LA-\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LA-') #  + event_date + " " + timestamp
                    pre_out_line = out_line
            pid = 0
            ppid = 0
            new_pid = 0
            new_ppid = 0
            pname = ""
            d_ip = ""
            d_port = ""
            s_ip = ""
            s_port = ""
            acct = ""
            objname = ""
            accesses = ""
            continue
            
        if "New Process ID:" in entry:
            if "0x" in entry:
                new_pid =  str(int(entry.split("0x")[1].split("\"")[0], 16))
                if len(new_pid) == 0:
                    print(entry)
            else:
                new_pid = str(int(entry.split()[-1].split("\"")[0]))
                if len(new_pid) == 0:
                    print(entry)

            pid = new_pid

            if new_pid not in process_parent:
                if new_ppid != 0:
                    process_parent[new_pid] = new_ppid
            new_pid = 0
            new_ppid = 0

            continue

        if "Creator Process ID:" in entry:
            if "0x" in entry:
                new_ppid = str(int(entry.split("0x")[1].split("\"")[0], 16))
                if len(new_ppid) == 0:
                    print(entry)
            else:
                new_ppid = str(int(entry.split()[-1].split("\"")[0]))
                if len(new_ppid) == 0:
                    print(entry)

            ppid = new_ppid

            continue

        # process id
        if "Process ID:" in entry:
            if "0x" in entry:
                pid = str(int(entry.split("0x")[1].split("\"")[0], 16))
                if len(pid) == 0:
                    print(entry)
            else:
                pid = str(int(entry.split()[-1].split("\"")[0]))
                if len(pid) == 0:
                    print(entry)
            continue

        # Process Name
        if "Application Name:" in entry or "Process Name:" in entry or "New Process Name:" in entry:
            if len(pname) == 0:
                pname = entry.split("Name:")[1]
                first_char_index = len(pname) - len(pname.lstrip())
                pname = pname[first_char_index:]
                #'''
                last_char_index = len(pname.rstrip())
                pname = pname[:last_char_index]
                
                if "\"" in pname:
                    pname = pname[:len(pname)-1]
            continue

        # destination ip
        if "Destination Address:" in entry:
            d_ip = entry.split()[-1].split("\"")[0]
            continue

        # destination port
        if "Destination Port:" in entry:
            d_port = entry.split()[-1].split("\"")[0]
            continue

        # source ip
        if "Source Address:" in entry:
            s_ip = entry.split()[-1].split("\"")[0]
            continue

        # source port
        if "Source Port:" in entry:
            s_port = entry.split()[-1].split("\"")[0]
            continue

        # principle of object access
        if "Object Type:" in entry:
            acct = entry.split()[-1].split("\"")[0]
            if len(accesses) > 0:
                acct += accesses
            continue

        # network direction
        if "Direction:" in entry:
            network_direction = entry.split()[-1].split("\"")[0]
            continue

        # object name
        if "Object Name:" in entry:
            objname = entry.split("Object Name:")[1].lstrip().rstrip().split("\"")[0]
            continue

        if entry.startswith("Accesses:"):
            accesses = entry.split("Accesses:")[1]
            continue

# preprocess http log
def pp_http(preprocessing_lines, malicious_labels, path):
    log_file_path = path + '/firefox.txt'
    event_number = 1
    ADJ_FF_TIME = -5

    with open(log_file_path, 'r') as f:
        single_lines = []
        single_line = ''
        enter = False
        for line in f:
            if "uri=http" in line:
                single_lines.append(line)
                continue

            line = line.strip().replace('\'', '').replace('\"', '')
            if 'http response [' in line or 'http request [' in line:
                enter = True
                single_line += line
                continue

            if enter:
                if ' ]' not in line:
                    single_line += ' ' + line
                else:
                    enter = False
                    single_lines.append(single_line)
                    single_line = ''

    # then for each log entry, compute domain
    pre_out_line = ',' * 19
    for entry in single_lines:
        out_line = ''

        # timestamp
        timestamp = re.findall(r'([0-9]+:[0-9]+:[0-9]+)\.', entry)[0]
        h, m, s = timestamp.split(':')

        event_date = entry.split()[0]
        year, month, day = event_date.split('-')
        day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
        if 0 <= int(h) <= 3:
            h = str(24 + int(h) + (ADJ_FF_TIME))
            day_of_year = day_of_year - 1
            timestamp = h + ":" + m + ":" + s
            event_date = "2018-" + str(date.fromordinal(day_of_year).timetuple().tm_mon) + "-" + str(date.fromordinal(day_of_year).timetuple().tm_mday)
        else:
            h = str(int(h) + (ADJ_FF_TIME))

        date_val = str(int(day_of_year) * 24 * 60 * 60)

        out_line += str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "c" + str(event_number) # str((int(h) + 3) * 3600 + int(m) * 60 + int(s))
        event_number += 1

        for i in range(0, 9):
            out_line += ','

        # http type
        if "uri=http" in entry:
            out_line += ',' + "request"
        else:
            type = re.findall(r' http (\S+) \[', entry)
            if type:
                out_line += ',' + type[0]
            else:
                out_line += ','
        url = ""
        # get query
        if "uri=http" in entry and "://" in entry:
            url = entry.split("://")[1]
            #url_trim = url[url.find("/"):]
            url_trim = url
            if len(url_trim) > 0:
                url_trim = url_trim.split()[0]
                if url_trim:
                    if url_trim.endswith("]"):
                        url_trim = url_trim.split("]")[0]
                out_line += ',' + url_trim.replace(',', '')
            else:
                out_line += ','
        else:
            get_q = re.findall(r' GET (\S+) HTTP', entry)
            if get_q:
                #get_q = get_q[0][get_q[0].find("/"):]
                get_q = get_q[0][:]
                if get_q.endswith("]"):
                    get_q = get_q.split("]")[0]
                if get_q.startswith("/"):
                    continue # redundant event
                out_line += ',' + get_q.replace(',', '')
            else:
                out_line += ','

        # post query
        post_q = re.findall(r' POST (\S+) HTTP', entry)
        if post_q:
            post_q = post_q[0][post_q[0].find("/"):]
            if post_q.endswith("]"):
                post_q = post_q.split("]")[0]
            out_line += ',' + post_q.replace(',', '')
        else:
            out_line += ','

        # response code
        res_code = re.findall(r' HTTP/[0-9]\.[0-9] ([0-9]+) ', entry)
        if res_code:
            out_line += ',' + res_code[0]
        else:
            out_line += ','

        # 14- host domain name, if request, if response?
        if " Host: " in entry:
            h_domain = re.findall(r' Host: (.*?) ', entry)
            if h_domain:
                h_domain = h_domain[0]
                if ":" in h_domain:
                    h_domain = h_domain.split(":")[0]
                out_line += ',' + h_domain
            else:
                out_line += ','
        else:
            res_loc = re.findall(r' Location: (.*?) ', entry)
            if res_loc:
                host = ""
                loc_url = res_loc[0]
                if loc_url:
                    if loc_url.endswith("]"):
                        loc_url = loc_url.split("]")[0]
                if "://" in loc_url:
                    host = loc_url.split("://")[1]
                    host = host.split("/")[0]
                    if ":" in host:
                        host = host.split(":")[0]
                    out_line += ',' + host
            else:
                out_line += ','

        # 15- referer
        referer = re.findall(r' Referer: (.*?) ', entry)
        if referer:
            referer = referer[0]
            if "://" in referer:
                referer = referer.split("://")[1]
            if referer.endswith("/"):
                referer = referer[:len(referer)-1]
            out_line += ',' + referer.replace(',', '')
        else:
            out_line += ','

        # 16- location of redirect
        res_loc = re.findall(r' Location: (.*?) ', entry)
        if res_loc:
            res_loc = res_loc[0]
            if "://" in res_loc:
                res_loc = res_loc.split("://")[1]
            if res_loc.endswith("/"):
                res_loc = res_loc[:len(res_loc)-1]
            out_line += ',' + res_loc.replace(',', '')
        else:
            out_line += ','

        for i in range(0, 3):
            out_line += ','

        # write lines out, remove adjacent duplicate entries
        if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
            matched = False
            if "/RiPleEsZw/PjttGs/ZIUgsQ.swf" in entry:
                print(entry)
            if is_matched(out_line, malicious_labels):
                matched = True
            if not ",,,,,,,,,,,,,,,,,,," in out_line:
                if matched:
                    #wf.write(out_line + '-LB+\n')
                    preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LB+') #  + event_date + " " + timestamp
                else:
                    #wf.write(out_line + '-LB-\n')
                    preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LB-') #  + event_date + " " + timestamp
                pre_out_line = out_line

# end of pasta
def pp_atlas(raw_path, mal_labels_path, out_file):
    malicious_labels = []
    with open(mal_labels_path, 'r') as f:
        for line in f:
            malicious_labels.append(line.strip())

    preprocessing_lines = []
    pp_dns(preprocessing_lines, malicious_labels, raw_path)
    pp_audit_w(preprocessing_lines, malicious_labels, raw_path)
    pp_http(preprocessing_lines, malicious_labels, raw_path)
    order_events(preprocessing_lines)
    with open(out_file, 'w') as wf:
        wf.writelines(preprocessing_lines)

def write_labels_to_file(file_name: str, labels: List[str]):
    with open(file_name, 'w') as f:
        for label in labels:
            f.write(f'{label}\n')

def pp_atlas_original_scenarios(raw_path, dest_path):
    lables = {
        'S1' : ['0xalsaheel.com', '192.168.223.3', 'payload.exe'],
        'S2' : ['0xalsaheel.com', '192.168.223.3', 'payload.exe'],
        'S3' : ['0xalsaheel.com', '192.168.223.3', 'payload.exe', 'msf.rtf', 'msf.exe', 'aalsahee/index.html'],
        'S4' : ['192.168.223.3', '0xalsaheel.com', 'msf.doc', 'pypayload.exe', 'aalsahee/index.html'],
        'M1/h1': ['0xalsaheel.com', '192.168.223.3', 'payload.exe', 'aalsahee/index.html'], 
        'M1/h2': ['0xalsaheel.com', '192.168.223.3', 'payload.exe', 'aalsahee/index.html'],
        'M2/h1': ['0xalsaheel.com', '192.168.223.3', 'pypayload.exe', 'aalsahee/index.html'], 
        'M2/h2': ['0xalsaheel.com', '192.168.223.3', 'pypayload.exe', 'aalsahee/index.html'],
        'M3/h1': ['0xalsaheel.com', '192.168.223.3', 'pypayload.exe', 'aalsahee/index.html'], 
        'M3/h2': ['0xalsaheel.com', '192.168.223.3', 'pypayload.exe', 'aalsahee/index.html'],
        'M4/h1': ['0xalsaheel.com', '192.168.223.3', 'msf_2018_8174.rtf', 'payload.exe', 'aalsahee/index.html'],
        'M4/h2': ['0xalsaheel.com', '192.168.223.3', 'payload.exe'],
        'M5/h1': ['0xalsaheel.com', '192.168.223.3', 'msf.doc', 'pypayload.exe'],
        'M5/h2': ['0xalsaheel.com', '192.168.223.3', 'pypayload.exe'],
        'M6/h1': ['0xalsaheel.com', '192.168.223.3', 'msf.rtf', 'msf.exe', 'payload.exe', 'aalsahee/index.html'],
        'M6/h2': ['0xalsaheel.com', '192.168.223.3', 'payload.exe']
    }

    for scn, labels in lables.items():
        # single label file under Sx/
        dest_dir = os.path.join(dest_path, scn)
        raw_dir = os.path.join(raw_path, scn, 'logs')
        lbl_file = os.path.join(raw_dir, 'labels.txt')
        out_csv  = os.path.join(dest_dir, 'scenario.csv')

        os.makedirs(dest_dir, exist_ok=True)
        write_labels_to_file(lbl_file, labels)
        pp_atlas(raw_dir, lbl_file, out_csv)
    

def write_list_to_file(file_name: str, list_data: List[str]):
    with open(file_name, 'w') as f:
        for line in list_data:
            f.write(f'{line}\n')

def fix_dns_sa(log_file: str, new_file: str, time_list : List[Tuple[datetime, datetime, timedelta]], new_ip: str):
    adjusted_logs = []
    old_ip = '192.168.223.3'
    domain = '0xalsaheel.com'

    with open(log_file, 'r') as file:
        for line in file:
            if time_list:
                timestamp_str = line.strip().split(' ',1)[1][:19]
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                temp = pytz.timezone('America/New_York').localize(timestamp, is_dst=None).astimezone(pytz.utc)
                adjusted_timestamp = timestamp

                for (prev_time, new_time, time_delta) in time_list:
                    if temp > prev_time:
                        adjusted_timestamp = adjusted_timestamp + time_delta

                new_line = line.replace(timestamp_str, str(adjusted_timestamp)).strip()
            else:
                new_line = line.strip()
            
            if old_ip in new_line:
                if domain in new_line:
                    new_line = new_line.replace(old_ip, new_ip)
                else:
                    # this request is for the malicious actor which should not exists in the network
                    continue

            adjusted_logs.append(new_line)
        
    with open(new_file, 'w') as f:
        for line in adjusted_logs:
            f.write(f'{line}\n')

def fix_audit_sa(org_log: str, new_log: str, initial_ip: str, cc_ip:str, discard_before: datetime = None):
    # initial_ip is the ip address that resolves to 0xalsaheel.com
    # cc_ip is the ip address that is used later to command and control (C&C) by payload.exe

    parsed_logs = []
    log_entry = []
    lines = []
    log_start_pattern = re.compile(r'^(Audit Success|Audit Failure|Audit Information)')
    datetime_pattern = re.compile(r'(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s[APM]{2})')

    with open(org_log, 'r') as file:
        lines = file.read().splitlines()

    for line in lines:
        if log_start_pattern.match(line) and log_entry:
            parsed_logs.append("\n".join(log_entry))
            log_entry = []
        log_entry.append(line)

    # Append the final log entry if it exists
    if log_entry:
        parsed_logs.append("\n".join(log_entry))

    with open(new_log, 'w') as f:
        for log in parsed_logs:
            if '192.168.223.3' in log:
                if '255.255.255.255' in log or '192.168.223.255' in log:
                    # discard the broadcast messages, we are changing to a public ip address
                    # machine should not receiving broadcast messages from public ip addresses
                    continue
                if 'firefox' in log:
                    # initial attack, replace to initial ip address
                    log = log.replace('192.168.223.3', initial_ip)
                else:
                    log = log.replace('192.168.223.3', cc_ip)
            if discard_before:
                datetime_match = datetime_pattern.search(log)
                if datetime_match:
                    date_str = datetime_match.group(1)
                    time_str = datetime_match.group(2)
                    ts = datetime.strptime(f'{date_str} {time_str}', '%m/%d/%Y %I:%M:%S %p')
                    if ts < discard_before:
                        continue
            f.write(f'{log}\n')

def fix_firefox_sa(org_log: str, new_log: str):
    shutil.copy(org_log, new_log)

def produce_se1_logs(s1_raw_log: str, sa1_raw_dest_logs: str):
    raw_logs = s1_raw_log
    alt_logs = sa1_raw_dest_logs

    org_security_log = os.path.join(raw_logs, 'security_events.txt')
    org_dns_log = os.path.join(raw_logs, 'dns')
    org_firefox_log = os.path.join(raw_logs, 'firefox.txt')
    new_security_log = os.path.join(alt_logs, 'security_events.txt')
    new_dns_log = os.path.join(alt_logs, 'dns')
    new_firefox_log = os.path.join(alt_logs, 'firefox.txt')
    new_initial_ip = '46.101.68.39'
    new_cc_ip = '46.11.60.81'
    prev_time = datetime.strptime("2018-11-03T02:47:35", '%Y-%m-%dT%H:%M:%S').replace(tzinfo=pytz.utc)
    new_time = datetime.strptime("2018-11-06T00:15:41", '%Y-%m-%dT%H:%M:%S').replace(tzinfo=pytz.utc)
    delta = new_time - prev_time

    fix_dns_sa(org_dns_log, new_dns_log, [(prev_time, new_time, delta)], new_initial_ip)
    fix_audit_sa(org_security_log, new_security_log, new_initial_ip, new_cc_ip)
    fix_firefox_sa(org_firefox_log, new_firefox_log)
    write_list_to_file(os.path.join(alt_logs, 'labels.txt'), 
                       [new_initial_ip, '0xalsaheel.com', 'payload.exe', new_cc_ip])

def produce_se2_logs(s2_raw_log: str, sa2_raw_dest_logs: str):
    raw_logs = s2_raw_log
    alt_logs = sa2_raw_dest_logs

    org_security_log = os.path.join(raw_logs, 'security_events.txt')
    org_dns_log = os.path.join(raw_logs, 'dns')
    org_firefox_log = os.path.join(raw_logs, 'firefox.txt')
    new_security_log = os.path.join(alt_logs, 'security_events.txt')
    new_dns_log = os.path.join(alt_logs, 'dns')
    new_firefox_log = os.path.join(alt_logs, 'firefox.txt')
    new_initial_ip = '46.101.68.39'
    new_cc_ip = '46.11.60.81'

    fix_dns_sa(org_dns_log, new_dns_log, None, new_initial_ip)
    fix_audit_sa(org_security_log, new_security_log, new_initial_ip, new_cc_ip, datetime(2018, 9, 15))
    fix_firefox_sa(org_firefox_log, new_firefox_log)
    write_list_to_file(os.path.join(alt_logs,'labels.txt'), 
                       [new_initial_ip, '0xalsaheel.com', 'payload.exe', new_cc_ip])

def produce_se3_logs(s3_raw_log: str, sa3_raw_dest_logs: str):
    raw_logs = s3_raw_log
    alt_logs = sa3_raw_dest_logs

    org_security_log = os.path.join(raw_logs, 'security_events.txt')
    org_dns_log = os.path.join(raw_logs, 'dns')
    org_firefox_log = os.path.join(raw_logs, 'firefox.txt')
    new_security_log = os.path.join(alt_logs, 'security_events.txt')
    new_dns_log = os.path.join(alt_logs, 'dns')
    new_firefox_log = os.path.join(alt_logs, 'firefox.txt')
    new_initial_ip = '46.101.68.39'
    new_cc_ip = '46.11.60.81'
    fix_dns_sa(org_dns_log, new_dns_log, None, new_initial_ip)
    fix_audit_sa(org_security_log, new_security_log, new_initial_ip, new_cc_ip)
    fix_firefox_sa(org_firefox_log, new_firefox_log)
    write_list_to_file(os.path.join(alt_logs,'labels.txt'), 
                       [new_initial_ip, '0xalsaheel.com', 'payload.exe', 'msf.rtf', 'msf.exe', new_cc_ip])

def produce_se4_logs(s4_raw_log: str, sa4_raw_dest_logs: str):
    raw_logs = s4_raw_log
    alt_logs = sa4_raw_dest_logs
    org_security_log = os.path.join(raw_logs, 'security_events.txt')
    org_dns_log = os.path.join(raw_logs, 'dns')
    org_firefox_log = os.path.join(raw_logs, 'firefox.txt')
    new_security_log = os.path.join(alt_logs, 'security_events.txt')
    new_dns_log = os.path.join(alt_logs, 'dns')
    new_firefox_log = os.path.join(alt_logs, 'firefox.txt')
    new_initial_ip = '46.101.68.39'
    new_cc_ip = '46.11.60.81'
    fix_dns_sa(org_dns_log, new_dns_log, None, new_initial_ip)
    fix_audit_sa(org_security_log, new_security_log, new_initial_ip, new_cc_ip)
    fix_firefox_sa(org_firefox_log, new_firefox_log)
    write_list_to_file(os.path.join(alt_logs, 'labels.txt'), 
                       [new_initial_ip, '0xalsaheel.com', 'pypayload.exe', 'msf.doc', new_cc_ip])

def produce_se_logs(base_raw_logs: str, base_dest_logs: str):
    
    se1_raw_logs = os.path.join(base_raw_logs, 'SE1', 'logs')
    se2_raw_logs = os.path.join(base_raw_logs, 'SE2', 'logs')
    se3_raw_logs = os.path.join(base_raw_logs, 'SE3', 'logs')
    se4_raw_logs = os.path.join(base_raw_logs, 'SE4', 'logs')
    se1_dest_logs = os.path.join(base_dest_logs, 'SE1')
    se2_dest_logs = os.path.join(base_dest_logs, 'SE2')
    se3_dest_logs = os.path.join(base_dest_logs, 'SE3')
    se4_dest_logs = os.path.join(base_dest_logs, 'SE4')
    s1_raw_logs = os.path.join(base_raw_logs, 'S1', 'logs')
    s2_raw_logs = os.path.join(base_raw_logs, 'S2', 'logs')
    s3_raw_logs = os.path.join(base_raw_logs, 'S3', 'logs')
    s4_raw_logs = os.path.join(base_raw_logs, 'S4', 'logs')

    os.makedirs(se1_raw_logs, exist_ok=True)
    os.makedirs(se2_raw_logs, exist_ok=True)
    os.makedirs(se3_raw_logs, exist_ok=True)
    os.makedirs(se4_raw_logs, exist_ok=True)

    # first produce raw logs
    produce_se1_logs(s1_raw_logs, se1_raw_logs)
    produce_se2_logs(s2_raw_logs, se2_raw_logs)
    produce_se3_logs(s3_raw_logs, se3_raw_logs)
    produce_se4_logs(s4_raw_logs, se4_raw_logs)
    
    os.makedirs(se1_dest_logs, exist_ok=True)
    os.makedirs(se2_dest_logs, exist_ok=True)
    os.makedirs(se3_dest_logs, exist_ok=True)
    os.makedirs(se4_dest_logs, exist_ok=True)

    # then produce preprocessed atlas format logs
    pp_atlas(se1_raw_logs, os.path.join(se1_raw_logs, 'labels.txt'), os.path.join(se1_dest_logs, 'scenario.csv'))
    pp_atlas(se2_raw_logs, os.path.join(se2_raw_logs, 'labels.txt'), os.path.join(se2_dest_logs, 'scenario.csv'))
    pp_atlas(se3_raw_logs, os.path.join(se3_raw_logs, 'labels.txt'), os.path.join(se3_dest_logs, 'scenario.csv'))
    pp_atlas(se4_raw_logs, os.path.join(se4_raw_logs, 'labels.txt'), os.path.join(se4_dest_logs, 'scenario.csv'))

def produce_ss_logs_generic(sa_raw_logs: str, sb_raw_logs: str):
    org_path = sa_raw_logs
    dest_path = sb_raw_logs

    org_security_log = os.path.join(org_path, 'security_events.txt')
    org_dns_log = os.path.join(org_path, 'dns')
    org_firefox_log = os.path.join(org_path, 'firefox.txt')
    new_security_log = os.path.join(dest_path, 'security_events.txt')
    new_dns_log = os.path.join(dest_path, 'dns')
    new_firefox_log = os.path.join(dest_path, 'firefox.txt')
    org_labels_file = os.path.join(org_path, 'labels.txt')
    new_labels_file = os.path.join(dest_path, 'labels.txt')
    
    # simple find and replace
    shutil.copy(org_security_log, new_security_log)
    shutil.copy(org_dns_log, new_dns_log)
    shutil.copy(org_firefox_log, new_firefox_log)
    shutil.copy(org_labels_file, new_labels_file)

    # open each new file, find and replace domain name and executable name
    # old domain name: 0xalsaheel.com, new domain name: official-system-monitoring.xyz
    # old executable name: payload.exe, new executable name: systempatch.exe
    files_to_replace = [new_security_log, new_dns_log, new_firefox_log, new_labels_file]

    for file_path in files_to_replace:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace('0xalsaheel.com', 'official-system-monitoring.xyz')
        content = content.replace('payload.exe', 'systempatch.exe')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

def produce_ss_logs(base_raw_logs: str, base_dest_logs: str):
    
    ss1_raw_logs = os.path.join(base_raw_logs, 'SS1', 'logs')
    ss2_raw_logs = os.path.join(base_raw_logs, 'SS2', 'logs')
    ss3_raw_logs = os.path.join(base_raw_logs, 'SS3', 'logs')
    ss4_raw_logs = os.path.join(base_raw_logs, 'SS4', 'logs')
    se1_raw_logs = os.path.join(base_raw_logs, 'SE1', 'logs')
    se2_raw_logs = os.path.join(base_raw_logs, 'SE2', 'logs')
    se3_raw_logs = os.path.join(base_raw_logs, 'SE3', 'logs')
    se4_raw_logs = os.path.join(base_raw_logs, 'SE4', 'logs')
    ss1_dest_logs = os.path.join(base_dest_logs, 'SS1')
    ss2_dest_logs = os.path.join(base_dest_logs, 'SS2')
    ss3_dest_logs = os.path.join(base_dest_logs, 'SS3')
    ss4_dest_logs = os.path.join(base_dest_logs, 'SS4')
    
    os.makedirs(ss1_raw_logs, exist_ok=True)
    os.makedirs(ss2_raw_logs, exist_ok=True)
    os.makedirs(ss3_raw_logs, exist_ok=True)
    os.makedirs(ss4_raw_logs, exist_ok=True)
    os.makedirs(ss1_dest_logs, exist_ok=True)
    os.makedirs(ss2_dest_logs, exist_ok=True)
    os.makedirs(ss3_dest_logs, exist_ok=True)
    os.makedirs(ss4_dest_logs, exist_ok=True)

    produce_ss_logs_generic(se1_raw_logs, ss1_raw_logs)
    produce_ss_logs_generic(se2_raw_logs, ss2_raw_logs)
    produce_ss_logs_generic(se3_raw_logs, ss3_raw_logs)
    produce_ss_logs_generic(se4_raw_logs, ss4_raw_logs)

    pp_atlas(ss1_raw_logs,  os.path.join(ss1_raw_logs, 'labels.txt'), os.path.join(ss1_dest_logs, 'scenario.csv'))
    pp_atlas(ss2_raw_logs,  os.path.join(ss2_raw_logs, 'labels.txt'), os.path.join(ss2_dest_logs, 'scenario.csv'))
    pp_atlas(ss3_raw_logs,  os.path.join(ss3_raw_logs, 'labels.txt'), os.path.join(ss3_dest_logs, 'scenario.csv'))
    pp_atlas(ss4_raw_logs,  os.path.join(ss4_raw_logs, 'labels.txt'), os.path.join(ss4_dest_logs, 'scenario.csv'))

def parse_to_json_with_custom_delimiters(text):
    if text[0] == '¬':
        text = text[1:-1]
    # Split into sections using `¬¬` as the delimiter
    sections = text.split('¬¬')
    result_dict = {}  # Initialize the result dictionary
    
    # Process each section
    for section in sections:
        if not section.strip():
            continue  # Skip empty sections
        try:
        # Split into lines using `¬` as the delimiter
            lines = section.strip().split('¬')
            section_name = lines[0].strip()  # Assume the first line names the section
            key, value = section_name.split(':', 1)
            section_name = key.strip()
            # Initialize section dictionary with the first key-value if applicable
            #section_dict = {key.strip(): value.strip()}
            section_dict = {}
            
            # Process each line in the section
            for line in lines[1:]:
                if ':' in line:  # Ensure the line has a key-value pair
                    key, value = line.split(':', 1)
                    section_dict[key.strip()] = value.strip()
            
            # Add the processed section to the result dictionary
            result_dict[section_name] = section_dict
        except:
            continue
    
    return result_dict

def parse_windows_audit(file_path: str):
    events = []
    current_event = {}
    capture_extra_details = False
    
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            # Identify the start of a new log event
            if line.startswith('Audit '):
                match = re.match(r'^Audit (Success|Failure|Information)\s+(\d+/\d+/\d+\s+\d+:\d+:\d+\s+[APM]+)\s', line)
                if match:
                    # Add the current event to events list before starting a new one
                    if current_event:
                        current_event['extra_details'] = parse_to_json_with_custom_delimiters(current_event['extra_details'])
                        events.append(current_event)
                        current_event = {}
                        capture_extra_details = False
                    current_event['type'] = "Audit"
                    current_event['audit_status'] = match.group(1).lower()
                    current_event['timestamp'] = datetime.strptime(match.group(2), "%m/%d/%Y %I:%M:%S %p")
                    # Localize the datetime object to the 'America/New_York' timezone (which is typically UTC-5, but can be UTC-4 during daylight saving)
                    current_event['timestamp'] = pytz.timezone('America/New_York').localize(current_event['timestamp'], is_dst=None)
                    current_event['timestamp'] = current_event['timestamp'].astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')
                    try:
                        current_event['information'] = line[line.index('"') + 1:].strip()
                        current_event['extra_details'] = ''
                        capture_extra_details = True  # Start capturing extra details in subsequent lines
                    except ValueError:  # Corrected from a bare except
                        # If failed to read `"` for the beginning of the message
                        current_event['information'] = line.split('\t')[-1].strip()
                        current_event['extra_details'] = ''
                        events.append(current_event)
                        current_event = {}  # Reset current_event after appending

            elif capture_extra_details:
                # Detect the start of a new audit event in the middle of extra details
                if re.match(r'^Audit (Success|Failure|Information)', line):
                    current_event['extra_details'] = parse_to_json_with_custom_delimiters(current_event['extra_details'])
                    events.append(current_event)
                    current_event = {}
                    capture_extra_details = False
                    # This continues to the next line of the file, not the loop, so no need to process the same line again
                    continue
                
                # Append extra details from the current line
                line = line.strip()
                if len(line) > 0:
                    if line[-1] == '"':
                        line = line[:-1]
 
                current_event['extra_details'] += line + '¬'

        # Add the last event if any
        if current_event:
            current_event['extra_details'] = parse_to_json_with_custom_delimiters(current_event['extra_details'])
            events.append(current_event)

    return events

def parse_windows_audit_df(file_path: str):
    tmp_df = pd.DataFrame(parse_windows_audit(file_path)).iloc[::-1].reset_index(drop=True)
    # Ensure that all DataFrames have the same columns
    columns = ['timestamp', 'type', 'audit_status', 'information', 'extra_details']
    for col in columns:
        if col not in tmp_df.columns:
            tmp_df[col] = None

    # Collect process instances and audit events
    pid_records = []
    audit_records = []
    process_instance_id_counter = 0
    active_processes = {}  # pid -> list of active process instances

    audit_events_gen = event_generator(tmp_df, None, ['audit_status', 'type'])

    try:
        while True:
            event = next(audit_events_gen)
            time = event['timestamp']

            if event['information'] == 'An attempt was made to access an object.':
                # Access event
                prc = event['extra_details']['Process Information']['Process Name']
                pid_hex = event['extra_details']['Process Information']['Process ID']
                pid = convert_pid_to_dec(pid_hex)
                target = event['extra_details']['Object']['Object Name']
                access = event['extra_details']['Access Request Information']['Accesses']
                access = access.lower()
                if 'read' in access:
                    access = 'read'
                elif 'write' in access:
                    access = 'write'
                elif 'execute' in access:
                    access = 'execute'
                elif 'delete' in access:
                    access = 'delete'
                else:
                    continue

                # Find the process_instance_id
                process_instance_id = None
                if pid in active_processes:
                    # Find the process instance whose creation_time is before the event time
                    candidates = [pi for pi in active_processes[pid] if pi['creation_time'] <= time]
                    if candidates:
                        # Pick the one with the latest creation_time before the event time
                        process_instance = max(candidates, key=lambda pi: pi['creation_time'])
                        process_instance_id = process_instance['process_instance_id']

                audit_records.append({
                    'time': str(time),
                    'pid': pid,
                    'process_instance_id': process_instance_id,
                    'access': access,
                    'object': target
                })

            elif event['information'] == 'The Windows Filtering Platform has permitted a connection.':
                # Network event
                prc = event['extra_details']['Application Information']['Application Name']
                pid = event['extra_details']['Application Information']['Process ID']
                dir = event['extra_details']['Network Information']['Direction']
                src = f"{event['extra_details']['Network Information']['Source Address']}:{event['extra_details']['Network Information']['Source Port']}"
                dst = f"{event['extra_details']['Network Information']['Destination Address']}:{event['extra_details']['Network Information']['Destination Port']}"
                prt = event['extra_details']['Network Information']['Protocol']
                access = 'connect'

                protocol_map = {'1': 'ICMP', '6': 'TCP', '17': 'UDP'}
                prt = protocol_map.get(prt, prt)

                target = dst if dir.lower() == 'outbound' else src
                pid = int(pid)

                # Find the process_instance_id
                process_instance_id = None
                if pid in active_processes:
                    candidates = [pi for pi in active_processes[pid] if pi['creation_time'] <= time]
                    if candidates:
                        process_instance = max(candidates, key=lambda pi: pi['creation_time'])
                        process_instance_id = process_instance['process_instance_id']

                audit_records.append({
                    'time': str(time),
                    'pid': pid,
                    'process_instance_id': process_instance_id,
                    'access': access,
                    'object': target
                })

            elif event['information'] == 'A new process has been created.':
                # Process creation event
                pid_hex = event['extra_details']['Process Information']['New Process ID']
                pid = convert_pid_to_dec(pid_hex)
                creation_time = time
                prc = event['extra_details']['Process Information']['New Process Name']
                ppid = convert_pid_to_dec(event['extra_details']['Process Information']['Creator Process ID'])
                token = event['extra_details']['Process Information']['Token Elevation Type']
                process_instance_id = process_instance_id_counter
                process_instance_id_counter += 1
                process_instance = {
                    'process_instance_id': process_instance_id,
                    'pid': pid,
                    'creation_time': creation_time,
                    'pname': prc,
                    'ppid': ppid,
                    'token_type': token,
                    'exit_time': None,
                    'exit_status': None
                }

                pid_records.append(process_instance)
                active_processes.setdefault(pid, []).append(process_instance)

            elif event['information'] == 'A process has exited.':
                # Process exit event
                pid_hex = event['extra_details']['Process Information']['Process ID']
                pid = convert_pid_to_dec(pid_hex)
                exit_st = event['extra_details']['Process Information']['Exit Status']
                exit_time = time
                if pid in active_processes:
                    candidates = [pi for pi in active_processes[pid] if pi['creation_time'] <= exit_time]
                    if candidates:
                        process_instance = min(candidates, key=lambda pi: pi['creation_time'])
                        process_instance['exit_time'] = exit_time
                        process_instance['exit_status'] = exit_st
                        active_processes[pid].remove(process_instance)
                        if not active_processes[pid]:
                            del active_processes[pid]
    except StopIteration:
        pass

    # Convert records to DataFrames
    pid_df = pd.DataFrame(pid_records)
    audit_df = pd.DataFrame(audit_records)

    # Merge audit_df with pid_df to get 'ppid' and 'process_name'
    audit_df = audit_df.merge(pid_df[['process_instance_id', 'pname', 'ppid']], on='process_instance_id', how='left')

    # Drop 'process_instance_id' if it's not needed
    audit_df = audit_df.drop(columns=['process_instance_id'])

    return audit_df

def parse_windows_audit_df_old(file_path: str):
    tmp_df = pd.DataFrame(parse_windows_audit(file_path)).iloc[::-1].reset_index(drop=True)
    # ensure that all detaframes have the same columns
    columns = ['timestamp', 'type', 'audit_status', 'information', 'extra_details']
    for col in columns:
        if col not in tmp_df.columns:
            tmp_df[col] = None
    
    # Create a DataFrame with the specified columns
    audit_df = pd.DataFrame(columns=['time', 'pid', 'ppid', 'pname', 'access', 'object'])
    pid_df = pd.DataFrame(columns=['pid', 'creation_time', 'process_name', 'ppid', 'token_type', 'exit_time', 'exit_status'])
    audit_events_gen = event_generator(tmp_df, None, ['audit_status','type'])
    try:
        while True:
            event = next(audit_events_gen)
            time = event['timestamp']

            if event['information'] == 'An attempt was made to access an object.':
                ## access
                prc = event['extra_details']['Process Information']['Process Name']
                pid = event['extra_details']['Process Information']['Process ID']
                target = event['extra_details']['Object']['Object Name']
                access = event['extra_details']['Access Request Information']['Accesses']
                details = str({'Handle ID': event['extra_details']['Object']['Handle ID']})
                if 'read' in access.lower():
                    access = 'read'
                elif 'write' in access.lower():
                    access = 'write'
                elif 'execute' in access.lower():
                    access = 'execute'
                elif 'delete' in access.lower():
                    access = 'delete'
                audit_df = pd.concat([audit_df, pd.DataFrame([{
                    'time': str(time),
                    'pid': convert_pid_to_dec(pid),
                    'ppid': None,
                    'pname': prc,
                    'access': access,
                    'object': target
                }])], ignore_index=True)

            elif event['information'] == 'The Windows Filtering Platform has permitted a connection.':
                ## network
                prc = event['extra_details']['Application Information']['Application Name']
                pid = event['extra_details']['Application Information']['Process ID']
                dir = event['extra_details']['Network Information']['Direction']
                src = f"{event['extra_details']['Network Information']['Source Address']}:{event['extra_details']['Network Information']['Source Port']}"
                dst = f"{event['extra_details']['Network Information']['Destination Address']}:{event['extra_details']['Network Information']['Destination Port']}"
                prt = f"{event['extra_details']['Network Information']['Protocol']}"
                access = 'connect'
                
                if prt == '1':
                    prt = 'ICMP'
                elif prt == '6':
                    prt = 'TCP'
                elif prt == '17':
                    prt == 'UDP'
                
                target = src
                details = str({'Direction': dir, 'Source': src, 'Destination':dst, 'Transport Protocol': prt})
                if dir.lower() == 'outbound':
                    target = dst

                audit_df = pd.concat([audit_df, pd.DataFrame([{
                    'time': str(time),
                    'pid': pid,
                    'ppid': None,
                    'pname': None,
                    'access': access,
                    'object': target
                }])], ignore_index=True)

            elif event['information'] == 'A new process has been created.':
                pid = convert_pid_to_dec(event['extra_details']['Process Information']['New Process ID'])
                prc = event['extra_details']['Process Information']['New Process Name']
                ppid = convert_pid_to_dec(event['extra_details']['Process Information']['Creator Process ID'])
                token = event['extra_details']['Process Information']['Token Elevation Type']
                pid_df = pd.concat([pid_df, pd.DataFrame([{
                    'pid': pid,
                    'creation_time': str(time),
                    'process_name': prc,
                    'ppid': ppid,
                    'token_type': token,
                    'exit_time': None,
                    'exit_status': None
                }])], ignore_index=True)
                #db.add_entry_ignore(Process(creation_time=str(time), pid=pid, process_name=prc, ppid=ppid, token_type=token))
                
            elif event['information'] == 'A process has exited.':
                pid = convert_pid_to_dec(event['extra_details']['Process Information']['Process ID'])
                exit_st = event['extra_details']['Process Information']['Exit Status']
                pid_df.loc[pid_df['pid'] == pid, ['exit_time', 'exit_status']] = [str(time), exit_st]
                #db.update_process(pid, exit_time=str(time), exit_status=exit_st)
                

    except StopIteration:
        pass

    # Update audit_df records with ppid from pid_df
    for pid in pid_df['pid'].unique():
        matching_audit_rows = audit_df[audit_df['pid'] == pid]
        if not matching_audit_rows.empty:
            ppid = pid_df[pid_df['pid'] == pid].iloc[0]['ppid']
            pname = pid_df[pid_df['pid'] == pid].iloc[0]['process_name']
            audit_df.loc[audit_df['pid'] == pid, 'pname'] = pname
            audit_df.loc[audit_df['pid'] == pid, 'ppid'] = ppid
    
    return audit_df, pid_df

def get_tld_and_sld(domain):
    extracted = tldextract.extract(domain)
    tld = "{}".format(extracted.suffix)
    sld = "{}.{}".format(extracted.domain, extracted.suffix)
    return tld, sld

def parse_http(file_path: str):
    info_logs = []
    parsed_data = []
    current_block = {}
    current_block['method'] = None
    collecting = False

    with open(file_path, 'r') as file:
        for line in file:
            try:
                # Strip whitespace and split the line to find the log type
                for word in line.strip().split(' '):
                    # the log file have three levels: I/ns = info, D/ns = Debug, V/ns = verbose
                    if word.startswith("I/ns"):
                        info_logs.append(f"{line[:30]}{line.split(word)[-1]}")
                        break
            except:
                pass
        
    for line in info_logs:
        if 'http request' in line or 'http response' in line:
            # If starting a new block, store the previous one if it exists
            if collecting and current_block:
                parsed_data.append(current_block)
                current_block = {}
                current_block['method'] = None
            collecting = True
            # Extract date from the log entry line
            # ...

            current_block['timestamp'] = datetime.strptime(line[:26].strip(), "%Y-%m-%d %H:%M:%S.%f")
            current_block['timestamp'] = current_block['timestamp'].replace(microsecond=0)
            current_block['timestamp'] = pytz.utc.localize(current_block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            if 'http request' in line:
                current_block['type'] = 'request'
            elif 'http response' in line:
                current_block['type'] = 'response'
        elif collecting:
            # Try to extract fields of interest
            if 'Host:' in line:
                current_block['host'] = line.split('Host:', 1)[1].strip()
                current_block['tld'], current_block['sld'] = get_tld_and_sld(current_block['host'])
            elif ('GET' in line or 'POST' in line) and current_block['method'] is None:
                parts = line.split()
                current_block['method'] = parts[3].strip()
                current_block['param'] = parts[4].strip()
            elif 'Content-Length:' in line:
                current_block['length'] = line.split('Content-Length:', 1)[1].strip()
            elif 'Referer:' in line:
                current_block['referer'] = line.split('Referer:', 1)[1].strip()
            elif 'Cookie:' in line:
                current_block['cookie'] = line.split('Cookie:', 1)[1].strip()
                if len(current_block['cookie']) > 0:
                    if current_block['cookie'][-1] == ';':
                        current_block['cookie'] = current_block['cookie'][:-1]
            elif 'Location:' in line:
                current_block['location'] = line.split('Location:', 1)[1].strip()
        # Handle the end of a block
        if line.strip() == '' and collecting:
            # End of current block, add to results and reset
            if current_block:
                parsed_data.append(current_block)
                current_block = {}
            collecting = False

    # Add the last block if any
    if current_block:
        parsed_data.append(current_block)

    return parsed_data

def parse_http_df(file_path: str):
    df = pd.DataFrame(parse_http(file_path))
    # ensure that all detaframes have the same columns
    columns = ['timestamp', 'type', 'method', 'param', 'host', 'length', 'cookie', 'referer', 'location', 'tld', 'sld']
    for col in columns:
        if col not in df.columns:
            df[col] = None
    
    return df

def parse_dns(file_path: str):
    events = []

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            # Parse the timestamp
            timestamp = datetime.strptime(f'{parts[1]} {parts[2]}', '%Y-%m-%d %H:%M:%S.%f')
            timestamp = pytz.timezone('America/New_York').localize(timestamp, is_dst=None)
            timestamp = timestamp.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')
            # Parse source and destination addresses
            src, dst = parts[3], parts[5]
            
            if "response" in line:
                # Handle response-specific parsing
                query_id = parts[11]
                # Initialize an empty list to store the answer sections, with potential for multiple answers
                answers = []
                    
                # Start iterating through parts at index 14, stepping by 2 to process pairs
                for i in range(14, len(parts), 2):
                    # Check if the next part (the data part of the pair) exists
                    if i + 1 < len(parts):
                        # Add the pair (type, data) to the answers list
                        answers.append((parts[i], parts[i + 1]))
                    else:
                        # If there's a type without a corresponding data, add it alone
                        answers.append((parts[i],))
                # Now, 'answers' will contain all the answer sections, correctly paired or singly listed if unmatche
                for event in events:  # Find the corresponding query event by query_id
                    if event["query_id"] == query_id and event["response"] is None:
                        grouped_data = defaultdict(list)

                        if 'No such name' in line:
                            event["response"] = str({'Response': 'No Such Name'})
                        else:    
                            # Group values under the same key
                            for key, value in answers:
                                grouped_data[key].append(value)

                            # Convert defaultdict to regular dictionary
                            result_dict = dict(grouped_data)
                            event["response"] = str({'Response': result_dict})
                        break  # Assuming one response per query
            elif "query" in line:
                # Handle query-specific parsing
                query_id = parts[10]
                query_type = parts[11]  # A or AAAA
                domain_name = parts[12]
                event = {
                    "type": "DNS Query",
                    "timestamp": timestamp,
                    "src": src,
                    "dst": dst,
                    "query_id": query_id,
                    "query_type": query_type,
                    "domain_name": domain_name,
                    "response": None
                }
                events.append(event)
    return events

def parse_dns_df(file_path: str):
    df = pd.DataFrame(parse_dns(file_path))
    # ensure that all detaframes have the same columns
    columns = ['timestamp', 'src', 'dst', 'query_id', 'query_type', 'domain_name', 'response']
    for col in columns:
        if col not in df.columns:
            df[col] = None
    return df

def parse_dns_answer(file_path: str):
    events = []

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()

            # Parse the timestamp
            timestamp = datetime.strptime(f'{parts[1]} {parts[2]}', '%Y-%m-%d %H:%M:%S.%f')
            timestamp = pytz.timezone('America/New_York').localize(timestamp, is_dst=None)
            timestamp = timestamp.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')

            # Parse source and destination addresses
            src, dst = parts[3], parts[5]

            if "response" in line:
                # Handle response-specific parsing
                query_id_index = parts.index("response") + 1
                query_id = parts[query_id_index]
                query_type = parts[query_id_index + 1]
                domain_name = parts[query_id_index + 2]

                # Initialize sections
                answer_records = []

                # Start parsing RRs from index after domain_name
                i = query_id_index + 3
                current_section = "answer"  # Start with the answer section

                while i < len(parts) - 1:
                    rr_type = parts[i]
                    rr_data = parts[i + 1]

                    if rr_type == 'NS':
                        break  # Stop parsing after the answer section

                    # Collect answer records
                    if current_section == "answer":
                        answer_records.append((rr_type, rr_data))

                    i += 2  # Move to the next RR

                # Find the corresponding query event by query_id
                for event in events:
                    if event["query_id"] == query_id and event["response"] is None:
                        event["response"] = answer_records  # Only store the Answer section
                        break  # Assuming one response per query

            elif "query" in line:
                # Handle query-specific parsing
                query_id_index = parts.index("query") + 1
                query_id = parts[query_id_index]
                query_type = parts[query_id_index + 1]  # A or AAAA
                domain_name = parts[query_id_index + 2]
                event = {
                    "type": "DNS Query",
                    "timestamp": timestamp,
                    "src": src,
                    "dst": dst,
                    "query_id": query_id,
                    "query_type": query_type,
                    "domain_name": domain_name,
                    "response": None
                }
                events.append(event)

    return events

def parse_dns_df_answer(file_path: str):
    events = parse_dns_answer(file_path)
    # Create a list of dictionaries to be converted into a dataframe
    for event in events:
        # Extract the answer IPs from the response
        if event['response']:
            answer_ips = [rr[1] for rr in event['response'] if rr[0] == 'A']
            event['response'] = answer_ips
        else:
            event['response'] = []


    df = pd.DataFrame(events)
    # Ensure that all dataframes have the same columns
    columns = ['timestamp', 'src', 'dst', 'query_id', 'query_type', 'domain_name', 'response']
    for col in columns:
        if col not in df.columns:
            df[col] = None

    return df

def simplify_dns_df(df: pd.DataFrame):
    # Assuming dns_df is your original DNS DataFrame
    # and it has 'object' for domain names and 'response' for response data

    # Step 1: Initialize an empty dictionary to store domain names and their associated responses
    domain_responses = {}

    # Step 2: Iterate through the DataFrame to populate the dictionary
    for index, row in df.iterrows():
        domain_name = row['domain_name']
        # Extract IP addresses from the response column (assuming they are tuples like ('A', 'IP Address'))
        ips = [resp[1] for resp in row['response'] if resp[0] == 'A']
        if domain_name in domain_responses:
            # Append new IPs to the existing list for the domain
            domain_responses[domain_name].extend(ips)
        else:
            # Create a new entry in the dictionary for the domain
            domain_responses[domain_name] = ips

    # Step 3: Remove duplicates from the lists of IP addresses
    for domain in domain_responses:
        domain_responses[domain] = list(set(domain_responses[domain]))

    # Step 4: Convert the dictionary back into a DataFrame with the desired schema
    return pd.DataFrame(list(domain_responses.items()), columns=['domain_name', 'responses'])

def reverse_dns_lookup(df: pd.DataFrame, ip_address: str):
    """
    Perform a reverse DNS lookup to find the domain name(s) associated with an IP address.

    :param df: The DataFrame containing DNS data with 'domain_name' and 'responses' columns.
    :param ip_address: The IP address to search for.
    :return: A list of domain names associated with the given IP address.
    """
    associated_domains = []

    # Iterate over the DataFrame
    for index, row in df.iterrows():
        # Check if the IP address is in the 'responses' list of the current row
        if ip_address in str(row['response']):
            # If found, add the domain name to the list
            associated_domains.append(row['domain_name'])

    return associated_domains

def dns_lookup(df: pd.DataFrame, domain_name: str):
    # Assuming the 'response' column contains sets of responses, including IP addresses
    # Filter for the specific domain and then work with the 'response' column
    responses = df[df['domain_name'] == domain_name]['response']

    # Initialize an empty set to collect unique IP addresses
    unique_ips = set()

    # Iterate over each row in the filtered 'response' column
    for response_set in responses:
        # Assuming each response_set is an iterable (e.g., list, set); adjust as needed
        for response in response_set:
            # Check if the response is an IP address (simple validation; adjust regex for more specific patterns)
            if isinstance(response, tuple) and response[0] == 'A':
                ip_address = response[1]
                unique_ips.add(ip_address)

    # Convert the set of unique IPs back to a list (optional, if you need list functionality)
    return list(unique_ips)

def merge_logs(dns_file_path: str, audit_file_path: str):
    dns_events = parse_dns(dns_file_path)
    audit_events = parse_windows_audit(audit_file_path)  # Placeholder for actual audit log parsing
    
    # Combine the events
    combined_events = dns_events + audit_events
    
    # Convert to DataFrame and sort by 'timestamp'
    df = pd.DataFrame(combined_events)
    df = df.sort_values(by='timestamp')
    
    return df

def event_generator(df: pd.DataFrame, start_datetime: datetime = None, drop_labels: list = None):
    """
    A generator function that yields events from a DataFrame starting from a given datetime.

    :param df: The DataFrame, sorted by date.
    :param start_datetime: The datetime to start from.
    :param drop_labels: Optional list of column labels to exclude from the yielded events.
    :return: Yields events as dictionaries with column names as keys.
    """
    # Filter the DataFrame to start from the given datetime
    filtered_df = df
    if start_datetime is not None:
        filtered_df = df[df['timestamp'] >= start_datetime]

    # Iterate over each row in the filtered DataFrame
    for index, row in filtered_df.iterrows():
        # Convert the row to a dictionary
        event_dict = row.to_dict()
        
        # If drop_labels is provided, drop the specified labels from the dictionary
        if drop_labels is not None:
            for label in drop_labels:
                event_dict.pop(label, None)
        
        # Yield the event as a dictionary
        yield event_dict

def convert_pid_to_dec(pid: str) -> int:
    return int(pid, 16 if pid.startswith('0x') else 10)

def create_audit_table(conn: sqlite3.Connection):
    cursor = conn.cursor()
    create_table_query = (
        "CREATE TABLE audit_logs \n"
        "-- This table captures user activities from the operating system's auditing component (Windows).\n"
        "-- It records process activities within the system, including 'read', 'write', 'execute', 'delete', and 'connect' actions.\n"
        "-- - 'read', 'write', 'execute', and 'delete' actions can occur on files or executables.\n"
        "-- - 'connect' actions occur on network addresses.\n"
        "-- The 'object' field represents the file path, executable, or network address accessed.\n"
        "-- This table is low level; correlating it with other logs provides a fuller picture.\n"
        "-- All TEXT fields are UTF-8 encoded.\n"
        "(\n"
        "    time TEXT,      -- Time of the event in UTC (format: 'YYYY-MM-DD HH:MM:SS')\n"
        "    pid INTEGER,    -- Process ID\n"
        "    ppid INTEGER,   -- Parent Process ID\n"
        "    pname TEXT,     -- Name of the process executable with its full path (e.g., 'C:\\Windows\\System32\\LogonUI.exe')\n"
        "    access TEXT,    -- Type of access; possible values: 'read', 'write', 'execute', 'delete', 'connect'\n"
        "    object TEXT     -- Object accessed: file path, executable, or network address (depending on 'access' type)\n"
        "-- Examples:\n"
        "-- time: '2018-11-03 02:36:52'\n"
        "-- pid: 3212\n"
        "-- ppid: 464\n"
        "-- pname: 'C:\\Windows\\System32\\LogonUI.exe'\n"
        "-- access: 'read'\n"
        "-- object: 'C:\\Windows\\System32\\imm32.dll'  -- For file access\n"
        "-- access: 'connect'\n"
        "-- object: '192.0.2.1:80'                   -- For network connections\n"
        ");"
    )
    
    cursor.execute(create_table_query)
    conn.commit()

def insert_audit_row(conn: sqlite3.Connection, time, pid, ppid, pname, access, object):
    cursor = conn.cursor()
    
    insert_query = '''
    INSERT INTO audit_logs (time, pid, ppid, pname, access, object)
    VALUES (?, ?, ?, ?, ?, ?)
    '''
    
    cursor.execute(insert_query, (time, pid, ppid, pname, access, object))

def preprocess_windows_audit(db_path: str, file_path: str):
    audit_df = parse_windows_audit_df(file_path)
    audit_events_gen = event_generator(audit_df)
    conn = sqlite3.connect(db_path)
    create_audit_table(conn)
    
    try:
        i = 0
        while True:
            audit_ev = next(audit_events_gen)
            insert_audit_row(conn, audit_ev['time'], audit_ev['pid'], audit_ev['ppid'], audit_ev['pname'], audit_ev['access'], audit_ev['object'])
            i += 1
            if i > 100:
                conn.commit()
                i = 0
    except StopIteration:
        pass

    conn.commit()
    conn.close()

def create_dns_table(conn: sqlite3.Connection):
    cursor = conn.cursor()
    
    # SQL to create the table
    create_table_query = (
        "CREATE TABLE dns_requests \n"
        "-- This table captures the DNS resolution requests made by the user, extracted from the local DNS server logs.\n"
        "-- It records each DNS request along with the response received.\n"
        "-- While it's not possible to identify the specific process that made the request, the timestamp can be used to correlate with other logs.\n"
        "(\n"
        "    time TEXT,       -- Time of the request in UTC (format: 'YYYY-MM-DD HH:MM:SS')\n"
        "    domain TEXT,     -- Fully qualified domain name (FQDN) queried (e.g., 'tiles-cloudfront.cdn.mozilla.net')\n"
        "    sld TEXT,        -- Second-level domain extracted from the domain using public suffix rules (e.g., 'mozilla.net')\n"
        "    response TEXT    -- DNS response in JSON format containing resource records (e.g., CNAME, A, NS)\n"
        "                    -- Example: '{\"Response\": {\"CNAME\": [\"alias.example.com\"], \"A\": [\"192.0.2.1\"]}}'\n"
        "                    -- Note:\n"
        "                    --   - The 'Response' object may include multiple record types.\n"
        "                    --   - If no response is received, this field may be empty or contain an error message.\n"
        ");"
    )
    
    # Execute the create table query and close the connection
    cursor.execute(create_table_query)
    conn.commit()

def insert_dns_row(conn: sqlite3.Connection, time, domain, sld, response):
    """
    Inserts a row into the 'dns_requests' table in the specified SQLite database.

    Args:
        db_path (str): The path to the SQLite database file.
        time (str): Time of the request in UTC (format: 'YYYY-MM-DD HH:MM:SS')
        domain (str): Fully qualified domain name (FQDN) queried (e.g., 'tiles-cloudfront.cdn.mozilla.net')
        sld (str): Second-level domain extracted from the domain using public suffix rules (e.g., 'mozilla.net')
        response (str): DNS response in JSON format containing resource records.
    """
    cursor = conn.cursor()
    # SQL to insert a row
    insert_query = '''
    INSERT INTO dns_requests (time, domain, sld, response)
    VALUES (?, ?, ?, ?)
    '''
    
    # Execute the insert query and close the connection
    cursor.execute(insert_query, (time, domain, sld, response))

def preprocess_dns(db_path: str, file_path: str, host_address: str):
    dns_df = parse_dns_df_answer(file_path)
    dns_events = event_generator(dns_df, None, ['type', 'dst', 'query_id'])
    conn = sqlite3.connect(db_path)
    create_dns_table(conn)
    try:
        i = 0
        while True:
            dns_ev = next(dns_events)
            if dns_ev['src'] != host_address or dns_ev['query_type'] != 'A':
                continue
            
            sld = get_tld_and_sld(dns_ev['domain_name'])[1]
            insert_dns_row(conn, dns_ev['timestamp'], dns_ev['domain_name'], sld, str(dns_ev['response']))
            
            i += 1
            if i > 100:
                conn.commit()
                i = 0
    except StopIteration:
        pass

    conn.commit()
    conn.close()

def create_http_table(conn: sqlite3.Connection):
    cursor = conn.cursor()
    
    # SQL to create the table
    create_table_query = (
        "CREATE TABLE browser_history \n"
        "-- This table captures the browsing history extracted from Firefox logs.\n"
        "-- It records each visit along with relevant information such as the time of the visit,\n"
        "-- the host of the visited site, the second-level domain, the HTTP method used for requests,\n"
        "-- and the headers associated with each request.\n"
        "(\n"
        "time TEXT,    -- Time of the visit in UTC (format: 'YYYY-MM-DD HH:MM:SS')\n"
        "host TEXT,    -- Full host visited, including subdomains (e.g., 'tiles-cloudfront.cdn.mozilla.net')\n"
        "sld TEXT,     -- Second-level domain extracted from the host (e.g., 'mozilla.net')\n"
        "method TEXT,  -- HTTP method used ('GET' or 'POST')\n"
        "headers TEXT  -- Request headers concatenated in a readable format.\n"
                      "-- Format: 'Key: Value; Key: Value; ...'\n"
                      "-- Possible keys include:\n"
                      "--   - Path: The request path (e.g., '/images/...').\n"
                      "--   - Length: The length of the request body in bytes (if applicable).\n"
                      "--   - Cookie: Cookies sent with the request.\n"
                      "--   - Referer: The address of the previous web page that linked to the current page.\n"
                      "--   - Location: The target URI of a redirect (if applicable).\n"
                      "-- Note that not all headers are available for all requests.\n"
                      ");")
    
    # Execute the create table query and close the connection
    cursor.execute(create_table_query)
    conn.commit()

def insert_http_row(conn: sqlite3.Connection, time, host, sld, method, param=None, length=None, cookie=None, referer=None, location=None):
    """
    Inserts a row into the 'browser_history' table in the specified SQLite database.

    Args:
        db_path (str): The path to the SQLite database file.
        time (str): Time of the visit in UTC (format: 'YYYY-MM-DD HH:MM:SS')
        host (str): Full host visited, including subdomains (e.g., 'tiles-cloudfront.cdn.mozilla.net')
        sld (str): Second-level domain extracted from the host (e.g., 'mozilla.net')
        method (str): HTTP method used ('GET' or 'POST')
        param (str, optional): The request path (e.g., '/images/...').
        length (str, optional): The length of the request body in bytes (if applicable).
        cookie (str, optional): Cookies sent with the request.
        referer (str, optional): The address of the previous web page that linked to the current page.
        location (str, optional): The target URI of a redirect (if applicable).
    """
    cursor = conn.cursor()

    # Construct the headers field from provided arguments
    
    #print(param, length, cookie, referer, location)
    headers = []
    if not pd.isna(param):
        headers.append(f"Path: {param}")
    if not pd.isna(length):
        headers.append(f"Length: {length}")
    if not pd.isna(cookie):
        headers.append(f"Cookie: {cookie}")
    if not pd.isna(referer):
        headers.append(f"Referer: {referer}")
    if not pd.isna(location):
        headers.append(f"Location: {location}")
    
    # Join headers into a single string
    headers_str = '; '.join(headers)

    # SQL to insert a row
    insert_query = '''
    INSERT INTO browser_history (time, host, sld, method, headers)
    VALUES (?, ?, ?, ?, ?)
    '''
    
    # Execute the insert query and close the connection
    cursor.execute(insert_query, (time, host, sld, method, headers_str))

def preprocess_http(db_path: str, file_path: str):
    http_df = parse_http_df(file_path)
    http_events = event_generator(http_df)
    conn = sqlite3.connect(db_path)
    create_http_table(conn)

    try:
        i = 0
        while True:
            http_ev = next(http_events)
            if http_ev['method'] != 'GET' and http_ev['method'] != 'POST':
                continue

            insert_http_row(conn, 
                            http_ev['timestamp'], 
                            http_ev['host'], 
                            http_ev['sld'], 
                            http_ev['method'], 
                            http_ev['param'], 
                            http_ev['length'], 
                            http_ev['cookie'], 
                            http_ev['referer'], 
                            http_ev['location'])
            i += 1
            if i > 100:
                conn.commit()
                i = 0
    except StopIteration:
        pass

    conn.commit()
    conn.close()

def process_scenario(scenario_dir_path: str, scenario_name: str, host_address: str):
    """
    Opens the directory path, then for each file:
    - if file is security_event.txt then preprocess_windows_audit(security_event_path)
    - if file is dns then preprocess_dns(dns_path)
    - if file is firefox.txt then preprocess_http(firefox_path)

    Before processing any file, creates a database with the name `scenario_name`.
    """
    # Initialize the database manager with a specific database URI
    db_path = scenario_name
    
    # Traverse the directory and process files based on their names
    for file_name in os.listdir(scenario_dir_path):
        full_file_path = os.path.join(scenario_dir_path, file_name)
        
        if file_name == "security_events.txt":
            preprocess_windows_audit(db_path, full_file_path)
            pass
        elif file_name == "dns":
            preprocess_dns(db_path, full_file_path, host_address)
            pass
        elif file_name == "firefox.txt":
            preprocess_http(db_path, full_file_path)
            pass

def process_all(raw_logs_path: str, dest_logs_path: str, delete_existing: bool = True):
    srcs = [
        'S1/logs', 
        'S2/logs', 
        'S3/logs', 
        'S4/logs',
        'M1/h1/logs',
        'M1/h2/logs',
        'M2/h1/logs',
        'M2/h2/logs',
        'M3/h1/logs',
        'M3/h2/logs',
        'M4/h1/logs',
        'M4/h2/logs',
        'M5/h1/logs',
        'M5/h2/logs',
        'M6/h1/logs',
        'M6/h2/logs',
        'SE1/logs', 
        'SE2/logs', 
        'SE3/logs', 
        'SE4/logs',
        'SS1/logs', 
        'SS2/logs', 
        'SS3/logs', 
        'SS4/logs']

    dbs = [
        'S1/scenario.db',
        'S2/scenario.db',
        'S3/scenario.db',
        'S4/scenario.db',
        'M1/h1/scenario.db',
        'M1/h2/scenario.db',
        'M2/h1/scenario.db',
        'M2/h2/scenario.db',
        'M3/h1/scenario.db',
        'M3/h2/scenario.db',
        'M4/h1/scenario.db',
        'M4/h2/scenario.db',
        'M5/h1/scenario.db',
        'M5/h2/scenario.db',
        'M6/h1/scenario.db',
        'M6/h2/scenario.db',
        'SE1/scenario.db',
        'SE2/scenario.db',
        'SE3/scenario.db',
        'SE4/scenario.db',
        'SS1/scenario.db',
        'SS2/scenario.db',
        'SS3/scenario.db',
        'SS4/scenario.db']
    
    host = [
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.130',
        '192.168.223.128',
        '192.168.223.130',
        '192.168.223.128',
        '192.168.223.130',
        '192.168.223.128',
        '192.168.223.130',
        '192.168.223.128',
        '192.168.223.130',
        '192.168.223.128',
        '192.168.223.130',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',
        '192.168.223.128',]
    
    for i in range(len(srcs)):
        print(f"Processing {srcs[i]} into {dbs[i]} with host {host[i]}")
        if delete_existing:
            try:
                os.remove(f'{dest_logs_path}/{dbs[i]}')
            except:
                pass
        
        process_scenario(f'{raw_logs_path}/{srcs[i]}', f'{dest_logs_path}/{dbs[i]}', host[i])


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="Preprocess ATLAS raw logs into CSV and SQLite DB for evaluation and benchmarking. "
                    "Also generates synthetic scenarios based on the original single‐host ones."
    )
    parser.add_argument(
        "-r", "--raw-logs-path",
        dest="raw_logs_path",
        help="Path to ATLAS raw logs directory (e.g. atlas/)"
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
    raw_logs_path = args.raw_logs_path if args.raw_logs_path else "atlas"
    dest_logs_path = args.dest_logs_path if args.dest_logs_path else "scenarios"
    delete_existing = args.delete_existing if args.delete_existing else False

    pp_atlas_original_scenarios(raw_logs_path, dest_logs_path)
    produce_se_logs(raw_logs_path, dest_logs_path)
    produce_ss_logs(raw_logs_path, dest_logs_path)
    process_all(raw_logs_path, dest_logs_path, delete_existing)

