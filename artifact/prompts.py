eval_agent = """You will be provided with a security investigation report. Your task is to **summarize the investigation findings for evaluation purposes**. Focus on **artifacts directly related to the attack**, such as **malicious websites, network addresses, files, or processes controlled by malicious actors**. Make a distinction between malicious (spawned and executed by malicious actor) and legitimate processes (existing benign processes, that were used in the attack), for the latter, include the time they were hijacked if possible.

**Response Format:**  
Return the summary in **JSON format** as a list of objects, with the structure below. Example:

```json
{
    "addresses": ["10.20.30.40"],
    "domains": ["mal_domain.evil"],
    "files": ["mal_file.rtf"],
    "malicious_processes": [{"pid":218, "name":"mal1.exe"}],
    "tainted_processes": [{"pid":2191, "name": "word.exe", "hijack_time": "2019-08-09 00:00:58"}],
}
```"""

investigation_agent = """You are a security expert tasked with conducting a security investigation using provided data sources and analysis tools. These tools act as abstraction layers, allowing you to query log data directly. Your responsibility is to formulate precise and context-rich questions to effectively utilize these tools. Identify attack related artifacts, such as processes names, their PIDs, files, network addresses, and domains used by the attackers. The evaluation of your report will be based on the accuracy and relevance of the identified artifacts. You will be presented with the logs of a single machine.

Guidelines:
- Clearly specify all relevant details within your questions (e.g., exact timestamps, IP addresses, process names). Do NOT assume tools are aware of contextual information about the investigation.
- You may perform up to {max_questions} queries.
- Use backward analysis (tracking events back in time), forward analysis (tracking subsequent activities), and correlation methods (e.g., timing, data volume) to identify entities related to the attack.
- Although you will given specific task to investigate, you have to report any suspicious activity you find, even if it is not related to the task.
- Conclude your investigation by summarizing findings clearly.

Information about the environment:
{environment}

Attack Lead:
{initial_message}
"""

ablation_agent = """You are a security expert, your task is to conduct security investigation using the available data sources. The logs of the incident have been processed into SQLite database. Your role lies in querying this database to fulfill your investigation objectives and map this incident to the cyber kill chain. Conclude your investigation by producing a comprehensive report, detailing attack time line and includes malicious processes names and their PIDs as well as any attack artifacts (files, network addresses and domains). 

* You are allowed to perform {max_queries} queries.
* Rely on backward analysis, forward analysis and correlation (e.g. time correlation and data size) to reveal the attack related entities.

* Information about the environment:
{environment}

* Database Schema:
{schema}

* Examples:
{examples}

Attack Lead:
{initial_message}
"""

sqlexpert_agent = """You are an SQL expert assigned to answer questions related to security incidents by querying an SQLite database. Break down the task into multiple simple SQLite queries instead of one complex query. Use only the provided tables and columns. Analyze the query results and provide a clear, concise answer based on the retrieved data. If the data is insufficient or the question cannot be answered, clearly explain why.

**Schema:**  
{schema}

**Examples:**  
{examples}

Reply with a tool call or your final answer to the question. You will are allowed to preform {max_queries} queries. Although you will be given specific question to answer, you have to report any abnormal behavior you find within the data, even if it is not related to the question.

Question: {question}
"""

chief_inspector_agent = """You are a cybersecurity expert tasked with analyzing a security incident on a single compromised machine. Your goal is to clearly identify the attack source, establish a timeline of attack events, attack objectives, and mapping the attack to the cyber kill chain. You will receive a message from monitoring team as a starting lead, environment context, and given access to the compromised machine logs. Your analysis must clearly list attack artifacts such as process names and their PIDs, Files involved, Network addresses (IPs) and attacker-controlled domains.

Instructions:
* This is an iterative process, with each investigation you will find new artifacts and leads, investigate each one thoroughly, leave no stone unturned.
* Be aggressive in your investigation, do not stop until you have inspected all attack artifacts you found and have exhausted all possible leads.
* You will be allowed to conduct a maximum of {max_investigations} investigations, you will be prompted to stop when we hit this limit.
* At the end, reflect on ALL the reports you received from your investigators and produce a final report.
* Your final report should include all details of the attack you found, including the starting point, attack vector, timeline, and objectives. 
* Your final report will be evaluated based on accuracy, clarity, and correctness of identification of attack artifacts.
* For attack related processes, include their PIDs in the final report. If a process was hijacked, include the time it was hijacked.
* When reporting domains, include IP addresses associated with them.
* Think and reflect on each report you receive, and then decide what to do next.

Environment: 
{environment}

Message from SOC: 
{initial_message}
"""

browser_examples_qa = {
    # High-level overview focusing on second-level domains and their visit counts
    "Give a high-level overview of the most visited second-level domains (SLDs), ordered by visit count.": 
    "-- Get the most visited second-level domains (SLDs)\n"
    "-- Grouping the results by SLD to get a count of visits for each domain\n"
    "SELECT sld, COUNT(*) as visit_count FROM browser_history GROUP BY sld ORDER BY visit_count DESC;",

    # High-level overview of second-level domains with a breakdown of all websites under each SLD
    "Show all websites visited, grouped by second-level domain (SLD).": 
    "-- Group websites by SLD, showing only unique hosts under each SLD in a list\n"
    "SELECT sld, GROUP_CONCAT(host, ', ') as websites FROM (SELECT DISTINCT sld, host FROM browser_history) GROUP BY sld;",

    # High-level overview for websites visited within a specific timeframe (not exceeding 1 hour)
    "Show all websites visited between 3:00 PM and 4:00 PM on 1st August 2018, grouped by second-level domain (SLD).": 
    "-- Get a breakdown of websites visited between a specific time range (3:00 PM and 4:00 PM)\n"
    "-- Grouping by second-level domain (SLD) and host, focusing on a specific time window of 1 hour\n"
    "SELECT sld, host, COUNT(*) as visit_count FROM browser_history WHERE time BETWEEN '2018-08-01 15:00:00' AND '2018-08-01 16:00:00' GROUP BY sld, host  ORDER BY sld, visit_count DESC;",

    # Specific website visit query (showing all columns) where the user might have been redirected
    "Show all details for visits to the website xyz.tld.": 
    "-- Show all details for visits to xyz.tld\n"
    "-- including records where xyz.tld is found in headers indicating a redirection to it\n"
    "SELECT * FROM browser_history WHERE (host LIKE '%xyz.tld%' OR sld LIKE '%xyz.tld%' OR headers LIKE '%xyz.tld%');",

    # Same query but within a specific timeframe of 1 hour
    "Show all details for visits to xyz.tld between 2:00 PM and 3:00 PM on 1st August 2018.": 
    "SELECT * FROM browser_history WHERE (host LIKE '%xyz.tld%' OR sld LIKE '%xyz.tld%' OR headers LIKE '%xyz.tld%') AND time BETWEEN '2018-08-01 14:00:00' AND '2018-08-01 15:00:00';"
}

dns_examples_qa = {
    # Example 1: Time of requests - List all DNS requests made within a specific timeframe
    "List all DNS requests made between 2:00 PM and 3:00 PM on 1st August 2018.":
    "SELECT * FROM dns_requests WHERE time BETWEEN '2018-08-01 14:00:00' AND '2018-08-01 15:00:00';",

    # Example 2: Finding a response for a domain - Show the DNS response for a specific domain
    "Show the DNS response for the domain 'example.com'.":
    "SELECT response FROM dns_requests WHERE domain LIKE '%example.com%';",

    # Example 3: Finding all subdomains of an SLD - List all subdomains queried under 'example.com'
    "List all subdomains queried under the second-level domain 'example.com'.":
    "SELECT DISTINCT domain FROM dns_requests WHERE sld LIKE '%example.com%';",

    # Example 4: Finding domains related to IP address - Find all domains that resolved to the IP address '192.0.2.1'
    "Find all domains that resolved to the IP address '192.0.2.1'.":
    "SELECT DISTINCT domain FROM dns_requests WHERE response LIKE '%192.0.2.1%';",
}

audit_examples_qa = {
    # Example 1: Locate newly installed processes by filtering with 'write' access and files that end with '.exe'
    "Locate newly installed processes":
    "-- To find new installed processes we need to look for 'write' access on a file ending with .exe\n"
    "-- This query finds all 'write' actions on files that are executables (ending with '.exe').\n"
    "-- It helps identify newly installed or modified executable files.\n"
    "SELECT * FROM audit_logs WHERE access = 'write' AND object LIKE '%.exe';",

    # Example 2: List all processes that connected to an IP address
    "List all processes that connected to the IP address '192.0.2.1'.":
    "-- This query retrieves all 'connect' actions where the object (network address) includes '192.0.2.1'.\n"
    "-- Using LIKE '%192.0.2.1%' to match the IP address regardless of port or additional data.\n"
    "-- You may optinally display time for this, but becareful as it may return too many results.\n"
    "SELECT DISTINCT pname, pid FROM audit_logs WHERE access = 'connect' AND object LIKE '%192.0.2.1%';",

    # Example 3: List all processes that read from a file within a specific time frame
    "List all processes that read from the file 'file.ext' between 2:00 PM and 3:00 PM on 1st August 2018.":
    "-- This query finds all 'read' actions on files where the object includes 'file.ext' within the specified time frame.\n"
    "-- Using LIKE '%file.ext%' to match the file name, disregarding the directory path.\n"
    "SELECT DISTINCT pname, pid FROM audit_logs WHERE access = 'read' AND object LIKE '%file.ext%' AND time BETWEEN '2018-08-01 14:00:00' AND '2018-08-01 15:00:00';",

    # Example 4: List the time a process was executed
    "When was `someprocess.exe` executed?":
    "-- simple question, we just need to be carefull with how we query the process\n"
    "-- Using LIKE '%someprocess.exe%' to match the process, as the logs contains the full and simple matching will fail.\n"
    "SELECT DISTINCT time, pname, pid, ppid, access, object FROM audit_logs WHERE access = 'execute' AND object LIKE '%someprocess.exe%';",

    # Example 5: Find the execution tree for a process
    "Find the execution tree for process 'someprocess.exe'.":
    "-- Step 1: Retrieve the PID(s) and parent PID(s) (ppid) of processes named 'someprocess.exe'.\n"
    "SELECT DISTINCT pid, pname, ppid FROM audit_logs WHERE process_name LIKE '%someprocess.exe%';\n\n"
    "-- Step 2: Use helper tools to get the list of ancestors and list of descendants."
}

darpa_dns_examples_qa = {
    "Find all domains associated with 192.0.0.1": 
    "SELECt * FROM dns_logs WHERE answers LIKE '%192.0.0.1%'",

    "Find all addresses associated with example.com":
    "SELECt * FROM dns_logs WHERE query LIKE '%example.com%'",

    "Purpose": 
    "-- consult the local DNS server to find domains associated with addresses or addresses associated with domains;"
}

darpa_browser_examples_qa = {
    # High-level overview focusing on second-level domains and their visit counts
    "Give a high-level overview of the most visited sites": 
    "-- Get the most visited sites along with their ip addresses, group by ip address\n"
    "SELECT dst_ip, host, COUNT(*) as visit_count FROM http_logs GROUP BY dst_ip ORDER BY visit_count DESC;",

    # High-level overview for websites visited within a specific timeframe (not exceeding 1 hour)
    "Show all websites visited between 3:00 PM and 4:00 PM": 
    "-- Get a breakdown of websites visited between a specific time range (3:00 PM and 4:00 PM)\n"
    "SELECT dst_ip, host, COUNT(*) as visit_count FROM http_logs WHERE ts BETWEEN '15:00:00' AND '16:00:00' GROUP BY dst_ip  ORDER BY visit_count DESC;",

    # Specific website visit query (showing all columns) where the user might have been redirected
    "Show all uri requests for xyz.tld.": 
    "-- select all distinct URIs\n"
    "-- possibly showing files downloaded\n"
    "SELECT DISTINCT uri FROM http_logs WHERE uri LIKE '%xyz.tld%';",

    # Same query but within a specific timeframe of 1 hour
    "How many bytes sent and received for xyz.tld between 11:00 AM and 3:00 PM": 
    "-- Get the total bytes sent and received for xyz.tld between 2:00 PM and 3:00 PM\n"
    "SELECT SUM(request_body_len) AS total_sent, SUM(resp_body_len) AS total_received FROM http_logs WHERE host LIKE '%xyz.tld%' AND ts BETWEEN '11:00:00' AND '15:00:00';"
}

darpa_process_examples_qa = {
    "List all processes where address 192.0.2.1 is found in the command line":
    "SELECT * FROM processes_logs WHERE cmd_line LIKE '%192.0.2.1%';",

    "List all processes created by user zleazer between 11:00 AM and 3:00 PM.":
    "SELECT * FROM processes_logs WHERE action = 'CREATE' AND user like '%zleazer%' AND ts BETWEEN '11:00:00' AND '15:00:00';",

    "find all instances of process ping.exe":
    "-- ping.exe can be executed by powershell.exe for example\n"
    "-- in such cases we look in the command line as well\n"
    "SELECT ts, process_name, pid, ppid, cmd_line FROM processes_logs WHERE process_name LIKE '%ping.exe%' OR cmd_line LIKE '%ping.exe%' AND action = 'CREATE';",
}

darpa_files_examples_qa = {
    "Locate newly installed executables":
    "-- To find new installed executables we need to look for CREATE, RENAME actions\n"
    "-- filter files ending with .exe or .bat for example\n"
    "SELECT ts, pid, process_name, action, file_path FROM file_logs WHERE (action = 'CREATE' OR action = 'RENAME') AND (file_path LIKE '%.exe' OR file_path LIKE '%.bat');",
    
    "Find largest files read from between 11:00 AM and 3:00 PM":
    "SELECT ts, pid, process_name, file_path, size FROM file_logs WHERE action = 'READ' AND ts BETWEEN '11:00:00' AND '15:00:00' ORDER BY size DESC LIMIT 10;\n"
    "-- You could filter your results by setting action field to 'READ' or 'WRITE' or 'DELETE' or 'RENAME' or 'CREATE'.\n",

    "TIPS:":
    "-- You could filter files by path with file_path field\n"
    "-- `WHERE file_path NOT (LIKE '%C:\\Windows%')` to exclude system files\n"
    "-- You could filter files with extentions\n"
    "-- `WHERE file_path NOT (LIKE '%.dll' OR LIKE '%.exe%')` to execlude dll and executables\n"
    "-- if question cannot be answered with the data you have, inform the user."
    "-- There are four types of actions: CREATE, RENAME, DELETE, and WRITE.\n"
}

darpa_flow_examples_qa = {
    "Find top IP addresses connected to by our host":
    "-- The flow table is filtered to include traffic for specific host only\n"
    "-- outbound means from this host to the destination address\n"
    "-- inbound means to this host from the source address\n"
    "-- in all cases, ip field is external address\n"
    "SELECT ip, COUNT(*) AS count FROM flow_logs GROUP BY ip ORDER BY count DESC;",

    # Example 2: List all processes that connected to an IP address
    "Find top IP addresses with most exchanged bytes":
    "select ip, SUM(size) AS total_size from flow_logs GROUP BY ip ORDER BY total_size DESC;\n"
    "-- you can further filer this to exclude ip addreses (for example local ones), or identify addresse where hosts sent the most or read the most by changing the direction of the flow\n",

    "List all pid and their process_name's that connected to IP 192.1.1.1, the amount of data exchanged and the duration of all connections":
    "-- This is a multi step query. First, we find pids connected to ip address"
    "SELECT pid, process_name, ip, SUM(size) FROM flow_logs WHERE ip = '192.1.1.1' GROUP BY pid, process_name, ip;\n",
    "-- Then we can use the pids to find the duration of the connections\n"
    "-- For each pid, we find the duration of the connections\n"
    "SELECT MIN(ts) AS start_time, MAX(ts) AS finish_time FROM flow_logs WHERE ip = '192.1.1.1' AND pid = [pid value];\n"
    "-- combine the results and return a comprehensive view of the connections\n"

    "TIPS:":
    "-- only TCP and UDP traffic is recorded here.\n"
    "-- if question cannot be answered with the data you have, inform the user."
}

darpa_audit_examples_qa = {
    "Locate newly installed executables":
    "-- To find new installed executables we need to look for CREATE_FILE, RENAME_FILE actions\n"
    "-- filter files ending with .exe or .bat for example\n"
    "SELECT * FROM audit_logs WHERE (action = 'CREATE_FILE' OR action = 'RENAME_FILE') AND (object LIKE '%.exe%' OR object LIKE '%.bat%');",

    # Example 2: List all processes that connected to an IP address
    "List all processes that connected to the IP address '192.0.2.1'.":
    "-- This query retrieves all '%MESSAGE' actions where the object (a network address) includes '192.0.2.1'.\n"
    "-- Using `LIKE '%192.0.2.1%'` to match the IP address regardless of port or additional data.\n"
    "-- You may optinally display time for this, but be careful as it may return too many results.\n"
    "-- Only TCP and UDP traffic is recored with MESSAGE action\n"
    "SELECT DISTINCT process_name, pid, ppid FROM audit_logs WHERE action LIKE '%MESSAGE' AND object LIKE '%192.0.2.1%';",

    # Example 3: List all processes that read from a file within a specific time frame
    "List all processes created by user zleazer between 11:00 AM and 3:00 PM.":
    "SELECT process_name, pid, ppid, object FROM audit_logs WHERE action = 'CREATE_PROCESS' AND principal like '%zleazer%' AND ts BETWEEN '11:00:00' AND '15:00:00';",

    "find all instances of process ping.exe":
    "-- simple question, we just need to be carefull with how we query the process\n"
    "-- Using LIKE '%ping.exe%' to match the process, as the logs contains the full and simple matching will fail.\n"
    "SELECT DISTINCT process_name, pid, ppid, object FROM audit_logs WHERE process_name LIKE '%ping.exe%' OR object LIKE '%ping.exe%' AND action = 'CREATE_PROCESS';",

    # Example 5: Find the execution tree for a process
    "Find the execution tree for process 'someprocess.exe'.":
    "-- Step 1: Retrieve the PID(s) and parent PID(s) (ppid) of processes named 'someprocess.exe'.\n"
    "SELECT DISTINCT proces_name, pid, ppid, object FROM audit_logs WHERE process_name LIKE '%someprocess.exe%'; AND action = 'CREATE_PROCESS'\n\n"
    "-- Step 2: Use the parent PID(s) to find the details of the parent process(es).\n"
    "SELECT DISTINCTproces_name, pid, ppid, object FROM audit_logs WHERE action = 'CREATE_PROCESS' AND pid = [ppid_value]; -- Replace [ppid_value] with the ppid retrieved from Step 1."
    "-- Repeat Step 2 for each parent process to construct the execution tree untill the ppid returned is NULL"
    "-- Combine this with the timing of the execution (the first execution of the process in question) to give a comprehensive view of the execution tree."
}

opt_env_context = """You are investigating a security incident in an enterprise with over 1000 machines. Desktops use IPs 142.20.56.0–142.20.59.254 (Windows 10, internet browsing and file downloads allowed, but no technical controls preventing unauthorized executables), and servers use 142.20.60.1–142.20.64.254 (including DNS at 142.20.61.130/131 and SMB at 142.20.61.135). USB is disabled on all machines. The compromised system is a desktop suspected of being the attack entry point. You have 24 hours of its logs (HTTP, processes, files, and TCP/UDP flows) from midnight to 11:59 PM on the attack day—dates (month/day/year) have been removed, and you only have data from this single machine, so there is no need to reference its IP or the specific date in your questions. Investigate this incident using the logs. In all machines, we have maintenace batch files residing at C:\\ncr\\, and periodic execution of ping to localhost and qwinsta.exe. These are not malicious, you are free to ignore them."""

#darpa_init_c1_ip = "We noticed unusual connections to external address at 132.197.158.98. Investigate this connection and establish its purpose to construct the attack narrative and build cyber kill chain."
opt1_c1 = "We noticed unusual connections to external address at 132.197.158.98. investigate all processes that communicated with this address and find any causally related abnormal actions and behavior. The compromised machine address is 142.20.56.202."
opt1_c2 = "We noticed unusual connections to news.com. Find all IP addresses associated with this site, investigate all processes communicated with these addresses and find any causally related abnormal actions and behavior. The compromised machine address is 142.20.56.202."
opt1_c3 = "We noticed abnormal download of runme.bat (GET news.com/runme.bat) and repeated and frequent connections to 132.197.158.98. Initiate a comprehensive investigation to analyze all associated network and execution activities and verify the purpose of these connections within the attack narrative and cyber kill chain. The compromised machine address is 142.20.56.202."

opt2_c1 = opt1_c1.replace("132.197.158.98","202.6.172.98").replace("142.20.56.202", "142.20.57.246")
opt2_c2 = opt1_c1.replace("142.20.56.202", "142.20.57.246")
opt2_c3 = opt1_c2.replace("142.20.56.202", "142.20.57.246")
opt2_c4 = opt1_c2.replace("news.com", "sports.com").replace("142.20.56.202", "142.20.57.246")
opt3_c1 = opt1_c1.replace("132.197.158.98","53.192.68.50").replace("142.20.56.202","142.20.56.52")
opt3_c2 = opt1_c2.replace("news.com","notepad-plus.sourceforge.net").replace("142.20.56.202","142.20.56.52")
opt3_c3 = opt1_c2.replace("news.com","microsoft.com").replace("142.20.56.202","142.20.56.52")

#darpa_init_c3_bat = "We noticed unusual download and execution of a file called `cKfGW.exe`. Investigate this execution and establish its purpose to construct the attack narrative and build cyber kill chain."
#opt3_c3 = "Alert: Suspicious download and execution of file 'cKfGW.exe' have been detected. Find how the executable was downloaded, identify any processes that communicated with this source and investigate them thoroughly. The compromised machine address is 142.20.56.52."

atlas_env_context = """The incident occurred in a small enterprise network where the local DNS server (192.168.223.2) is intact and hasn't been compromised. USB ports are disabled, and although users can access the internet and download files, they are prohibited (but not enforced) from installing executables. Available data includes local DNS server resolution logs, audit logs from the compromised machine, and browser history, with no access to disk images or memory dumps. The attack occurred within the time frame of log collection, and the machine is assumed benign at the start of this period. When generating the attack artifacts list, do not classify attacker-leveraged programs or files (e.g., firefox.exe) as malicious; instead, include them in the tainted list or in files list."""
atlas_init_ip = "Alert: Persistent and suspicious connections to IP 192.168.223.3 have been detected. Conduct an immediate, in-depth investigation to trace all responsible processes, analyze their behavior, and determine their role in the attack narrative and cyber kill chain."
atlas_init_s_ip = "Alert: Persistent and suspicious connections to IP 46.11.60.81 have been detected. Conduct an immediate, in-depth investigation to trace all responsible processes, analyze their behavior, and determine their role in the attack narrative and cyber kill chain."
atlas_init_domain = "Alert: Unusual and aggressive connections to domain 0xalsaheel.com have been observed. Initiate a comprehensive investigation to analyze all associated network and execution activities and verify the purpose of these connections within the attack narrative and cyber kill chain."
atlas_init_sb_domain = "Alert: Unusual and aggressive connections to official-system-monitoring.xyz have been observed. Initiate a comprehensive investigation to analyze all associated network and execution activities and verify the purpose of these connections within the attack narrative and cyber kill chain."
atlas_init_file = "Alert: Suspicious download and execution of file 'payload.exe' have been detected. Conduct a rigorous analysis of this download and execution and concurrently investigate any associated network connections triggered by its execution to uncover its malicious role in the attack narrative and cyber kill chain."
atlas_init_file_py = "Alert: Suspicious download and execution of file 'pypayload.exe' have been detected. Conduct a rigorous analysis of this download and execution and concurrently investigate any associated network connections triggered by its execution to uncover its malicious role in the attack narrative and cyber kill chain."
atlas_init_sb_file = "Alert: Suspicious download and execution of file 'systempatch.exe' have been detected. Conduct a rigorous analysis of this download and execution and concurrently investigate any associated network connections triggered by its execution to uncover its malicious role in the attack narrative and cyber kill chain."
atlas_init_sb_file_py = "Alert: Suspicious download and execution of file 'pysystempatch.exe' have been detected. Conduct a rigorous analysis of this download and execution and concurrently investigate any associated network connections triggered by its execution to uncover its malicious role in the attack narrative and cyber kill chain."
