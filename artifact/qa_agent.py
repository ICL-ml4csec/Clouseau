from prompts_manager import get_prompt_sqlexpert
from langgraph.graph import StateGraph, MessagesState, END
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.language_models import BaseChatModel
from typing import Annotated
from datetime import datetime
import sqlite3
import prompts

def darpa_parse_ts(ts_str: str) -> datetime:
    """
    Parse a timestamp string into a datetime object.
    """
    if '.' not in ts_str:
        return datetime.strptime(ts_str, "%H:%M:%S")
    else:
        return datetime.strptime(ts_str, "%H:%M:%S.%f")

def darpa_get_process_record(conn: sqlite3.Connection, pid: int):
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

def darpa_get_children(conn: sqlite3.Connection, parent_pid: int, prefix: str="") -> str:
    """
    Recursively builds and returns a string representing the descendant tree 
    starting from the given parent_pid.
    
    A visual tree structure is created using branching characters. Each child process is
    formatted as: "branch_symbol <pid> - <process_name> - <timestamp> - <cmd_line>".
    
    Args:
        conn (sqlite3.Connection): The SQLite database connection.
        parent_pid (int): The parent process id from which to start the descendant tree.
        prefix (str): Internal parameter for formatting the tree structure (do not change).
    
    Returns:
        str: The descendant tree as a multi-line string.
    """
    output_lines = []
    cur = conn.execute("""
        SELECT rowid, ts, pid, process_name, ppid, cmd_line 
        FROM processes_logs 
        WHERE action = 'CREATE' AND ppid = ?
        ORDER BY ts ASC
    """, (parent_pid,))
    children = cur.fetchall()

    if not children:
        return ""
    
    for idx, child in enumerate(children):
        # Determine branch graphic: "└──" for the last child; "├──" otherwise.
        is_last = (idx == len(children) - 1)
        branch = "└── " if is_last else "├── "
        line = prefix + branch + "{} - {} - {} - {}".format(child[2], child[3], child[1], child[5])
        output_lines.append(line)
        # Prepare a new prefix for the next recursive`` level.
        new_prefix = prefix + ("    " if is_last else "│   ")
        descendant_str = darpa_get_children(conn, child[2], new_prefix)
        if descendant_str:
            output_lines.append(descendant_str)
    return "\n".join(output_lines)

def get_table_schema(db_name: str, table_name: str) -> str:
    """Returns table schema with 3 sample rows.
    
    Args:
        table_name: table name to reterive the schema for.
    
    Returns:
        str: schema and 3 sample rows.
    """
    try:
        with sqlite3.connect(db_name) as cnn:
            cursor = cnn.cursor()
            cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table_name}';")
            create_stmt = cursor.fetchone()[0]
            
            # Get the headers of the table
            cursor.execute(f"PRAGMA table_info({table_name});")
            headers = [column[1] for column in cursor.fetchall()]

            # Get three random rows from the table
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 3;")
            random_rows = cursor.fetchall()

            # Process the rows to limit each column value to at most 15 characters
            processed_rows = []
            for row in random_rows:
                processed_row = []
                for value in row:
                    if isinstance(value, str):
                        if len(value) > 25:
                            value = value[:15] + '..'
                    processed_row.append(value)
                processed_rows.append(tuple(processed_row))

            
            # Format the output as a string
            headers_str = '\t'.join(headers)
            random_rows_str = '\n'.join(['\t'.join(map(str, row)) for row in processed_rows])
            
            #return f"DDL:\n{create_stmt}"
            return f"DDL:\n{create_stmt}\nSample rows:\n{headers_str}\n{random_rows_str}"
    except Exception as e:
        return f"An error occurred: {e}"
    
@tool(parse_docstring=True)
def run_sql_query(db_name: Annotated[str, InjectedToolArg], query: str) -> str:
    """execute sql query against sqlite database and returns the results. An error is returned if the query is invalid.
    
    Args:
        query: the sql query to execute.
    
    Returns:
        str: the results of the query.
    """

    #print(f"Received Query: {query}")

    with sqlite3.connect(db_name) as cnn: 
        cursor = cnn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        if len(rows) == 0:
            return "No results found."
        
        if len(rows) > 30:
            return (
                f"Query returned too many results ({len(rows)} records)."
                " Please refine the query, consider using `GROUP BY`, `DISTINCT` or elminating some of the columns you request."
                " If you are selecting time column, consider using `DISTINCT` without the time column."
            )
        rows_str = '\n'.join(['\t'.join(map(str, row)) for row in rows])
        return rows_str

@tool(parse_docstring=True)
def darpa_get_ancestors(db_name: Annotated[str, InjectedToolArg], pid: int) -> str:
    """This function retrieves the ancestors of a given process ID (PID) from processes_logs table.
    
    Args:
        pid: the process ID to retrieve ancestors for.
    
    Returns:
        str: list of ancestors for the given PID.
    """

    # sqlite does not support stored procedures, this is an alternative approach
    # darpa scenario has a messy record of processes, hard to build process tree
    # this code is here to help the agent with that

    ancestors = []
    with sqlite3.connect(db_name) as conn:
        target_record = darpa_get_process_record(conn, pid)
        current = target_record
        # current record format: (rowid, ts, pid, ppid, process_name, cmd_line)
        while True:
            parent_pid = current[3]  # ppid of current process
            if parent_pid is None:
                break
            parent_record = darpa_get_process_record(conn, parent_pid)
            if not parent_record:
                # Parent record not found (e.g. process created before collection window)
                break
            # Stop if parent's timestamp is after the current process's timestamp
            if darpa_parse_ts(parent_record[1]) > darpa_parse_ts(current[1]):
                break
            # Insert at the beginning so that the oldest ancestor will be first.
            ancestors.insert(0, parent_record)
            current = parent_record
    
    if not ancestors:
        return "Unable to retrieve the ancestors list. This might be due to missing or incomplete data."

    output_lines = []
    for anc in ancestors:
        # Format: "  <pid> - <process_name> - <timestamp> - <cmd_line>"
        output_lines.append("  {} - {} - {} - {}".format(anc[2], anc[4], anc[1], anc[5]))
    # Append the target process (leaf of the lineage)
    output_lines.append("--> {} - {} - {} - {}".format(target_record[2], target_record[4], target_record[1], target_record[5]))
    return "\n".join(output_lines)

@tool(parse_docstring=True)
def darpa_get_descendants(db_name: Annotated[str, InjectedToolArg], pid: int) -> str:
    """This function retrieves the descendants of a given process ID (PID) from processes_logs table.
    
    Args:
        pid: the process ID to retrieve descendants for.
    
    Returns:
        str: list of descendants for the given PID.
    """

    with sqlite3.connect(db_name) as cnn: 
        parent_record = darpa_get_process_record(cnn, pid)
        if not parent_record:
            return f"Unable to retrieve any data on the given pid {pid}."
    
        # Get the children of the given process
        children = darpa_get_children(cnn, pid)
        if len(children) == 0:
            return f"Could not find any descendants for the given pid {pid}."
        
        # Fetch all results
        parent_str = "{} - {} - {} - {}".format(parent_record[2], parent_record[4], parent_record[1], parent_record[5])
        return f"{parent_str}\n{children}"

def atlas_parse_ts(ts_str: str) -> datetime:
    """
    Parse a timestamp string into a datetime object.
    2018-12-01 19:50:11
    """
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def atlas_get_process_record(conn: sqlite3.Connection, pid: int):
    """
    Returns the first CREATE event record for a process instance with the given pid.
    Fields returned: (rowid, ts, pid, ppid, process_name)
    If no CREATE event is found, returns None.
    """
    cur = conn.execute("""
        SELECT rowid, time, pid, ppid, pname
        FROM audit_logs 
        WHERE pid = ?
        ORDER BY time ASC LIMIT 1
    """, (pid,))
    return cur.fetchone()

def atlas_get_children(conn: sqlite3.Connection, parent_pid: int, parent_time: datetime, prefix: str="") -> str:
    """
    Recursively builds and returns a string representing the descendant tree 
    starting from the given parent_pid.
    
    A visual tree structure is created using branching characters. Each child process is
    formatted as: "branch_symbol <pid> - <process_name> - <timestamp> - <cmd_line>".
    
    Args:
        conn (sqlite3.Connection): The SQLite database connection.
        parent_pid (int): The parent process id from which to start the descendant tree.
        prefix (str): Internal parameter for formatting the tree structure (do not change).
    
    Returns:
        str: The descendant tree as a multi-line string.
    """
    output_lines = []
    cur = conn.execute("""
        SELECT MIN(time) AS time, pid, ppid, pname
        FROM audit_logs
        WHERE ppid = ?
        GROUP BY pid, ppid, pname
        ORDER BY time ASC
    """, (parent_pid,))
    children = cur.fetchall()

    if not children:
        return ""
    
    for idx, child in enumerate(children):
        # Determine branch graphic: "└──" for the last child; "├──" otherwise.
        is_last = (idx == len(children) - 1)
        branch = "└── " if is_last else "├── "
        line = prefix + branch + "{} - {} - {}".format(child[1], child[3], child[0])
        output_lines.append(line)
        # Prepare a new prefix for the next recursive`` level.
        new_prefix = prefix + ("    " if is_last else "│   ")
        descendant_str = atlas_get_children(conn, child[1], parent_time, new_prefix)
        if descendant_str:
            output_lines.append(descendant_str)
    return "\n".join(output_lines)

@tool(parse_docstring=True)
def atlas_get_ancestors(db_name: Annotated[str, InjectedToolArg], pid: int) -> str:
    """This function retrieves the ancestors of a given process ID (PID) from audit_logs table.
    
    Args:
        pid: the process ID to retrieve ancestors for.
    
    Returns:
        str: list of ancestors for the given PID.
    """

    # sqlite does not support stored procedures, this is an alternative approach
    # darpa scenario has a messy record of processes, hard to build process tree
    # this code is here to help the agent with that

    ancestors = []
    with sqlite3.connect(db_name) as conn:
        target_record = atlas_get_process_record(conn, pid)
        current = target_record
        # current record format: (rowid, ts, pid, ppid, process_name, cmd_line)
        while True:
            parent_pid = current[3]  # ppid of current process
            if parent_pid is None:
                break
            parent_record = atlas_get_process_record(conn, parent_pid)
            if not parent_record:
                # Parent record not found (e.g. process created before collection window)
                break
            # Stop if parent's timestamp is after the current process's timestamp
            if atlas_parse_ts(parent_record[1]) > atlas_parse_ts(current[1]):
                break
            # Insert at the beginning so that the oldest ancestor will be first.
            ancestors.insert(0, parent_record)
            current = parent_record
    
    if not ancestors:
        return "Unable to retrieve the ancestors list. This might be due to missing or incomplete data."

    output_lines = []
    for anc in ancestors:
        # Format: "  <pid> - <process_name> - <timestamp>"
        # rowid, time, pid, ppid, pname
        output_lines.append("  {} - {} - {}".format(anc[2], anc[4], anc[1]))
    # Append the target process (leaf of the lineage)
    # Format: "--> <pid> - <process_name> - <timestamp>"
    output_lines.append("--> {} - {} - {}".format(target_record[2], target_record[4], target_record[1]))
    return "\n".join(output_lines)

@tool(parse_docstring=True)
def atlas_get_descendants(db_name: Annotated[str, InjectedToolArg], pid: int) -> str:
    """This function retrieves the descendants of a given process ID (PID) from audit_logs table.
    
    Args:
        pid: the process ID to retrieve descendants for.
    
    Returns:
        str: list of descendants for the given PID.
    """

    with sqlite3.connect(db_name) as cnn: 
        parent_record = atlas_get_process_record(cnn, pid)
        if not parent_record:
            return f"Unable to retrieve any data on the given pid {pid}."
    
        # Get the children of the given process
        children = atlas_get_children(cnn, pid, parent_record[1])
        if len(children) == 0:
            return f"Could not find any descendants for the given pid {pid}."
        
        # Fetch all results
        # rowid, time, pid, ppid, pname
        parent_str = "{} - {} - {}".format(parent_record[2], parent_record[4], parent_record[1])
        return f"{parent_str}\n{children}"

class SQLAgent:
    def __init__(self, model: BaseChatModel, db_name: str, configs: dict = {}):
        
        # define tools
        tools = [run_sql_query]
        if configs.get('tools'):
            tools.extend(configs['tools'])

        # define the workflow
        workflow = StateGraph(MessagesState)
        workflow.add_node("agent", self.call_model)
        workflow.add_node("tools", self.call_tool)
        workflow.set_entry_point("agent")
        workflow.add_edge("tools", "agent")
        workflow.add_conditional_edges("agent", self.agent_router, ["tools", END])

        # set agent properties
        self.current_iteration = 0
        self.max_iterations = configs["max_queries"]
        self.max_tokens = configs["max_tokens"]
        self.db_name = db_name
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = model
        self.model = model.bind_tools(tools)

    def agent_router(self, state: MessagesState):
        """Decides whether to call the model or the tools based on the last message."""
        messages = state["messages"]
        last_message = messages[-1]
        if last_message.tool_calls:
            return "tools"
        return END

    def call_tool(self, state: MessagesState):
        tool_calls = state['messages'][-1].tool_calls
        results = []
        for t in tool_calls:
            if not t['name'] in self.tools:      # check for bad tool name from LLM
                print(f"{__name__}: {self.db_name} Received bad tool name from model {t['name']}")
                result = "bad tool name, retry"  # instruct LLM to retry if bad
            else:
                args = t['args'].copy()
                args['db_name'] = self.db_name # inject db_name
                result = self.tools[t['name']].invoke(args)
                self.current_iteration += 1
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
            #break # only one tool call is allowed
        
        if len(tool_calls) > 10:
            print(f"{__name__}: {self.db_name} Received more than one tool call from model")
            results.append(HumanMessage(content="Error: Only one tool call at a time is allowed."))
        
        return {'messages': results}
    
    def call_model(self, state: MessagesState):
        
        if self.current_iteration > self.max_iterations:
            messages = state["messages"] + [HumanMessage(content="Lets try to answer the question with the information we have. As we have reached the maximum number of iterations.")]
            response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]}
        
        messages = state["messages"]
        response = self.model.invoke(messages, max_tokens=self.max_tokens)
        #response = self.model.invoke(messages)
        return {"messages": [response]}
    
def run_agent(llm: BaseChatModel, db_name: str, table_name: str, qa_examples: dict, question: str, configs: dict):

    examples = ""
    for k, v in qa_examples.items():
        examples += f"{k}\n{v}\n\n"
    examples = examples.strip()

    graph_cfg = {'recursion_limit': 125}
    messages = [HumanMessage(content=get_prompt_sqlexpert(
        get_table_schema(db_name, table_name),
        examples, 
        configs["max_queries"], 
        question))]
    abot = SQLAgent(llm, db_name=db_name, configs=configs)
    final_result = ''

    try:
        result = abot.graph.invoke({"messages": messages}, config=graph_cfg)
        final_result = f"{result['messages'][-1].content}"
    except Exception as e:
        final_result = f"We had a problem understanding the question. Please try again. \n{e}"
    
    return final_result

def atlas_browser_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    return run_agent(llm, db_name, "browser_history", prompts.browser_examples_qa, question, configs)

def atlas_dns_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    return run_agent(llm, db_name, "dns_requests", prompts.dns_examples_qa, question, configs)

def atlas_audit_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    configs = configs.copy()
    configs['tools'] = [atlas_get_ancestors, atlas_get_descendants]
    return run_agent(llm, db_name, "audit_logs", prompts.audit_examples_qa, question, configs)

def darpa_http_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    return run_agent(llm, db_name, "http_logs", prompts.darpa_browser_examples_qa, question, configs)

def darpa_flow_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    return run_agent(llm, db_name, "flow_logs", prompts.darpa_flow_examples_qa, question, configs)

def darpa_processes_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    configs = configs.copy()
    configs['tools'] = [darpa_get_ancestors, darpa_get_descendants]
    return run_agent(llm, db_name, "processes_logs", prompts.darpa_process_examples_qa, question, configs)

def darpa_files_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    return run_agent(llm, db_name, "file_logs", prompts.darpa_files_examples_qa, question, configs)

def darpa_dns_agent(llm: BaseChatModel, db_name: str, question: str, configs: dict):
    return run_agent(llm, db_name, "dns_logs", prompts.darpa_dns_examples_qa, question, configs)
    