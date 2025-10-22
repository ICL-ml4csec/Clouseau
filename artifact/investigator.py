from prompts_manager import get_prompt_investigation_agent
from qa_agent import atlas_browser_agent, atlas_dns_agent, atlas_audit_agent
from qa_agent import darpa_http_agent, darpa_dns_agent, darpa_processes_agent, darpa_files_agent, darpa_flow_agent
from langgraph.graph import StateGraph, MessagesState, END
from langchain_core.messages import HumanMessage, ToolMessage, AIMessage
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.language_models import BaseChatModel
from typing import Annotated
import constants

class ds_ctx(dict):
    def __init__(self, llm: BaseChatModel, configs: dict = {}):
        self.llm = llm
        self.db_name = configs['db_name']
        self.configs = configs
        dict.__init__(self, {'db': self.db_name})

@tool(parse_docstring=True)
def ask_audit(ds: Annotated[ds_ctx, InjectedToolArg],  question: str) -> str:
    """This function processes queries about the `audit_logs` table, which logs user activities on a Windows system, including file access, process execution, deletion, and network connections. Each log entry includes a timestamp, process ID (PID), parent process ID (PPID), executable path, type of access (e.g., read, write, execute) and target object (e.g., file path or network address). The table is useful for tracking process interactions with files or network addresses, which can support security audits and system monitoring. Examples: question="List newly installed executables and find which processes installed them", question="List all processes that connected to the IP address '192.0.2.1'.", question="Find the execution tree 'sample.exe'.", question="Find ancestors and all descendants of 'sample.exe'", question="find acnestors and descendants of pid 1234", question="List all new executables written between 2:00 PM and 3:00 PM on 1st August 2030 by the process with PID 1234.", question="Identify the most frequent IP addresses connected to, and list all proceses who made these connections."

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return atlas_audit_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_dns(ds: Annotated[ds_ctx, InjectedToolArg],  question: str) -> str:
    """This function processes queries related to the `dns_requests` table, which logs DNS requests handled by a local DNS server. Each entry includes a timestamp, fully qualified domain name (FQDN) queried, second-level domain (SLD), and DNS response (in JSON format, including CNAME, A, or NS records). The table helps analyze DNS request patterns, domain access frequency, and network traffic, which is useful for DNS troubleshooting and security monitoring. Examples: question="List all DNS requests made between 2:00 PM and 3:00 PM on 1st August 2030.", question="Show the DNS response for the domain 'example.com'.", question="List all subdomains queried under the second-level domain 'example.com'.", question="Find all domains that resolved to the IP address '192.0.2.1'.", question="Provide a summary of the most frequently queried second-level domains."

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return atlas_dns_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_browser(ds: Annotated[ds_ctx, InjectedToolArg], question: str) -> str:
    """This function handles queries for the `browser_history` table, which captures Firefox browsing activity, including visit timestamps, full host names, second-level domains, HTTP methods (e.g., GET, POST), and request headers. This table allows for tracking user browsing behavior, commonly visited sites, and interaction types, supporting analysis of user activity on various websites. Examples: question="Show all websites visited, grouped by second-level domain (SLD).", question="Show all pages visited for site xyz, and how frequent were these visits.", question="Show a summary of user's browsing activity between 2:00 PM and 3:00 PM on 1st August 2030.", question="Provide a summary of user browsing activity, highlighting the most visited second-level domains."
    
    Args:
        question: string.

    Returns:
        answer: string.
    """
    return atlas_browser_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_darpa_http(ds: Annotated[ds_ctx, InjectedToolArg], question: str) -> str:
    """This function processes queries related to `http_logs` table, which records HTTP traffic details including timestamps,source and destination IP addresses and ports, HTTP methods, host names, URIs, request and response body lengths. This table is essential for analyzing web traffic, and tracking client-server interactions. This table contains request made by the host in question only.
    
    Examples:
      question="Give a high-level overview of the most visited sites",
      question="Show all websites visited between 3:00 PM and 4:00 PM and report paths visited and responses and requests size",
      question="Show all uri requests for xyz.tld.",
      question="What is the IP address for xyz.tld?",
      question="What websitese are associated with 192.1.1.1?",
      question="Show all POST requests made to xyz.tld.",

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return darpa_http_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_darpa_files(ds: Annotated[ds_ctx, InjectedToolArg], question: str) -> str:
    """
    This function processes queries for `files_logs` table, which logs system events on a Windows system related to processes and their files activities. It includes information about files manipulation for each process. This include creation, write, read, delete and rename events for each processes, recording the timestamp, size and process ID (PID) and its parent PID. When appropriate ask the function to execlude files with specific exetensions or in specific file paths.

    Examples:
      question="Locate newly installed executables and report pid, ppid file path and timestamp",
      question="Find largest files read from between 11:00 AM and 3:00 PM, and report their pid, ppid and timestamp",
      question="Find all files deleted by user zleazer between 11:00 AM and 3:00 PM.",
      question="Find all files renamed by pid 1234 between 11:00 AM and 3:00 PM.",

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return darpa_files_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_darpa_flows(ds: Annotated[ds_ctx, InjectedToolArg], question: str) -> str:
    """
    This function processes queries for `flow_logs` table, which logs system events on a Windows system related to processes and their network activities. It includes information about IP addresses connected to. The table has been filtered to include only network flows from a specific host related to your task. For each row, the table record IP address, port number, protocol, size (number of bytes), direction (inbound or outbound), timestamp and the process ID (PID) and parent process ID (PPID). `flow_logs` table only record TCP and UDP flows.

    Examples:
      question="Find top IP addresses connected to by our host",
      question="Find top IP addresses with most exchanged bytes",
      question="List all processes that connected to IP 1.2.3.4",
      question="List all pid and their ppid's that connected to IP 192.1.1.1, the amount of data exchanged and the duration of communication",

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return darpa_flow_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_darpa_processes(ds: Annotated[ds_ctx, InjectedToolArg], question: str) -> str:
    """
    This function processes queries for `processes_logs` table, which logs system events on a Windows system related to processes executions. It includes command line information for each process and records process names, its pid, its parent pid (ppid), time of execution, time of termination and the user who executed this process. Correlate this table with other tables to find a process name and command line or to find about its behavior.

    Examples:
      question="List all processes created by user zleazer between 11:00 AM and 3:00 PM.",
      question="List all processes that where command line has '192.0.2.1'",
      question="Find the process execution tree for 'cmd.exe' with pid 1234 and ppid 5678. Detailing its ancestors and descendants.",
      question="List all ancestors and descendants of pid 1234, along with their creation time, process name and command line.",

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return darpa_processes_agent(ds.llm, ds.db_name, question, ds.configs)

@tool(parse_docstring=True)
def ask_darpa_dns(ds: Annotated[ds_ctx, InjectedToolArg], question: str) -> str:
    """
    This tool can help you find information about DNS requests and responses. Due to the way the data is collected, we only kept a record of domains and their associated IPv4 addresses. The tool will help you in finding the IP address of a domain, or the domain name associated with an IP address.

    Examples:
      question="List all IP addresses associated with example.com",
      question="What domains associated with IP address '192.0.2.1'",

    Args:
        question: string.

    Returns:
        answer: string.
    """
    return darpa_dns_agent(ds.llm, ds.db_name, question, ds.configs)


@tool(parse_docstring=True)
def decode_base64(question: str) -> str:
    """This function decodes a base64 encoded string.

    Args:
        question: string.

    Returns:
        answer: string.
    """
    import base64
    # Add padding if missing
    try:
        missing_padding = len(question) % 4
        if missing_padding:
            question += "=" * (4 - missing_padding)
        return base64.b64decode(question).decode('utf-8')
    except Exception as e:
        return f"Error decoding base64: {str(e)}"

class InvestigateAgent:
    def __init__(self, llm: BaseChatModel, configs: dict):
        # define tools
        tools = [ask_audit, ask_dns, ask_browser]
        if configs.get('is_darpa', False):
            tools = [ask_darpa_files, ask_darpa_flows, ask_darpa_processes, ask_darpa_http, ask_darpa_dns, decode_base64]

        # define the workflow
        workflow = StateGraph(MessagesState)
        workflow.add_node("agent", self.call_model)
        workflow.add_node("tools", self.call_tool)
        workflow.add_node("error", self.call_error)
        workflow.set_entry_point("agent")
        workflow.add_conditional_edges("agent", self.agent_router, ["tools", "error", END])
        workflow.add_edge("error", "agent")
        workflow.add_edge("tools", "agent")

        # set agent properties
        self.ds = ds_ctx(llm, configs)
        self.current_iteration = 0
        self.max_iterations = int(configs['max_questions'])
        self.max_tokens = int(configs['max_tokens'])
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = llm
        self.model = llm.bind_tools(tools)

    def call_error(self, state: MessagesState):
        return {"messages": [HumanMessage(content="Error: Invalid tool call format.")]}
    
    def agent_router(self, state: MessagesState):
        """Decides whether to call the model or the tools based on the last message."""
        messages = state["messages"]
        last_message = messages[-1]
        if type(last_message) == AIMessage:
            if last_message.tool_calls:
                if self.current_iteration > self.max_iterations:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return END
                return "tools"
            elif '<tool_call>' in last_message.content or '</tool_call>' in last_message.content:
                if self.current_iteration > self.max_iterations:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return END
                return "error"
        return END

    def call_tool(self, state: MessagesState):
        tool_calls = state['messages'][-1].tool_calls
        results = []
        for t in tool_calls:
            if t['name'] not in self.tools:      # check for bad tool name from LLM
                print(f"{__name__}: Received bad tool name from model {t['name']}")
                result = "bad tool name, retry"  # instruct LLM to retry if bad
            else:
                args = t['args'].copy()
                args['ds'] = self.ds
                result = self.tools[t['name']].invoke(args)
                self.current_iteration += 1
                #result = "Dummy Results for evaluation only"
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
        return {'messages': results}
    
    def call_model(self, state: MessagesState):

        messages = state["messages"]
        if self.current_iteration > self.max_iterations:
            messages += [HumanMessage(content="We have to conclude this investigation, summarize your findings.")]
            response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]} # returning empty should end the conversation
        
        response = self.model.invoke(messages, max_tokens=self.max_tokens)
        return {"messages": [response]}


def investigate_attack(llm: BaseChatModel, configs: dict, lead: str) -> str:
    
    graph_cfg = {'recursion_limit': 125}
    lead_msg = HumanMessage(content=get_prompt_investigation_agent(
        environment=configs['environment'], 
        max_questions=configs['max_questions'], 
        lead=lead))

    attack = InvestigateAgent(llm, configs)
    response = attack.graph.invoke({"messages": lead_msg}, config=graph_cfg)
    return response["messages"][-1].content
