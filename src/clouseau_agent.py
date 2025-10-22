from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.callbacks import UsageMetadataCallbackHandler
from langgraph.graph import StateGraph, MessagesState, END
from typing import Annotated
from src.context_manager import ContextManager
from src.investigator_agent import investigate_attack
from src.investigation_context import InvestigationContext
from src.display_manager import DisplayManager, create_display_manager

# TODO: Rephrase the prompt to be more alert triaging focused and to determine if an attack is ongoing or not.
# TODO: While still incentivizing the agent to find all attack artifacts
CLOUSEAU_AGENT_PROMPT = """
You are a cybersecurity expert tasked with analyzing a security incident on a single compromised machine. Your goal is to clearly identify the attack source, establish a timeline of attack events, attack objectives, and mapping the attack to the cyber kill chain. You will receive a message from monitoring team as a starting lead, environment context, and given access to the compromised machine logs. Your analysis must clearly list attack artifacts such as process names and their PIDs, Files involved, Network addresses (IPs) and attacker-controlled domains.

Instructions:
* This is an iterative process, with each investigation you will find new artifacts and leads, investigate each one thoroughly, leave no stone unturned.
* Be aggressive in your investigation, do not stop until you have inspected all attack artifacts you found and have exhausted all possible leads.
* You will be allowed to conduct a maximum of {max_investigations} investigations, you will be prompted to stop when we hit this limit.
* At the end, reflect on ALL the reports you received from your investigators and produce a final report.
* Your final report should include all details of the attack you found, including the starting point, attack vector, timeline, and objectives. 
* Your final report will be evaluated based on accuracy, clarity, and correctness of identification of attack artifacts.
* For attack related processes, include their PIDs in the final report.
* When reporting domains, include IP addresses associated with them.
* Think and reflect on each report you receive, and then decide what to do next.
* IMPORTANT: Use timeline tools to keep track of important events and findings during your investigation. Make sure to do this after each investigation.

{environment}

Message from SOC: 
{initial_message}
"""

@tool(parse_docstring=True)
def add_timeline_entry(ctx: Annotated[InvestigationContext, InjectedToolArg], timestamp: str, event_type: str, description: str, evidence: str = "", confidence: str = "medium") -> str:
    """Adds a new entry to the attack timeline.
    
    Args:
        timestamp: The timestamp of the event in the format of YYYY-MM-DD HH:MM:SS (e.g., "2024-01-15 14:30:00")
        event_type: The type of event, not strictly defined, but should be a short description of what happened (e.g., "Network Connection", "Process Execution", "File Download")
        description: A one sentence detailed description of what happened.
        evidence: Supporting evidence or artifacts found (e.g., "PID 1234", "IP 192.168.1.100", "file.exe")
        confidence: Confidence level in this finding (LOW, MEDIUM, HIGH)
    
    Returns:
        str: Confirmation message with the entry ID
    """
    return ctx.add_timeline_entry(timestamp, event_type, description, evidence, confidence)

@tool(parse_docstring=True)
def delete_timeline_entry(ctx: Annotated[InvestigationContext, InjectedToolArg], entry_id: str) -> str:
    """Deletes a timeline entry by its ID.
    
    Args:
        entry_id: The ID of the entry to delete
    
    Returns:
        str: Confirmation message or error if entry not found
    """
    return ctx.delete_timeline_entry(entry_id)

@tool(parse_docstring=True)
def get_timeline(ctx: Annotated[InvestigationContext, InjectedToolArg]) -> str:
    """Returns the current timeline of events.

    Args:
        None
    
    Returns:
        str: The current timeline of events sorted by timestamp
    """
    return ctx.timeline_to_str()

@tool(parse_docstring=True)
def investigate_lead(ctx: Annotated[InvestigationContext, InjectedToolArg], lead: str, objective: str) -> str:
    """Initiates an investigation based on the given lead, returns a summary of the investigation. Lead message should be consice and to the point and does not exceed 3 sentences. Objective is a short description of the goal of the investigation, this is used as a status update to the user.
    
    Examples: 
        lead="We found a suspicious connections to 138.98.11.83, identify any processes that communicated with this IP and inspect their execution tree and spawned processes. Identify any domain associated with this address. Report any unusual behavior or processes that may be related to this IP address.", objective="Investigating network connections to 138.98.11.83"
        lead="Investigate the domain name malicious.xyz, find any processes who connected to this address, construct execution tree, and investigate these processes. Find any executables or script that may have been downdloaded around that time, inspect any frequent or unordinary connections around the time.", objective="Investigating domain name malicious.xyz"
        lead="Investigate a process 'malicious.exe' running on the system. Construct execution tree and find all network connections or files associated with it. Look for any abnormal behavior around the time of execution of this process.", objective="Investigating process 'malicious.exe'"
        lead="document.doc was downloaded from malicious sources around 1 PM. Check the logs for any abnormal behavior related to this file. Identify any processes that may have been exploited in the process of interacting with the file. Check for any abnormal network connections, process execution or file modifications around the time.", objective="Investigating file 'document.doc'"
        lead="firefox.exe visited malicious site evil.com at 1 PM, investigate the browser activity afterward to determine the effect of this visit. Check for any malicious downloads, file modifications or executions around the visit time, check firefox.exe process tree to find any abnormal processes. Investigate any frequent connections made around the time of this malicious behavior.", objective="Investigating activity of firefox.exe and its relation to evil.com"
        lead="Investigate malicious process 'malware.exe' with PID of 1234. It is clear this process has made contact with a C2 server at 138.98.11.83. We need to identify its subsequent actions after this, that is related to this attack. Check for any network connections, file modifications, or process creations made by this process or its associated processes, or around their time of execution.", objective="Investigating malware.exe and its relation to C2 server 138.98.11.83"
        lead="Find all execution instances of malware.exe, then check their execution tree for any parent processes that may have spawned it. Check the process tree for any other processes that may have been spawned by malware.exe. inspect network connections made, find any frequent or abnormal network connections.", objective="Investigating all execution instances of malware.exe"
    
    Args:
        lead: investigation lead.
        objective: a short description of the goal of the investigation.

    Returns:
        str: a summary of the investigation.
    """
    ctx.increment_iteration()
    ctx.add_tool_call("investigate_lead", lead)
    ctx.set_investigation(objective)
    return investigate_attack(ctx, lead)
    
class Clouseau:
    def __init__(self, model: BaseChatModel, ctx: InvestigationContext, max_investigations: int):
        # define tools
        tools = [investigate_lead, add_timeline_entry, delete_timeline_entry, get_timeline]

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
        self.ctx = ctx
        self.max = max_investigations
        self.max_tokens = self.ctx.invocation_max_size
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = model
        self.model = model.bind_tools(tools)

    def call_error(self, state: MessagesState):
        return {"messages": [HumanMessage(content="Error: Invalid tool call format.")]}
    
    def agent_router(self, state: MessagesState):
        """Decides whether to call the model or the tools based on the last message."""
        messages = state["messages"]
        last_message = messages[-1]
        if type(last_message) == AIMessage:
            if last_message.tool_calls:
                if self.ctx.get_current_iteration() > self.max:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return END
                return "tools"
            elif '<tool_call>' in last_message.content or '</tool_call>' in last_message.content:
                if self.ctx.get_current_iteration() > self.max:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return END
                return "error"
        return END

    def call_tool(self, state: MessagesState):
        last_message = state['messages'][-1]
        if type(last_message) != AIMessage:
            return self.call_error(state)
        
        tool_calls = last_message.tool_calls
        results = []
        for t in tool_calls:
            if t['name'] not in self.tools:      # check for bad tool name from LLM
                print(f"{__name__}: Received bad tool name from model {t['name']}")
                result = "bad tool name, retry"  # instruct LLM to retry if bad
            else:
                args = t['args'].copy()
                args['ctx'] = self.ctx
                result = self.tools[t['name']].invoke(args)
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
        return {'messages': results}
    
    def is_tool_call(self, message) -> bool:
        if type(message) != AIMessage:
            return False
        
        if message.tool_calls:
            return True
        return False

    def produce_final_report(self, state: MessagesState):
        messages = state['messages']
        task = "Write a detailed report of your findings, ensure that all attack artifacts are clearly identified by their PIDs."
        if self.ctx.get_timeline() is not None:
            task += "\n\nIMPORTANT: Include the following timeline of events in your final report:\n"
            task += self.ctx.timeline_to_str()
        
        messages += [HumanMessage(content=task)]
        response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
        return {"messages": [response]}

    def warn_agent(self, state: MessagesState):
        messages = state['messages']
        warning = HumanMessage(content="This is an automated message, I have not received a tool call from you, meaning you believe you have exhausted all of your options. Take a moment to think before continuing. Reply with a tool call if you want to continue the investigation. Otherwise, you will be prompted to produce the final report.")
        messages += [warning]
        response = self.model.invoke(messages, max_tokens=self.max_tokens)
        if not self.is_tool_call(response):
            return self.produce_final_report(state)
        return {"messages": [response]}

    def call_model(self, state: MessagesState):

        messages = state['messages']
        if self.ctx.get_current_iteration() > self.max:
            return self.produce_final_report(state)

        response = self.model.invoke(messages, max_tokens=self.max_tokens)
        if not self.is_tool_call(response):
            return self.warn_agent(state)
        return {"messages": [response]}

def ClouseauRun(
    llm: BaseChatModel, 
    context_manager: ContextManager, 
    display: DisplayManager | None,
    db_name: str, 
    max_investigations: int, 
    max_questions: int,
    max_queries: int,
    lead: str) -> str:

    usage = UsageMetadataCallbackHandler()    
    ctx = InvestigationContext(llm, context_manager, display, db_name, lead, max_investigations, max_questions, max_queries)
    agent = Clouseau(llm, ctx, max_investigations)
    prompt = CLOUSEAU_AGENT_PROMPT.format(environment=context_manager.get_context_summary(), max_investigations=max_investigations, initial_message=lead)
    chief_prompt = HumanMessage(content=prompt)
    if display is not None:
        display.add_usage_object(usage)
    response = agent.graph.invoke({"messages": chief_prompt}, config={'recursion_limit': 125, 'callbacks': [usage]})
    final_report = response["messages"][-1].content
    
    if display is not None:
        display.update_investigation_message(final_report, 'complete')
    return final_report

if __name__ == "__main__":

    import llm_manager
    llm = llm_manager.get_gpt41_mini()
    display = create_display_manager()

    report = ClouseauRun(llm, ContextManager('scenarios/scenarios_context.json'), display, 'scenarios/SS1/scenario.db', 15, 5, 5, "2024olympics-shop.com")
    print(report)
    