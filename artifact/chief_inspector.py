from investigator import investigate_attack
from prompts_manager import get_prompt_chief_inspector, get_prompt_evaluation
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.callbacks import UsageMetadataCallbackHandler
from langgraph.graph import StateGraph, MessagesState
from datetime import datetime
from typing import Annotated
import constants
import prompts
import os
        
class investigate_ctx(dict):
    def __init__(self, llm: BaseChatModel, configs: dict):
        self.llm = llm
        self.configs = configs
        dict.__init__(self, self.configs)

@tool(parse_docstring=True)
def investigate_lead(ctx: Annotated[investigate_ctx, InjectedToolArg], lead: str) -> str:
    """Initiates an investigation based on the given lead, returns a summary of the investigation. Lead message should be consice and to the point and does not exceed 3 sentences.
    
    Examples: 
        lead="We found a suspicious connections to 138.98.11.83, identify any processes that communicated with this IP and inspect their execution tree and spawned processes. Identify any domain associated with this address. Report any unusual behavior or processes that may be related to this IP address."
        lead="Investigate the domain name malicious.xyz, find any processes who connected to this address, construct execution tree, and investigate these processes. Find any executables or script that may have been downdloaded around that time, inspect any frequent or unordinary connections around the time."
        lead="Investigate a process 'malicious.exe' running on the system. Construct execution tree and find all network connections or files associated with it. Look for any abnormal behavior around the time of execution of this process."
        lead="document.doc was downloaded from malicious sources around 1 PM. Check the logs for any abnormal behavior related to this file. Identify any processes that may have been exploited in the process of interacting with the file. Check for any abnormal network connections, process execution or file modifications around the time."
        lead="firefox.exe visited malicious site evil.com at 1 PM, investigate the browser activity afterward to determine the effect of this visit. Check for any malicious downloads, file modifications or executions around the visit time, check firefox.exe process tree to find any abnormal processes. Investigate any frequent connections made around the time of this malicious behavior."
        lead="Investigate malicious process 'malware.exe' with PID of 1234. It is clear this process has made contact with a C2 server at 138.98.11.83. We need to identify its subsequent actions after this, that is related to this attack. Check for any network connections, file modifications, or process creations made by this process or its associated processes, or around their time of execution."
        lead="Find all execution instances of malware.exe, then check their execution tree for any parent processes that may have spawned it. Check the process tree for any other processes that may have been spawned by malware.exe. inspect network connections made, find any frequent or abnormal network connections."
    
    Args:
        lead: investigation lead.

    Returns:
        str: a summary of the investigation.
    """
    return investigate_attack(ctx.llm, ctx.configs, lead)

class Clouseau:
    def __init__(self, model: BaseChatModel, configs: dict):
        # define tools
        tools = [investigate_lead]

        # define the workflow
        workflow = StateGraph(MessagesState)
        workflow.add_node("agent", self.call_model)
        workflow.add_node("tools", self.call_tool)
        workflow.add_node("eval", self.call_eval)
        workflow.add_node("error", self.call_error)
        workflow.set_entry_point("agent")
        workflow.set_finish_point("eval")
        workflow.add_conditional_edges("agent", self.agent_router, ["tools", "error", "eval"])
        workflow.add_edge("error", "agent")
        workflow.add_edge("tools", "agent")

        # set agent properties
        self.ctx = investigate_ctx(llm=model, configs=configs)
        self.current_iteration = 0
        self.max_iterations = configs['max_investigations']
        self.max_tokens = configs['max_tokens']
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = model
        self.configs = configs.copy()
        self.model = model.bind_tools(tools)

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
                    return "eval"
                return "tools"
            elif '<tool_call>' in last_message.content or '</tool_call>' in last_message.content:
                if self.current_iteration > self.max_iterations:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return "eval"
                return "error"
        return "eval"

    def call_tool(self, state: MessagesState):
        tool_calls = state['messages'][-1].tool_calls
        results = []
        for t in tool_calls:
            if t['name'] not in self.tools:      # check for bad tool name from LLM
                print(f"{__name__}: Received bad tool name from model {t['name']}")
                result = "bad tool name, retry"  # instruct LLM to retry if bad
            else:
                args = t['args'].copy()
                args['ctx'] = self.ctx
                result = self.tools[t['name']].invoke(args)
                self.current_iteration += 1
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
        return {'messages': results}
    
    def is_tool_call(self, message: AIMessage) -> bool:
        if type(message) != AIMessage:
            return False
        
        if message.tool_calls:
            return True
        return False

    def call_model(self, state: MessagesState):

        messages = state['messages']
        if self.current_iteration > self.max_iterations:
            messages += [HumanMessage(content="Summarize your findings, compile the final report, and ensure that all attack artifacts are clearly identified by their PIDs.")]
            response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]}
        else:
            response = self.model.invoke(messages, max_tokens=self.max_tokens)
            if self.current_iteration < constants.DEFAULT_INVESTIGATION_MIN: 
                #make sure the investigation is thorough, if the agent quits early we need to push it do more
                if not self.is_tool_call(response):
                    # not a tool call, the agent is quitting, push them a bit farther
                    warning = HumanMessage(content="This is an automated message, I have not received a tool call from you, meaning you believe you have exhausted all of your options. Take a moment to think before continuing. Reply with a tool call if you want to continue the investigation. otherwise we will proceed to the evaluation phase.")
                    tmp = messages.copy()
                    tmp.append(response)
                    tmp.append(warning)
                    f_response = self.model.invoke(tmp, max_tokens=self.max_tokens)
                    if not self.is_tool_call(f_response):
                        # not a tool call, the agent is quitting, return the initial f_response and print a warning
                        print(f"{__name__}: Agent is quitting without a tool call, returning initial response.")
                        #response.pretty_print()
                        #f_response.pretty_print()
                        
                        return {"messages": [response]}
                    messages += [response, warning]
                    return {"messages": [f_response]}
            return {"messages": [response]}
    
    def call_eval(self, state: MessagesState):
        eval_prompt = get_prompt_evaluation()
        messages = state["messages"] + [HumanMessage(content=eval_prompt)]
        response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
        return {"messages": [response]}


def ClouseauRun(llm: BaseChatModel, configs: dict) -> str:
 
    graph_cfg = {'recursion_limit': 125}
    chief_prompt = HumanMessage(content=get_prompt_chief_inspector(
        configs['environment'], 
        configs['max_investigations'], 
        configs['clue']
        )
    )

    agent = Clouseau(llm, configs)
    response = agent.graph.invoke({"messages": chief_prompt}, config=graph_cfg)
    return response["messages"][-1].content
    

def investigate_optc(llm: BaseChatModel, configs: dict = {}):
    """Investigate a clue using the OPTC database."""
    
    configs['environment'] = prompts.opt_env_context
    configs['is_darpa'] = True
    return ClouseauRun(llm=llm, configs=configs)
    

def investigate_atlas(llm: BaseChatModel, configs: dict = {}):
    """Investigate a clue using the ATLAS database."""
    
    configs['environment'] = prompts.atlas_env_context
    configs['is_darpa'] = False
    return ClouseauRun(llm=llm, configs=configs)