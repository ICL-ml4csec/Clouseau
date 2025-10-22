from prompts_manager import get_prompt_ablation_agent, get_prompt_evaluation
from langgraph.graph import StateGraph, MessagesState
from langchain_core.messages import HumanMessage, ToolMessage, AIMessage
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.language_models import BaseChatModel
from langchain_core.callbacks import UsageMetadataCallbackHandler
from typing import Annotated
import sqlite3
import constants
import prompts
import os


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

def get_db_schema(db_name: str, tables: list[str]) -> str:
    """Returns the schema of the database.
    
    Args:
        db_name: the name of the database to get the schema for.
    
    Returns:
        str: the schema of the database.
    """
    schema = f"Database: {db_name}\n\n"
    for t in tables:
        schema += f"{get_table_schema(db_name, t)}\n\n"
    return schema

@tool(parse_docstring=True)
def run_sql_query(db_name: Annotated[str, InjectedToolArg], query: str) -> str:
    """execute sql query against sqlite database and returns the results. An error is returned if the query is invalid.
    
    Args:
        query: the sql query to execute.
    
    Returns:
        str: the results of the query.
    """

    #print(f"Received Query: {query}")

    try:
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
    except Exception as e:
        return f"An error occurred: {e}"


class AblationAgent:
    def __init__(self, llm: BaseChatModel, configs: dict):
        # define tools
        tools = [run_sql_query]

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
        self.configs = configs.copy()
        self.db = configs['db_name']
        self.max_tokens = configs.get('max_tokens', constants.DEFAULT_MAX_TOKENS)
        self.current_iteration = 0
        self.max_iterations = configs.get('max_queries', constants.DEFAULT_QUERIES_ABLATION)
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = llm
        self.model = llm.bind_tools(tools, parallel_tool_calls=False)

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
            self.current_iteration += 1
            if t['name'] not in self.tools:      # check for bad tool name from LLM
                print(f"{__name__}: Received bad tool name from model {t['name']}")
                result = "bad tool name, retry"  # instruct LLM to retry if bad
            else:
                args = t['args'].copy()
                args['db_name'] = self.db
                result = self.tools[t['name']].invoke(args)
                #result = "Dummy Results for evaluation only"
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
        
        return {'messages': results}
    
    def call_model(self, state: MessagesState):
        messages = state['messages']
        if self.current_iteration > self.max_iterations:
            messages += [HumanMessage(content="You have reached the maximum amount of tool calls. Summarize your findings, compile the final report, and ensure that all attack artifacts are clearly identified by their PIDs.")]
            response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]}
        else:
            response = self.model.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]}
    
    def call_eval(self, state: MessagesState):
        eval_prompt = get_prompt_evaluation()
        messages = state["messages"] + [HumanMessage(content=eval_prompt)]
        response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
        return {"messages": [response]}


def investigate_ablation_agent(llm: BaseChatModel, examples_list: list[dict], configs: dict) -> str:

    tables = ['dns_requests', 'audit_logs', 'browser_history']
    if configs.get('is_darpa', False):
        tables = ['dns_logs', 'http_logs', 'file_logs', 'processes_logs', 'flow_logs']
    
    examples = ""
    for eq in examples_list:
        for k, v in eq.items():
            examples += f"{k}\n{v}\n\n"

    graph_cfg = {'recursion_limit': 125}
    clue_msg = HumanMessage(content=get_prompt_ablation_agent(
        configs['environment'], 
        get_db_schema(configs['db_name'], tables), 
        examples, 
        configs['max_queries'],
        configs['clue'])
        )
    
    attack = AblationAgent(llm, configs)
    response = attack.graph.invoke({"messages": clue_msg}, config=graph_cfg)
    return response["messages"][-1].content

def ablation_optc(llm: BaseChatModel, configs: dict = {}):
    """Investigate a clue using the OPTC database."""
    
    configs['environment'] = prompts.opt_env_context
    configs['is_darpa'] = True

    examples = [prompts.darpa_browser_examples_qa,
                prompts.darpa_dns_examples_qa, 
                prompts.darpa_files_examples_qa, 
                prompts.darpa_flow_examples_qa, 
                prompts.darpa_process_examples_qa]
    
    return investigate_ablation_agent(llm=llm, examples_list=examples, configs=configs)
    

def ablation_atlas(llm: BaseChatModel, configs: dict = {}):
    """Investigate a clue using the ATLAS database."""
    
    configs['environment'] = prompts.atlas_env_context
    examples = [prompts.audit_examples_qa, 
                prompts.browser_examples_qa, 
                prompts.dns_examples_qa]
    return investigate_ablation_agent(llm=llm, examples_list=examples, configs=configs)