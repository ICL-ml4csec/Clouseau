from langgraph.graph import StateGraph, MessagesState, END
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.language_models import BaseChatModel
from typing import Annotated
from src.investigation_context import InvestigationContext
import sqlite3

# TODO: Move question out of the prompt and as a user message
SQL_EXPERT_PROMPT = """
You are an SQL expert assigned to answer questions related to security incidents by querying an SQLite database. Break down the task into multiple simple SQLite queries instead of one complex query. Use only the provided tables and columns. Analyze the query results and provide a clear, concise answer based on the retrieved data. If the data is insufficient or the question cannot be answered, clearly explain why.

**Schema:**  
{schema}

**Table Information:**  
{table_hint}

Reply with a tool call or your final answer to the question. You will are allowed to preform {max_queries} queries. Although you will be given specific question to answer, you have to report any abnormal behavior you find within the data, even if it is not related to the question.

Question: {question}
"""

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
def run_sql_query(ctx: Annotated[InvestigationContext, InjectedToolArg], query: str) -> str:
    """execute sql query against sqlite database and returns the results. An error is returned if the query is invalid.
    
    Args:
        query: the sql query to execute.
    
    Returns:
        str: the results of the query.
    """
    ctx.add_tool_call("run_sql_query", query)
    #print(f"Received Query: {query}")
    with sqlite3.connect(ctx.db_name) as cnn: 
        cursor = cnn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        if len(rows) == 0:
            return "No results found."
        rows_str = '\n'.join(['\t'.join(map(str, row)) for row in rows])
        if len(rows_str) > ctx.query_return_max_size:
            return (
                f"Query returned too many results ({len(rows)} records with a total of {len(rows_str)} charcaters)."
                " Please refine the query, consider using `GROUP BY`, `DISTINCT` or elminating some of the columns you request."
                " If you are selecting time column, consider using `DISTINCT` without the time column."
            )
        return rows_str


class SQLAgent:
    def __init__(self, invtg_ctx: InvestigationContext):
        
        # define tools
        tools = [run_sql_query]

        workflow = StateGraph(MessagesState)
        workflow.add_node("agent", self.call_model)
        workflow.add_node("tools", self.call_tool)
        workflow.set_entry_point("agent")
        workflow.add_edge("tools", "agent")
        workflow.add_conditional_edges("agent", self.agent_router, ["tools", END])

        # set agent properties
        self.current_iteration = 0
        self.ctx = invtg_ctx
        self.max = self.ctx.max_queries
        self.max_tokens = self.ctx.invocation_max_size
        self.query_return_max_size = self.ctx.query_return_max_size
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = self.ctx.llm
        self.model = self.model_no_tools.bind_tools(tools)

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
                print(f"{__name__}: {self.ctx.db_name} Received bad tool name from model {t['name']}")
                result = "bad tool name, retry"  # instruct LLM to retry if bad
            else:
                args = t['args'].copy()
                args['ctx'] = self.ctx
                result = self.tools[t['name']].invoke(args)
                self.current_iteration += 1
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
            #break # only one tool call is allowed
        
        if len(tool_calls) > 1:
            print(f"{__name__}: {self.ctx.db_name} Received more than one tool call from model")
            results.append(HumanMessage(content="Error: Only one tool call at a time is allowed."))
        
        return {'messages': results}
    
    def call_model(self, state: MessagesState):
        
        if self.current_iteration > self.max:
            messages = state["messages"] + [HumanMessage(content="Lets try to answer the question with the information we have. As we have reached the maximum number of iterations.")]
            response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]}
        
        messages = state["messages"]
        response = self.model.invoke(messages, max_tokens=self.max_tokens)
        #response = self.model.invoke(messages)
        return {"messages": [response]}
    
def run_agent(ctx: InvestigationContext, table_name: str, table_hint: str, question: str):
    
    prompt = SQL_EXPERT_PROMPT.format(
        schema=get_table_schema(ctx.db_name, table_name), 
        table_hint=table_hint, 
        max_queries=ctx.max_queries, 
        question=question)
    messages = [HumanMessage(content=prompt)]
    abot = SQLAgent(ctx)
    final_result = ''

    try:
        result = abot.graph.invoke({"messages": messages}, config={'recursion_limit': 125})
        final_result = f"{result['messages'][-1].content}"
    except Exception as e:
        final_result = f"We had a problem understanding the question. Please try again. \n{e}"
    
    #print(f'Question Answer: {final_result}\n--------')
    return final_result


if __name__ == "__main__":

    from llm_manager import get_gpt41_mini, get_deepseekv3
    from context_manager import ContextManager

    llm = get_gpt41_mini()
    cm = ContextManager('scenarios/scenarios_context.json')
    ctx = InvestigationContext(llm, cm, None, 'scenarios/SS1/scenario.db', "", 2, 2, 2)
    answer = run_agent(ctx, "audit_logs", str(cm.get_table_hint("audit_logs")), "Give me a breakdown of all network connections made by firefox processes, including all of its descendants")
    print(answer)

    