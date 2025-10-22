from langgraph.graph import StateGraph, MessagesState, END
from langchain_core.messages import HumanMessage, ToolMessage, AIMessage
from langchain_core.tools import InjectedToolArg, tool
from langchain_core.language_models import BaseChatModel
from typing import Annotated, Any, List
from src.context_manager import ContextManager
import src.sql_qa_agent as sql_qa_agent
from src.investigation_context import InvestigationContext

INVESTIGATOR_AGENT_PROMPT = """
You are a security expert tasked with conducting a security investigation using provided data sources and analysis tools. These tools act as abstraction layers, allowing you to query log data directly. Your responsibility is to formulate precise and context-rich questions to effectively utilize these tools. Identify attack related artifacts, such as processes names, their PIDs, files, network addresses, and domains used by the attackers. The evaluation of your report will be based on the accuracy and relevance of the identified artifacts. You will be presented with the logs of a single machine.

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

class InvestigatorAgent:
    def __init__(self, invtg_ctx: InvestigationContext, tools: List[Any]):
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
        self.ctx = invtg_ctx
        self.current_iteration = 0
        self.max = self.ctx.max_questions
        self.max_tokens = self.ctx.invocation_max_size
        self.graph = workflow.compile()
        self.tools = {t.name: t for t in tools}
        self.model_no_tools = self.ctx.llm
        self.model = self.model_no_tools.bind_tools(tools)

    def call_error(self, state: MessagesState):
        return {"messages": [HumanMessage(content="Error: Invalid tool call format.")]}
    
    def agent_router(self, state: MessagesState):
        """Decides whether to call the model or the tools based on the last message."""
        messages = state["messages"]
        last_message = messages[-1]
        if type(last_message) == AIMessage:
            if last_message.tool_calls:
                if self.current_iteration > self.max:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return END
                return "tools"
            elif '<tool_call>' in last_message.content or '</tool_call>' in last_message.content:
                if self.current_iteration > self.max:
                    print(f"{__name__}: Reached max iterations, model is not adhering to the workflow")
                    return END
                return "error"
        return END

    def call_tool(self, state: MessagesState):
        last_message = state['messages'][-1]
        if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
            return {'messages': [HumanMessage(content="No tool calls found in the message.")]}
        
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
                self.current_iteration += 1
                #result = "Dummy Results for evaluation only"
            results.append(ToolMessage(tool_call_id=t['id'], name=t['name'], content=str(result)))
        return {'messages': results}
    
    def call_model(self, state: MessagesState):

        messages = state["messages"]
        if self.current_iteration > self.max:
            messages += [HumanMessage(content="We have to conclude this investigation, summarize your findings.")]
            response = self.model_no_tools.invoke(messages, max_tokens=self.max_tokens)
            return {"messages": [response]} # returning empty should end the conversation
        
        response = self.model.invoke(messages, max_tokens=self.max_tokens)
        return {"messages": [response]}



from typing import List, Any, Annotated
from textwrap import dedent

# whatever provides these:
# from your_tools_lib import tool, InjectedToolArg
# from your_module import ds_ctx, sql_qa_agent

def create_dynamic_tools(context_manager: ContextManager) -> List[Any]:
    """Create tools dynamically for each available table in the context."""
    tools: List[Any] = []

    def make_tool(table_name: str, table_summary: str):
        # Define the raw function first so we can set metadata before decorating
        def dynamic_table_tool(
            ctx: Annotated[InvestigationContext, InjectedToolArg],
            question: str
        ) -> str:
            """placeholder; will be replaced below"""
            # body uses captured values (no late-binding issues)
            ctx.add_tool_call(func_name, question)
            return sql_qa_agent.run_agent(
                ctx,
                table_name,
                str(table_summary),
                question,
            )

        # Programmatically set a unique name and docstring
        func_name = f"ask_{table_name}"
        dynamic_table_tool.__name__ = func_name
        dynamic_table_tool.__qualname__ = func_name  # optional
        dynamic_table_tool.__doc__ = dedent(f"""
            This function processes queries about the `{table_name}` table.

            {table_summary}

            Args:
                question: The question to ask about the table data.

            Returns:
                A string containing the answer to the question based on the table data.
        """).strip()

        # Now decorate, so the tool parser sees the final name/docstring
        decorated = tool(parse_docstring=True)(dynamic_table_tool)
        return decorated

    # Build one tool per table
    for table_name in context_manager.get_available_tables():
        table_summary = context_manager.get_table_summary(table_name)
        tools.append(make_tool(table_name, table_summary))

    return tools

def investigate_attack(
    invtg_ctx: InvestigationContext, 
    lead: str) -> str:
    
    tools = create_dynamic_tools(invtg_ctx.context_manager)
    prompt = INVESTIGATOR_AGENT_PROMPT.format(
        environment=invtg_ctx.context_manager.get_context_summary(),
        max_questions=invtg_ctx.max_questions,
        initial_message=lead)
    lead_msg = HumanMessage(content=prompt)
    attack = InvestigatorAgent(invtg_ctx, tools)
    response = attack.graph.invoke({"messages": lead_msg}, config= {'recursion_limit': 125})
    return response["messages"][-1].content


if __name__ == "__main__":
    from llm_manager import get_gpt41_mini, get_deepseekv3
    llm = get_gpt41_mini()

    clue = "we noticed suspicious visits to 2024olympics-shop.com, investigate these visits and report any abnormal behavior found"
    db_name = 'scenarios/SS1/scenario.db'
    max_questions = 10
    max_queries = 10
    context_manager = ContextManager('scenarios/scenarios_context.json')
    invtg_ctx = InvestigationContext(llm, context_manager, None, db_name, "", 2, 2, 2)
    response = investigate_attack(invtg_ctx, clue)
    print(response)