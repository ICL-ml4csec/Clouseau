from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs.chat_generation import ChatGeneration
from langchain_core.messages import AIMessage, BaseMessage

def print_message(msg: BaseMessage):
    if isinstance(msg, AIMessage):
        role = "AI"
        print(f"{role}: \n{msg.content}")
        if msg.tool_calls:
            for call in msg.tool_calls:
                print(f"Tool Call: {call['name']}", flush=True)
                for arg_key, arg_val in call['args'].items():
                    print(f"{arg_key}: {arg_val}", flush=True)
    else:
        role = "Human"
        print(f"{role}: \n{msg.content}")
    

# Custom callback handler for streaming tokens & events
class SimpleCallback(BaseCallbackHandler):
    def on_llm_end(self, response, **kwargs):
        for r in response:
            for g in r:
                if isinstance(g, list):
                    for i in g:
                        for m in i:
                            if isinstance(m, ChatGeneration):
                                print_message(m.message)
        print("="*40, flush=True)