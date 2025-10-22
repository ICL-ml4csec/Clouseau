from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
import os

def get_llm(base_url = None, api_key = None, model = None, temperature = 0.0, seed = int(0xDEADBEAF), reasoning = None) -> BaseChatModel :
    if base_url is None:
        base_url = os.getenv('LLM_BASE_URL')

    if api_key is None:
        api_key = os.getenv('LLM_API_KEY')
    
    if model is None:
        model = os.getenv('LLM_MODEL')

    print(f"Connecting to {base_url} with model {model}")
    llm = None
    if reasoning is not None:
        llm = ChatOpenAI(base_url=base_url, api_key=api_key, model=model, temperature=temperature, reasoning=reasoning)
    else:
        llm = ChatOpenAI(base_url=base_url, api_key=api_key, model=model, temperature=temperature, seed=seed)
    return llm


def get_gpt5_nano() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'gpt-5-nano'
    reasoning = {
        "effort": "low",  # 'low', 'medium', or 'high'
    }
    return get_llm(base_url=base_url, api_key=api_key, model=model_name, temperature=1.0, reasoning=reasoning)

def get_gpt5_mini() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'gpt-5-mini'
    reasoning = {
        "effort": "low",  # 'low', 'medium', or 'high'
    }
    return get_llm(base_url=base_url, api_key=api_key, model=model_name, temperature=1.0, reasoning=reasoning)

def get_o3_mini() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'o3-mini'
    reasoning = {
        "effort": "low",  # 'low', 'medium', or 'high'
    }
    return get_llm(base_url=base_url, api_key=api_key, model=model_name, temperature=1.0, reasoning=reasoning)


def get_gpt41() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'gpt-4.1'
    return get_llm(base_url=base_url, api_key=api_key, model=model_name)

def get_gpt41_mini() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'gpt-4.1-mini'
    return get_llm(base_url=base_url, api_key=api_key, model=model_name)

def get_gpt41_nano() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'gpt-4.1-nano'
    return get_llm(base_url=base_url, api_key=api_key, model=model_name)

def get_gpt4o() -> BaseChatModel:
    base_url = os.environ['OPENAI_BASE_URL']
    api_key = os.environ['OPENAI_API_KEY']
    model_name = 'gpt-4o'
    return get_llm(base_url=base_url, api_key=api_key, model=model_name)

def get_deepseekv3() -> BaseChatModel:
    base_url = os.environ['DEEPSEEK_BASE_URL']
    api_key = os.environ['DEEPSEEK_API_KEY']
    model_name = 'deepseek-chat'
    return get_llm(base_url=base_url, api_key=api_key, model=model_name)

def get_llama33() -> BaseChatModel:
    base_url = os.environ['DEEPINFRA_BASE_URL']
    api_key = os.environ['DEEPINFRA_API_KEY']
    model_name = 'meta-llama/Llama-3.3-70B-Instruct'
    #model_name = 'meta-llama/Llama-3.3-70B-Instruct-Turbo'
    #model_name = 'openai/gpt-oss-20b'
    return get_llm(base_url=base_url, api_key=api_key, model=model_name)

def get_gemini_2_flash() -> BaseChatModel:
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",
        temperature=0)
    return llm    