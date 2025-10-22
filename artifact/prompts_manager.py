from typing import Any, Dict
import prompts

def get_prompt(prompt_name : str, configs: Dict[str, Any] = {}) -> str:
    v = ""
    if prompt_name == 'Investigation_agent':
        v = prompts.investigation_agent
    elif prompt_name == 'ablation_agent':
        v = prompts.ablation_agent
    elif prompt_name == 'SQLExpert_agent':
        v = prompts.sqlexpert_agent
    elif prompt_name == 'Evaluate':
        v = prompts.eval_agent
    elif prompt_name == 'ChiefInspector_agent':
        v = prompts.chief_inspector_agent
    else:
        return None

    if configs:
        return v.format(**configs)
    else:
        return v

    
def get_prompt_investigation_agent(environment: str, max_questions: int, lead: str) -> str:
    return get_prompt('Investigation_agent', {'environment': environment, 'max_questions': max_questions, 'initial_message': lead})

def get_prompt_ablation_agent(environment: str, schema: str, examples: str, max_queries: int, lead: str) -> str:
    return get_prompt('ablation_agent', {'environment': environment, 'schema': schema, 'examples': examples, 'max_queries': max_queries, 'initial_message': lead})

def get_prompt_sqlexpert(schema: str, examples: str, max_queries: int, question: str) -> str:
    return get_prompt("SQLExpert_agent", {'schema': schema, 'examples': examples, 'max_queries': max_queries, 'question': question})

def get_prompt_evaluation() -> str:
    return get_prompt("Evaluate")

def get_prompt_chief_inspector(environment: str, max_investigations: int, initial_message: str) -> str:
    return get_prompt("ChiefInspector_agent", {'environment': environment, 'max_investigations': max_investigations, 'initial_message': initial_message})

