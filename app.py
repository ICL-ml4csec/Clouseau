from src.llm_manager import get_llm, get_llama33, get_deepseekv3, get_gpt41_mini, get_gpt5_nano
from src.clouseau_agent import ClouseauRun
from src.context_manager import ContextManager
from src.display_manager import create_display_manager
from datetime import datetime
import argparse
import os

# default configs
DEFAULT_INVESTIGATIONS_MAX = 5
DEFAULT_QUESTIONS_MAX = 5
DEFAULT_QUERIES_MAX = 5
DEFAULT_QUIET = False
DEFAULT_INTERACTIVE = False
DEFAULT_REPORT_FILE = 'scenarios/report.md'
DEFAULT_DATA_SOURCE = 'scenarios/scenario.db'
DEFAULT_CONTEXT_FILE = 'scenarios/scenarios_context.json'
RECURSION_LIMIT = 125

def get_model_name(llm, model_name=None):
    if model_name is None:
        model_name = 'unknown_model'
        if hasattr(llm, 'model_name'):
            model_name = llm.model_name
    
    forbidden_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in forbidden_chars:
        model_name = model_name.replace(char, '_')
    return model_name

def print_envs():
    print('Environment Variables:')
    for key, value in os.environ.items():
        print(f'{key}={value}')

   
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Attack investigation tool backed by LLMs')
    parser.add_argument('--max-investigations', type=int, help=f'Maximum number of investigation to conduct (default: {DEFAULT_INVESTIGATIONS_MAX})')
    parser.add_argument('--max-questions', type=int, help=f'Maximum number of questions during investigation (default: {DEFAULT_QUESTIONS_MAX})')
    parser.add_argument('--max-queries', type=int, help=f'Maximum number of SQL queries to execute during question answering (default: {DEFAULT_QUERIES_MAX})')
    parser.add_argument('--data-source', type=str, help=f'scenario path (default: {DEFAULT_DATA_SOURCE})')
    parser.add_argument('--attack-clue', type=str, help=f'attack clue to use (default: prompts user to input)')
    parser.add_argument('--context-file', type=str, help=f'path to context file, contains helpful information about the environment, data schema, and any information we know about the attack (default: {DEFAULT_CONTEXT_FILE})')
    parser.add_argument('--report-file', type=str, help=f'path to store investigation report (default: {DEFAULT_REPORT_FILE})')
    parser.add_argument('--quiet', action='store_true', help=f'do not print progress to console (default: {DEFAULT_QUIET})')
    parser.add_argument('--interactive', action='store_true', help=f'prompt user for input after each investigation (default: {DEFAULT_INTERACTIVE})')

    # TODO: add tracing options here, allowing users to connect to open standards for LLM tracing

    args = parser.parse_args()

    # get system configs first
    max_investigations = args.max_investigations if args.max_investigations else DEFAULT_INVESTIGATIONS_MAX
    max_queries = args.max_queries if args.max_queries else DEFAULT_QUERIES_MAX
    max_questions = args.max_questions if args.max_questions else DEFAULT_QUESTIONS_MAX
    db_name = args.data_source if args.data_source else DEFAULT_DATA_SOURCE
    report_file = args.report_file if args.report_file else DEFAULT_REPORT_FILE
    quiet = args.quiet if args.quiet else DEFAULT_QUIET
    interactive = args.interactive if args.interactive else DEFAULT_INTERACTIVE
    context_file = args.context_file if args.context_file else DEFAULT_CONTEXT_FILE
    if args.context_file:
        with open(args.context_file, 'r') as f:
            context_file = f.read()
        
    attack_clue = None
    if args.attack_clue:
        attack_clue = args.attack_clue
    else:
        # read clue from user input
        attack_clue = input('Enter attack clue: ')

    cm = ContextManager(context_file)
    # TODO: Check LLM Manager and initialize llm here
    #llm = get_llm()
    llm = get_gpt41_mini()

    display = None
    if quiet == False:
        display = create_display_manager()
    
    response = ClouseauRun(llm, cm, display, db_name, max_investigations, max_questions, max_queries, attack_clue)

    with open(report_file, 'w') as f:
        f.write(response)
    exit(0)


