from langchain_openai import ChatOpenAI
from chief_inspector import investigate_atlas, investigate_optc
from ablation_agent import ablation_atlas, ablation_optc
from evaluation import evaluate_report
from datetime import datetime
from typing import List, Dict
import pandas as pd
import constants
import prompts
import argparse
import os

si_scn = [
    {'name': 's1', 'path': 'scenarios/S1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 's2', 'path': 'scenarios/S2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 's3', 'path': 'scenarios/S3/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 's4', 'path': 'scenarios/S4/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]}
]

ml_scn = [
    {'name': 'm1h1', 'path': 'scenarios/M1/h1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'm1h2', 'path': 'scenarios/M1/h2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'm2h1', 'path': 'scenarios/M2/h1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]},
    {'name': 'm2h2', 'path': 'scenarios/M2/h2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]},
    {'name': 'm3h1', 'path': 'scenarios/M3/h1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]},
    {'name': 'm3h2', 'path': 'scenarios/M3/h2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]},
    {'name': 'm4h1', 'path': 'scenarios/M4/h1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'm4h2', 'path': 'scenarios/M4/h2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'm5h1', 'path': 'scenarios/M5/h1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]},
    {'name': 'm5h2', 'path': 'scenarios/M5/h2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]},
    {'name': 'm6h1', 'path': 'scenarios/M6/h1/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'm6h2', 'path': 'scenarios/M6/h2/', 'poi': [(prompts.atlas_init_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]}
]

se_scn = [
    {'name': 'se1', 'path': 'scenarios/SE1/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'se2', 'path': 'scenarios/SE2/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'se3', 'path': 'scenarios/SE3/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file, 'file')]},
    {'name': 'se4', 'path': 'scenarios/SE4/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_domain, 'domain'), (prompts.atlas_init_file_py, 'file')]}
]

ss_scn = [{'name': 'ss1', 'path': 'scenarios/SS1/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_sb_domain, 'domain'), (prompts.atlas_init_sb_file, 'file')]},
    {'name': 'ss2', 'path': 'scenarios/SS2/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_sb_domain, 'domain'), (prompts.atlas_init_sb_file, 'file')]},
    {'name': 'ss3', 'path': 'scenarios/SS3/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_sb_domain, 'domain'), (prompts.atlas_init_sb_file, 'file')]},
    {'name': 'ss4', 'path': 'scenarios/SS4/', 'poi': [(prompts.atlas_init_s_ip, 'IP'), (prompts.atlas_init_sb_domain, 'domain'), (prompts.atlas_init_sb_file_py, 'file')]}
]

optc_scn = [
    {'name': 'optc1', 'path': 'scenarios/OPT1/', 'poi': [(prompts.opt1_c1, 'C1'), (prompts.opt1_c2,'C2'), (prompts.opt1_c3, 'C3')]},
    {'name': 'optc2', 'path': 'scenarios/OPT2/', 'poi': [(prompts.opt2_c1, 'C1'), (prompts.opt2_c3, 'C2'), (prompts.opt2_c2, 'C3')]},
    {'name': 'optc3', 'path': 'scenarios/OPT3/', 'poi': [(prompts.opt3_c1, 'C1'), (prompts.opt3_c2, 'C2'), (prompts.opt3_c3, 'C3')]}
]


def save_to_csv(df: pd.DataFrame, results_file: str):
    # save the results to a csv file
    # put headers if it is the first time
    # append to the file, do not overwrite
    if not os.path.exists(results_file):
        df.to_csv(results_file, index=False, header=True)
    else:
        df.to_csv(results_file, index=False, header=False, mode='a')

def run_scenarios(scns: List, llm: ChatOpenAI, configs: Dict, ablation: bool, darpa: bool, csv_file: str):
    for i in scns:
        print(f"Investigating {i['name']}")
        cfg = configs.copy()
        cfg['data_path'] = i['path']
        cfg['db_name'] = os.path.join(i['path'], 'scenario.db')
        for p in i['poi']:
            print(f"  Clue: {p[1]}")
            cfg['clue'] = p[0]
            cfg['test_name'] = f"{i['name']}_{p[1]}"

            results = None
            if ablation:
                if darpa:
                    results = ablation_optc(llm=llm, configs=cfg)
                else:
                    results = ablation_atlas(llm=llm, configs=cfg)
            else:
                if darpa:
                    results = investigate_optc(llm=llm, configs=cfg)
                else:
                    results = investigate_atlas(llm=llm, configs=cfg)
            er = evaluate_report(cfg, results)
            save_to_csv(er.get_pd(), csv_file)

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Attack investigation tool backed by LLMs')
    parser.add_argument('--max-investigations', type=int, help='Maximum number of questions to ask for the investigator')
    parser.add_argument('--max-questions', type=int, help='Maximum number of questions to ask for the investigator')
    parser.add_argument('--max-queries', type=int, help='Maximum number of SQL queries to run')
    parser.add_argument('--ablation-agent', action='store_true', help='Run ablation agent instead of Clouseau')
    parser.add_argument('--scenarios-si', action='store_true', help='Run ATLAS scenarios S1-S4')
    parser.add_argument('--scenarios-ml', action='store_true', help='Run ATLAS scenarios M1-M6')
    parser.add_argument('--scenarios-se', action='store_true', help='Run ATLAS scenarios SE1-SE4')
    parser.add_argument('--scenarios-ss', action='store_true', help='Run ATLAS scenarios SS1-SS4')
    parser.add_argument('--scenarios-optc', action='store_true', help='Run generlizability scenarios OPTC1-OPTC3')
    parser.add_argument('--no-warn', action='store_true', help='Suppress warnings about tracing not being set up')
    parser.add_argument('--csv-file', type=str, help='csv file to store evaluation results') # where to store numeric results
    args = parser.parse_args()

    # get system configs first
    ablation_agent = False
    scenarios_si = False
    scenarios_ml = False
    scenarios_se = False
    scenarios_ss = False
    scenarios_optc = False
    no_warn = False
    current_time = datetime.now().strftime('%Y-%m-%d-%H')
    configs = {}
    configs['max_investigations'] = args.max_investigations if args.max_investigations else constants.DEFAULT_INVESTIGATIONS
    configs['max_questions'] = args.max_questions if args.max_questions else constants.DEFAULT_QUESTIONS
    configs['max_queries'] = args.max_queries if args.max_queries else constants.DEFAULT_QUERIES
    configs['max_tokens'] = constants.DEFAULT_MAX_TOKENS
    csv_file = args.csv_file if args.csv_file else f"results_{current_time}.csv"

    if args.ablation_agent:
        ablation_agent = True
        configs['max_queries'] = args.max_queries if args.max_queries else constants.DEFAULT_QUERIES_ABLATION

    if args.scenarios_si:
        scenarios_si = True
    if args.scenarios_ml:
        scenarios_ml = True
    if args.scenarios_se:
        scenarios_se = True
    if args.scenarios_ss:
        scenarios_ss = True
    if args.scenarios_optc:
        scenarios_optc = True
    if args.no_warn:
        no_warn = True

    if not (scenarios_si or scenarios_ml or scenarios_se or scenarios_optc or scenarios_ss):
        print("No scenarios selected. Use --scenarios-si, --scenarios-ml, --scenarios-se, --scenarios-ss, or --scenarios-optc to select scenarios.")
        exit(1)
    

    # get LLM
    model = os.environ.get('LLM_MODEL', None)
    api_key = os.environ.get('API_KEY', None)
    base_url = os.environ.get('BASE_URL', None)

    if model is None or api_key is None:
        print("LLM_MODEL and API_KEY environment variables must be set")
        exit(1)

    if base_url is not None:
        print("Using custom base URL:", base_url)
    
    llm = None
    if base_url is not None:
        llm = ChatOpenAI(model=model, temperature=0, api_key=api_key, base_url=base_url)
    else:
        llm = ChatOpenAI(model=model, temperature=0, api_key=api_key)

    print("Using model:", model)
    print('saving results to:', csv_file)
    print("This may take a while...")

    if not no_warn:
        print("Make sure you have enough quota in your provider account.")

        if os.environ.get('LANGSMITH_TRACING', None) is None:
            print("Make sure tracing is set up using LangSmith or another provider.")
            print("It is super easy to set up: https://docs.langchain.com/langsmith/observability-quickstart")

        # confirm user wants to proceed
        proceed = input("Do you want to proceed? (y/n): ")
        if proceed.lower() != 'y':
            print("Exiting...")
            exit(0)

    if scenarios_si:
        print("Running ATLAS SI scenarios")
        run_scenarios(si_scn, llm, configs, ablation_agent, False, csv_file)
    
    if scenarios_ml:
        print("Running ATLAS ML scenarios")
        run_scenarios(ml_scn, llm, configs, ablation_agent, False, csv_file)
    
    if scenarios_se:
        print("Running ATLAS SE scenarios")
        run_scenarios(se_scn, llm, configs, ablation_agent, False, csv_file)
    
    if scenarios_ss:
        print("Running ATLAS SS scenarios")
        run_scenarios(ss_scn, llm, configs, ablation_agent, False, csv_file)
    
    if scenarios_optc:
        print("Running OPTC scenarios")
        run_scenarios(optc_scn, llm, configs, ablation_agent, True, csv_file)

    print("Done")
    exit(0)

