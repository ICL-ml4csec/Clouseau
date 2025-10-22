# Clouseau: Hierarchical Multi-Agent Attack Investigation System

Clouseau is a hierarchical multi-agent system for iterative cyber attack investigation. Starting from a point of interest (e.g., a suspicious domain), it autonomously explores incident data sources, issues targeted queries, analyzes evidence, and incrementally reconstructs an attack narrative. Clouseau does not require any training or predefined heuristics; instead, it leverages LLMs' understanding of systems and security and their capabilities to correlate and reason about the incident data.

## Repository High-Level Structure

- `artifact` — source code for Clouseau, including prompts and processed scenarios for testing.
- `claims` — instructions and scripts to reproduce paper's main claims.

## Installation

Create a virtual environment first with conda or any other alternatives. We tested this with Python 3.12.11.

```bash
pip install -r artifact/requirements.txt
```

## Reproduction Notes
You will need an OpenAI key to reproduce the results, please set `API_KEY` properly before running any script.

### Claim 1: Single Host Scenarios
A run of clouseau to reproduce results for Single Host scenarios (Section 6.1). Run:

```bash
./claims/claim1/run.sh
```

Then inspect `claims/claim1/average.csv`, recall, precision and f1 should above 95%.


### Claim 2: Single Host Extended Scenarios
A run of clouseau to reproduce results for Single Host Extended scenarios (Section 6.1). Run:

```bash
./claims/claim2/run.sh
```

Then inspect `claims/claim2/average.csv`, recall, precision and f1 should above 95%.


### Claim 3: Keyword Sensitivity Scenarios
A run of clouseau to reproduce results for Keyword Sensitivity scenarios (Section 6.2). Run:

```bash
./claims/claim3/run.sh
```

Then inspect `claims/claim3/average.csv`, recall, precision and f1 should above 95%.

### Other Experiments and Claims
Want to go beyond the paper claims? Use the CLI to explore, tweak, and run targeted experiments:

```bash
cd artifact
python app.py --help
```

This shows how to:
- switch the underlying LLM model.
- enable single‑agent mode.
- evaluate on OpTC datasets.

To run single exeperiments, you can utilize the notebook `artifact/clouseau.ipynb`.