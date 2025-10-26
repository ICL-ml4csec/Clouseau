#!/bin/bash

# change directory
# cd ../../ # go to root directory


export LLM_MODEL="gpt-4.1-mini"

cd artifact

echo "[INFO] Running the claim1 scenario..."
python app.py --scenarios-si --csv-file ../claims/claim1/scenarios.csv --no-warn
echo "[INFO] Finished running the claim1 scenario."
python average.py ../claims/claim1/average.csv ../claims/claim1/scenarios.csv
echo "[INFO] Average results are stored at claims/claim1/average.csv"