#!/bin/bash

# change directory
# cd ../../ # go to root directory


export LLM_MODEL="gpt-4.1-mini"

cd artifact

echo "[INFO] Running the claim3 scenario..."
python app.py --scenarios-ss --csv-file ../claims/claim3/scenarios.csv --no-warn
echo "[INFO] Finished running the claims3 scenario."
python average.py ../claims/claim3/average.csv ../claims/claim3/scenarios.csv
echo "[INFO] Average results are stored at claims/claim3/average.csv"