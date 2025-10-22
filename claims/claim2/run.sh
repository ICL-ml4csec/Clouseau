#!/bin/bash

# change directory
# cd ../../ # go to root directory


export LLM_MODEL="gpt-4.1-mini"

cd artifact

echo "[INFO] Running the claim2 scenario..."
python app.py --scenarios-se --csv-file ../claims/claim2/scenarios.csv --no-warn --max-investigations 3 --max-questions 5 --max-queries 5
echo "[INFO] Finished running the claim2 scenario."
python average.py ../claims/claim2/average.csv ../claims/claim2/scenarios.csv
echo "[INFO] Average results are stored at claims/claim2/average.csv"