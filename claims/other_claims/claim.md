To reproduce the other claims (multi-host results, OpTC results, ablation results, and open-weight model results), you need the processed scenario files — including the OpTC and multi-host scenarios. First, run the preprocessing step in `artifact/preprocessing/` to generate the scenario files. After preprocessing, run the commands below to reproduce the experiments.

You can set the model type as needed. If you use a reasoning model, increase `DEFAULT_MAX_TOKENS` in `constants.py` to at least 4096.

```bash
# set model type
# if using a reasoning model, increase DEFAULT_MAX_TOKENS in constants.py to at least 4096

python app.py --scenarios-optc --csv-file scenarios-optc.csv --no-warn
python app.py --scenarios-ml --csv-file scenarios-ml.csv --no-warn
python app.py --scenarios-optc --ablation-agent --csv-file scenarios-optc-ab.csv --no-warn
python app.py --scenarios-ss --ablation-agent --csv-file scenarios-ss-ab.csv --no-warn
```