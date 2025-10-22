# Dataset download and preprocessing

This folder helps you pull the raw datasets (ATLAS and DARPA OpTC) and turn them into analysis‑ready scenarios. One command will fetch the data, unpack it, and build the CSV/SQLite artifacts used elsewhere in this repo.

What this gives you
- ATLAS: original single‑host and multi-host scenarios (S1–S4, M1-M6) plus synthetic variations (SE1–SE4 and SS1–SS4) as `scenario.csv` and `.db` files under `scenarios/`
- OpTC (OPT1–OPT3): preprocessed SQLite databases under `scenarios/OPT*/`

## Getting Started
Start by verifying that you can access the raw dataset hosted at this google drive folder:
```https://drive.google.com/drive/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa```


Then, you will need to install and configure `rclone`:
1) Install rclone (see https://rclone.org/install/)
2) `rclone config` and create a remote called `optc` with drive access.

Now you can run `download.sh` to download and preprocess the data.