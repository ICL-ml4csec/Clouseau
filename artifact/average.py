import pandas as pd
from pathlib import Path

def process_csv(csv_file: str | Path) -> pd.DataFrame:
    df = pd.read_csv(csv_file)

    df["precision"] = df["tp"] / (df["tp"] + df["fp"])
    df["recall"]    = df["tp"] / (df["tp"] + df["fn"])      # = TPR
    df["fpr"]       = df["fp"] / (df["fp"] + df["tn"])      # incorrect positives rate
    df["f1"] = 2 * df["precision"] * df["recall"] / (df["precision"] + df["recall"])
    df.rename(columns={"test_name": "Name"}, inplace=True)
    return df[["Name", "precision", "recall", "fpr", "f1"]]

def categorize_scenario(name: str) -> str:
    if name.startswith("se"):
        return "Single Extended"
    if name.startswith("m"):
        return "Multi"
    if name.startswith("optc"):
        return "OPTC"
    if name.startswith("ss"):
        return "Single Sensitivity"
    return "Single"

def concat_runs(files: list[str | Path]) -> pd.DataFrame:
    runs = []
    for run_idx, fp in enumerate(files, 1):
        run_df = process_csv(fp).assign(Run=run_idx)
        runs.append(run_df)
    return pd.concat(runs, ignore_index=True)

def fmt(mean, digits=2):
    return f"{mean*100:.{digits}f}"

def stats_by_type(files: list[str | Path]) -> pd.DataFrame:
    df = concat_runs(files)
    df["Type"] = df["Name"].apply(categorize_scenario)

    summary = (
        df.groupby("Type")
        .agg(
            precision=("precision", "mean"),
            recall=("recall", "mean"),
            f1=("f1", "mean"),
            fpr=("fpr", "mean"),
            samples=("Type", "count"),

        )
        .reset_index()
    )

    summary["recall"]    = summary.apply(lambda r: fmt(r.recall), axis=1)
    summary["precision"] = summary.apply(lambda r: fmt(r.precision), axis=1)
    summary["f1"]        = summary.apply(lambda r: fmt(r.f1), axis=1)
    summary["fpr"]       = summary.apply(lambda r: fmt(r.fpr), axis=1)

    return summary.fillna(0)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python average.py <output.csv> <run1.csv> [<run2.csv> ...]")
        exit(1)

    output_csv = Path(sys.argv[1])
    input_csvs = [Path(p) for p in sys.argv[2:]]
    summary_df = stats_by_type(input_csvs)
    print(summary_df)
    summary_df.to_csv(output_csv, index=False)