This short experiment aims to reproduce Clouseau results against single host scenarios. Executing run.sh will run Clouseau against SS1 to SS4 across three POIs for each scenario. Then we average these results to produce a single score. Clouseau's average results in recall, precision, and F1 should be above 95% for all values. The results may be lower than reported in the paper, because we restricted the budget for investigation to 3, 5 and 5 (less than half!). For faithful reproduction, please remove the constraints from the arguments in run.sh.

To run the experiment, simply execute run.sh. Before running, make sure you have stored your API key in `API_KEY` environment variable, and you are in the project root directory (and not inside the claims directory) as stated in the README.txt. 

If the experiment is completed successfully, it should output two CSV files: 

1- `scenarios.csv`: results of each test case are stored here.
2- `average.csv`: contains the average score of all test cases.