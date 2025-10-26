# Project Summary

Clouseau automates attack investigation using LLMs with a hierarchical multi-agent approach. Starting from a single attack clue and environmental context, it plans the investigation, asks targeted questions, executes SQL queries on the provided scenario dataset, and produces a clear incident report—reducing manual triage while keeping optional human-in-the-loop control.

# How to use

Run the CLI and provide an attack clue when prompted; by default it reads `scenarios/scenario.db` and `scenarios/scenarios_context.json`, then writes the report to `scenarios/report.md`. You can override paths and limits with flags such as `--data-source`, `--context-file`, `--report-file`, `--max-investigations`, `--max-questions`, `--max-queries`, and toggle `--interactive` or `--quiet`.

```bash
python app.py --data-source scenarios/scenario.db --context-file scenarios/scenarios_context.json --report-file scenarios/report.md
```

# Demo

<video controls width="720" src="demo/demo.mp4">
	Your browser does not support the video tag. You can download the demo here: [demo/demo.mp4](demo/demo.mp4)
</video>


# ToDo

ToDo:
- [ ] Human In The Loop: CTL-C to step into investigation and give instructions to the agent.
- [ ] Interactive mode: chatbot replacing Closueau agent. if asked to stop, the agent will stop and print the final report.
- [ ] Investigator agent access to timeline for better contextualization.
- [ ] Support for reasoning and thinking models.
- [ ] Integerations with other types of data sources.
- [ ] More complex scenarios.




