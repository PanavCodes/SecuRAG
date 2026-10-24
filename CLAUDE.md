@AGENTS.md

# Claude Code notes
- Start in plan mode for each Step: state the plan and the acceptance test, then implement.
- Use `pytest -q` and the step's acceptance command to verify; paste the real output.
- Keep `NOTES.md` updated at the end of every step.
- When unsure about a library API, run `python -c "import X; help(X.Y)"` or read the installed source rather than guessing.
