# Contributing

Contributions should keep the project small, auditable, and safe for defensive use.

Good contributions include:

- More precise Windows API error handling
- Safer output formatting
- Additional synthetic test targets
- Documentation for authorized lab workflows
- CI or static-analysis improvements

Before opening a pull request:

```powershell
python -m py_compile .\mem_scanner.py .\tools\hold_hex_target.py
python .\scripts\check-public-repo.py
```

Do not submit real process dumps, extracted secrets, private incident data, or bypass instructions.
