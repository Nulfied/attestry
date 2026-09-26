# Examples

| File | What it shows |
|---|---|
| `suites/example.suite.json` | the starter suite `attestry init` writes; runs free against `echo` |
| `suites/support.suite.json` | a realistic suite: policy, tone, JSON-shape and numeric checks |
| `consent.json` | three consent grants, including one that expires |
| `skills/hello-web/` | a packagable skill with an NTS tool declaring `network: true` |
| `end_to_end.py` | all four subsystems in ~60 lines of Python, then one verify |

```bash
# free, no API key
cp examples/suites/example.suite.json .attestry/drift/suites/
attestry drift run example

# all four subsystems, then verify every claim at once
python examples/end_to_end.py
```
