# siteaudit

Command-line website auditing for freelancers and small agencies.
Point it at a small-business domain and get the fixable technical issues —
measured live, nothing invented.

Built as the **Open Source mini-challenge** contribution alongside the
[Hermes Site-Audit MCP Server](https://github.com/ZeroZen270/hermes-mcp)
(Alexa+ track) for the Amazon Developer Hackathon *Build, Ship, Shape* (2026).

## Install

```bash
pip install -e .
```

## Use

```bash
siteaudit example.com
```

```
Domain : example.com
URL    : https://example.com
Score  : 2 (higher = more fixable issues)

HTTP status : 200 (0.33s)

Issues found:
  • homepage has no meta description (hurts click-through)
```

JSON output for scripts and CI:

```bash
siteaudit example.com --json
```

## What it checks (all measured with live requests)

- HTTP status / reachability, response latency (flags > 4s)
- Missing `<title>` tag, missing meta description, missing mobile viewport tag
- TLS certificate expiry (flags < 14 days)
- Server 5xx errors, plain-HTTP fallback detection
- Public contact emails (homepage + contact/about pages, `mailto:` first)

## Library use

```python
from siteaudit import audit_domain, draft_outreach

audit = audit_domain("example.com")
print(audit.to_dict())

draft = draft_outreach("example.com")  # honest outreach from measured findings
print(draft["subject"], draft["body"])
```

## Test

```bash
python -m pytest test_cli.py -v   # or: python test_cli.py
```

## License

MIT — see [LICENSE](LICENSE).
