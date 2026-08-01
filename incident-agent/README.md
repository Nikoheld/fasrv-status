# FASRV Incident Agent

This service connects Upptime and the public status report form to two isolated Grok 4.5 classification steps.

## Security model

- Public input is normalized, size limited, character allowlisted, rate limited, proof-of-work protected, and checked for prompt injection before it reaches a model.
- The intake Grok has no tools, memory, web access, filesystem access, or subagents and returns a constrained JSON schema.
- The remediation Grok never receives raw report or GitHub text. It sees only controller enums and bounded health facts, then chooses from fixed allowlisted actions.
- Grok never writes to GitHub and never executes a command. The controller independently validates actions and service recovery.
- Complete stdout and stderr from both Grok calls is scanned against known local secret values and generic credential formats before any side effect.
- GitHub titles, bodies, and comments are generated only from local templates, enums, application configuration, and UUIDs. User and model prose is never published.
- Any prompt-injection or secret finding creates `PAUSED`, sends an email to the administrator, and blocks the API, model calls, remediation, and GitHub writes.

The design does not claim that a language model can recognize every possible malicious sentence. Instead it removes the model's ability to disclose data or create arbitrary public content even if semantic classification fails.
