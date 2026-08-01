# FASRV Incident Agent

This service connects Upptime and the public status report form to two isolated Grok 4.5 classification steps.

## Security model

- Public input is normalized, size limited, character allowlisted, rate limited, proof-of-work protected, and checked for prompt injection before it reaches a model.
- The intake Grok has no tools, memory, web access, filesystem access, or subagents and returns a constrained JSON schema.
- The remediation Grok never receives raw report or GitHub text. It sees only controller enums and bounded health facts, then chooses from fixed allowlisted actions.
- Automated bug remediation is limited to Jellyfin. Playback failures may restart Jellyfin, image failures may request a targeted Jellyfin metadata/image refresh, and failed HiAnime downloads may requeue one conservatively matched failed job. Other applications and unsupported categories are forced to `no_action`.
- Grok never writes to GitHub and never executes a command. The controller independently validates actions and service recovery.
- Complete stdout and stderr from both Grok calls is scanned against known local secret values and generic credential formats before any side effect.
- GitHub titles, bodies, and comments are generated only from local templates, enums, application configuration, and UUIDs. User and model prose is never published.
- Every processed issue receives one idempotent fixed-template outcome comment. Successful repairs are marked solved; declined or failed repairs remain open and explain why no automatic repair was completed.
- Any prompt-injection or secret finding creates `PAUSED`, sends an email to the administrator, and blocks the API, model calls, remediation, and GitHub writes.

The design does not claim that a language model can recognize every possible malicious sentence. Instead it removes the model's ability to disclose data or create arbitrary public content even if semantic classification fails.

## Local control dashboard

The dashboard listens only on the server loopback interface and is exposed to the administrator laptop through a restricted SSH local-forward account. It is available on the laptop at `http://127.0.0.1:8153`.

It shows sanitized lifecycle events for the intake and remediation Grok processes, including a bounded decision summary, controller facts, allowlisted actions, targets, and individual recovery checks. Raw reports, complete model output, hidden chain-of-thought, credentials, and GitHub tokens are never exposed. The pipeline switch creates or removes the fail-closed `PAUSED` state. Blocking terminates a running Grok process; manually interrupted queue work is resumed without creating a duplicate issue. Work rejected by a security gate is moved to local quarantine when an administrator explicitly unblocks the pipeline and is never reprocessed.
