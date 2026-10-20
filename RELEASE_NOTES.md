## Reliability fixes

| Area | Change |
| --- | --- |
| Processing status | Track admitted queued, in-flight and post-processing work; return idle after completion, failure or cancellation without hiding active captures |
| Read-only previews | Opening results or retaining live-capture context no longer implies an active capture |
| Incomplete transport headers | Avoid port-formatting panics while retaining connection packet counts, bytes and direction |
| Unsupported IP protocols | Retain separate connection accounting without requiring a decoded transport header |
| Behavioral baselines | Preserve valid rate windows starting at Unix time zero across baseline saves |
| Investigation evidence | Retain capture-scoped evidence across persisted investigations |
| Stream lifecycle | Preserve stream ownership during cancellation |
| WebUI startup | Report synchronous listener bind failures |
