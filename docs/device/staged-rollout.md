# Staged rollout

`staged_rollout` executes sequentially. Every asset needs its own request, approval and prechecks.
The next action remains unattempted when one fails, is unknown, or needs manual recovery.
In-memory locks/journals are test-only; production needs durable distributed equivalents.

Recovery is an injected supported path with separate scope and postchecks. It is never automatic
inverse-command execution; production recovery remains blocked.
