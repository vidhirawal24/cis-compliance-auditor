# Drift analysis

`compare_normalized_facts` compares normalized facts deterministically without mutation.
Differences retain paths and safe before/after values; password/secret/token strings are redacted.
Partial captures produce uncertainty rather than false removals. `drift_events` are typed output
only; Mandar owns persistence, alerting, expected-change policy, and risk decisions.
