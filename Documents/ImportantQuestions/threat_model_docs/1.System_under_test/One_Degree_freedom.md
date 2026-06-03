Why Single Is Right for v1
1. Measurement integrity
Your AIS metric measures who the system blames for an action. If the attack succeeds at the decision step but the execution step is correctly attributed, you get a partial misattribution that’s messy to score. With a single call, there’s no ambiguity: the entire action (decision + execution) is either correctly or incorrectly attributed. That’s a cleaner result for your first benchmark.

2. Reproducibility
A single call makes the attack injector simpler. You just have to get the orchestrator to issue a token that sends contain(...) under the wrong identity. If you split it, you might have to coordinate two separate injections, which increases the chance of a failed experiment that’s not due to the defense but to implementation complexity.

3. Attack attribution
When you present your results, you want to say "with defense X, the impersonation succeeds Y% of the time." If you split the call, you can't easily tell whether the defense failed at the decision or the execution layer. That’s interesting, but it’s a second-order question. v1 should establish the primary finding: delegation-chain accountability is broken in a specific, measurable way. You can always add nuance in v2.

4. Real-world precedent
Even in real SOCs, many containment actions are single-step: an analyst hits a button that both decides and executes (e.g., "block IP" on a firewall). The split workflow is more common in large enterprises with manual approval gates, but your v1 benchmark doesn’t need to model that to be valid. It just needs to model a realistic atomic action that can be misattributed.

**Future Work:**
How v2 Could Handle Split Workflows (Without Breaking v1)
When you’re ready to add nuance, you can model the split without invalidating v1:

Keep the AIS metric identical. You still measure whether the final attribution record matches ground truth for the entire incident (decision + execution).

Add a second metric, "Decision Integrity Score" (DIS), for the internal decision step if you want to isolate where the failure occurred.

Add a second attack flavor that targets the decision step specifically (e.g., an attacker who only wants to cause a false containment decision, even if the execution is correctly attributed). But that’s a different benchmark, not a v1 expansion.

v1 with a single tool call stands on its own; it’s a complete, defensible measurement of delegation-layer misattribution. v2 would build on it, not replace it.