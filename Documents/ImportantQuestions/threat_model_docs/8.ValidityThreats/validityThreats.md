# §8 — Validity Threats: Working Notes

## The central concession (the spine of §8)

LIMITATION 1 (conceded, not defeated): single-system-instance.
The non-monotonic curve is demonstrated on ONE minimal pipeline,
ONE orchestrator, ONE re-delegation topology. v1 shows the gap
EXISTS / is TRIGGERABLE / SURVIVES the two standard defenses — in
this system. Does NOT prove it across all RFC 8693 deployments.

MITIGATION (in the same breath): the gap is STRUCTURAL, not a
topology quirk. Follows from §4.1 MUST-attribute-to-current-actor +
the standard's implicit assumption (§A.2.3/A.2.5) that current
actor == executor. That assumption is topology-INDEPENDENT. Wherever
requester != executor, the gap should appear. n=1 measured;
mechanism makes generalization LIKELY but unproven. Generality
across topologies = primary future work.

Why concede first: reviewer reaches for it first; head-on > buried.
Why a good §8 NEEDS a real concession: an all-threats-defeated
validity section reads defensive and less convincing. Honest
limitation + reason-it-doesn't-sink-the-result = mature, trusted.

## Two honest SUB-limitations retained (deliberately not defeated)

- Threat 3: ground-truth independence is by CONSTRUCTION + argument,
  NOT formal verification. v1 asserts it, doesn't machine-check it.
- Threat 6: v1 does NOT measure the manipulated-Enrich case (relies
  on Enrich being correct). Named out of scope, left to future work.

## The seven threats and their mitigations (assembly map)

1. Generalize? → CONCEDED + §4.1 structural mitigation. [from §6 notes]
2. Toy system? → minimal != unrealistic; every element maps to a
   real precedent (Cline/Log4Shell/Splunk/ELK + SOAR routing + NIST).
3. Ground truth not independent? → Boundary 5 three axes (process,
   credential, causal). [from Boundary 5 notes] + sub-limitation.
4. Unfair baselines? → config flags over ONE codebase; B2=1.0 model
   stated (authn=executor). [from §6 notes]
5. Just a logic bug? → §4.1 MANDATES it; can't "read a different
   field." Spec-grounded. [from Boundary 2 + §6 notes]
6. Scripted not real LLM? → attack is model-robustness-INDEPENDENT
   by design (Reading 2); strength not gap + sub-limitation.
7. Why gray-box? → matches precedents; Kerckhoffs category error
   avoided. [from adversary-model notes]

## The closing discipline (the benchmark-vs-demo point)

Every AIS value is a PRE-REGISTERED hypothesis, committed before
any attack code. Contradicted predictions are REPORTED as findings,
not reconciled away. This is THE structural difference between a
benchmark and a demo. This is the closing statement of §8 — must be
its own bold subsection, not buried in threat 7.