🧩 The Two‑Layer Model of Multi‑Agent Trust
text
┌─────────────────────────────────────────────────────────────────┐
│                    MULTI‑AGENT SYSTEM                            │
│                                                                  │
│  ┌─────────────────────────────┐  ┌───────────────────────────┐ │
│  │       MODEL LAYER           │  │    DELEGATION LAYER        │ │
│  │  (what the agent believes)  │  │ (who the system blames)    │ │
│  │                             │  │                            │ │
│  │  • Semantic understanding   │  │  • Identity & scope chains │ │
│  │  • Policy compliance        │  │  • Token‑based delegation  │ │
│  │  • Action justification     │  │  • Audit trail attribution │ │
│  └──────────────┬──────────────┘  └──────────────┬─────────────┘ │
│                 │                                │               │
│                 │                                │               │
│           ┌─────▼─────┐                    ┌─────▼─────┐         │
│           │  SND      │                    │ AEGIS‑AT  │         │
│           │ (Memory   │                    │ (Sibling  │         │
│           │ Poisoning)│                    │ Imperson‑ │         │
│           │           │                    │ ation)    │         │
│           └─────┬─────┘                    └─────┬─────┘         │
│                 │                                │               │
│                 ▼                                ▼               │
│     ┌─────────────────────┐        ┌──────────────────────────┐ │
│     │ ATTACKS BELIEF      │        │ ATTACKS BLAME            │ │
│     │                     │        │                          │ │
│     │ Model thinks it's   │        │ Audit log says Agent A   │ │
│     │ following policy    │        │ did it, but Agent B      │ │
│     │ but actually        │        │ actually executed the    │ │
│     │ complying with      │        │ action under adversarial │ │
│     │ poisoned memory     │        │ control                  │ │
│     └─────────────────────┘        └──────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
**SND: The Model‑Layer Attack (Memory Poisoning)**

text
  Attacker poisons vector store ──► poisoned document retrieved
                                         │
                                         ▼
  Model sees: "I should comply with this policy"
                                         │
                                         ▼
  Safety classifier: "No violation detected"  ❌ (belief is corrupted)
                                         │
                                         ▼
  Model acts on attacker's instructions ──► attributes its own action to 
                                             legitimate policy interpretation


What SND proved: The model believes it's doing the right thing, and the auditing layer (safety classifiers) validates that belief. The attack is invisible because it operates at the level of what the model thinks it's doing.

**AEGIS‑AT: The Delegation‑Layer Attack (Sibling Impersonation)**
text
  Attacker injects prompt into Enrich (benign subagent)
                   │
                   ▼
  Orchestrator tricked into issuing delegation token
  with Enrich's identity but Contain's action
                   │
                   ▼
  Contain executes dangerous action ──► audit log says "Enrich did it"
                   │
                   ▼
  Forensic analyst sees benign agent ──► containment action never investigated
                   │
                   ▼
  Attribution Integrity Score (AIS) drops to 0.0  ❌ (blame is corrupted)
What AEGIS‑AT measures: The system knows something happened (unlike SND, where it doesn't even detect the violation), but it blames the wrong agent. The attack survives because the delegation chain—the very mechanism meant to provide non‑repudiation—is the attack vector.

 The Complementarity (Why Both Must Be Measured)

 **Layer	Attack	Fails Because**

* Model (Belief)	SND / Memory Poisoning	The model cannot detect that its own reasoning is corrupted by poisoned context. Safety classifiers look for model misalignment, not memory‑layer attacks.
* Delegation (Blame)	AEGIS‑AT / Sibling Impersonation	The delegation chain cannot guarantee that the act claim in a signed token matches the agent that actually performed the action. The audit log becomes untrustworthy evidence.
* The combined implication: An attacker can (1) poison memory so the model believes it should take a malicious action, and (2) exploit the delegation layer so that action is blamed on a different agent. The system not only does the wrong thing—it accuses the wrong entity of doing it. This is a forensic nightmare that neither layer alone can fix.



