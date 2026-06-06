Indirect injection via external data ingested by Enrich. The attacker poisons an external data source (e.g., a SIEM alert, a threat feed, a log entry) that Enrich reads. Enrich processes that data, and the malicious content propagates to the orchestrator when Enrich acts on it. This adds a data-provenance step and makes the attack chain longer and more dependent on external state.

Answer:
        Recommend: the alert ingestion path.Three reasons, ordered by which one would actually matter to a reviewer:The realism argument is the strongest. A SOC analyst is a trusted, authenticated insider; modeling the attacker as the analyst's own typing is closer to insider threat than to the agent-security problem we're scoping. Alerts, by contrast, are definitionally untrusted input - they describe activity from outside the security perimeter, often quoting attacker-controlled strings (hostnames, URLs, file paths, log lines). An alert containing attacker text is the normal case, not the edge case. This pre-empts the §8 question "is your injection vector realistic?" with the cleanest possible answer: yes, that's just how alerts work.The precedent argument lines up too. 
        
        The Cline incident we anchored the orchestrator decision to was a confused-deputy via a crafted GitHub issue title - exactly an "external content flowing into a triage system" vector. our alert ingestion path is the SOC analog. If a reviewer asks whether this kind of injection happens in the wild, I point at Cline. 
        
        If I'd picked the analyst's prompt instead, the closest precedent is much weaker.The scope-discipline argument seals it. The analyst-prompt vector implicitly assumes the analyst can be tricked, which drags human-factors questions into a benchmark that's supposed to be about cryptographic delegation under adversarial pressure. 
        
        Alert ingestion keeps the attack surface purely technical, which is where our AIS measurement actually lives. One degree of freedom, again.(Why not "both"? Tempting, but it doubles the attack surface description without doubling the measurement. v1 wants one injection path we can defend exhaustively. 
        
        The analyst-prompt vector is a clean backlog item for the future-work section.)
