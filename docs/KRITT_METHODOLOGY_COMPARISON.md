# How Kritt Finds Bugs — Methodology Comparison & What We Adopted

Source: the official kritt.ai docs (getting-started/welcome and the workflow/finding
reference). Mission of this note: understand **how their agent actually finds bugs**,
compare it to APKracken's mobile pipeline, and record the methodology changes we made
to match their core mechanism — while keeping the parts of mobile research that kritt
does not do at all.

Kritt is source-repo / blockchain focused (Solidity, Rust, Go, node consensus). It has
**no device layer, no dynamic execution, no runtime-guard bypass** — that whole half is
ours. So the comparison is deliberately asymmetric: we copy their *static reasoning
engine* and keep our *dynamic validation* on top.

---

## The one thing that makes them work

Their agent does **not** "scan a repo for bugs." It runs a **tree of small, focused
prompt steps**, and the entire method rests on three moves:

1. **Enumerate entrypoints** — every place an outside actor can reach the system.
2. **Pair each entrypoint with a concrete _impact_** (node crash / consensus break /
   loss of funds). This is the pivot: a run is never "look at this contract," it is
   "can THIS entrypoint cause THIS impact."
3. **Investigate one focused unit** — "Each downstream run spends its context window on
   one concrete entrypoint-impact pair." One function, one file, one question.

On top of that sits the property the user singled out: the agent goes **back and forth,
again and again, deeper and deeper** — it re-enters the workflow, treats prior findings
as leads, and chases each thread another hop until the path is proven or exhausted.

Everything else (fixed finding schema, automatic de-duplication, post-scripts,
markdown severity rankers) is plumbing around those three moves.

---

## Comparison table

| Dimension | Kritt.ai | APKracken (before) | APKracken (now) |
|---|---|---|---|
| **Unit of work** | One entrypoint × one impact per context window | Recon → "trace to any sink" (impact implicit) | **Recon emits `impact_candidates`; Trace pursues ONE entrypoint × ONE `target_impact`** ✅ matched |
| **Entrypoint enumeration** | Contract/RPC/message entrypoints | Exported Activities/Services/Receivers, deep links, providers, WebView bridges, PendingIntents, FileProvider | Same (kept) |
| **Impact vocabulary** | node crash / consensus break / loss of funds | none explicit | **Mobile impacts**: cred/PII exfil, file read/overwrite, SQLi, WebView JS-bridge RCE, intent redirection, exported-component privesc, provider leak, insecure crypto, native memory corruption |
| **Iterative deepening (back & forth)** | Core selling point — re-research again and again | single forward pass | **ITERATIVE DEEPENING directive**: hypothesise→test→follow every lead recursively; on later passes treat findings as leads, go one hop deeper ✅ matched |
| **Focused-question philosophy** | "point it at one function in one file" | multi-depth DAG, one objective per step | Same shape; reinforced by impact pairing |
| **Workflow model** | Tree of prompt steps, output feeds next | Multi-depth DAG (`llm_workflows`+`steps`) with horizontal branches | Same (we already had a richer DAG than their 3-stage fan-out) |
| **Finding schema** | Fixed schema | Fixed per-step `outputFormat` schema | Same |
| **De-duplication** | Automatic | present in engine merge | keep |
| **Per-finding follow-up** | Post-scripts | per-vuln AI chat + report + exploit-flow | richer than kritt |
| **Severity** | Markdown severity rankers | severity_score + confidence + FP verifier | richer |
| **Static validation** | Re-reads code with focused prompts | WorkspaceTools static tools (ReAct) | same + tool-using FP adjudicator |
| **Dynamic validation** | ❌ none | ✅ on-device reproduce + Frida bypass + screenshots | ✅ **unique to us** |
| **Runtime guard bypass** | ❌ none | ✅ ssl_unpin / anti_detect, re-verify after bypass | ✅ **unique to us** |
| **No-evidence discipline** | prompt-bound | `[[REQUIRES_DEVICE]]` guard — never fabricates device results | ✅ **unique to us** |
| **Target domain** | source repos / chains | decompiled APK (smali/java) + live Android | — |

---

## What we changed (this note's deliverables)

1. **Impact pairing** — `Recon` now outputs `impact_candidates` per entrypoint, and
   `Trace` investigates **one entrypoint × one `target_impact`** at a time, spending its
   full context on proving that single path. This is kritt's pivot move, translated to a
   mobile impact vocabulary. (`backend/src/lib/androidDynamicResearch.js`)

2. **Iterative deepening** — both mobile workflows carry an explicit directive to
   hypothesise, test against code with tools, follow every lead recursively, and on later
   passes treat earlier findings as leads to push one hop deeper. This is the "back and
   forth, deeper and deeper" property the user identified as their most valuable point.

3. Both changes are applied via the workflows' idempotent refresh-in-place ensure
   functions, so they propagate on backend startup and are already live in the DB.

## Where we deliberately diverge (mobile ≠ source repos)

- **Impacts are mobile, not on-chain.** No "loss of funds"; instead credential/PII
  exfiltration, file overwrite/traversal, exported-component privilege escalation,
  WebView bridge RCE, intent redirection, provider leaks, native memory corruption.
- **Source is decompiled**, not authoritative — smali/java from jadx, plus native `.so`
  disasm on a horizontal branch kritt has no analogue for.
- **We validate dynamically.** Kritt stops at a reasoned static finding. We take each
  candidate to a rooted device/emulator, reproduce it, bypass runtime guards (SSL
  pinning, root/emulator detection), re-verify, and attach screenshots — turning a
  "plausible" static finding into a proven, exploitable one. This is the biggest reason
  our output should carry lower false-positive rates than a pure static tool.

## Net

We now share kritt's engine of bug discovery — **enumerate → pair with impact →
investigate one focused unit, and loop back deeper** — and keep the mobile-only dynamic
validation layer they don't have. The static reasoning matches how they found $2M bugs;
the dynamic layer is what makes a mobile finding demonstrably real.
