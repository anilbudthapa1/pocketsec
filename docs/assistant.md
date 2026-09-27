# PocketSec alert explainer (`pocketsec-chat`)

- **Status:** implemented, stdlib only, no language model. Package `pocketsec/assistant/`.
- **Design:** "Option 1" — a built-in explainer: a deterministic intent classifier plus
  sentence templates filled only from facts the alert carries.
- **Authority:** none (ADR-0003). The assistant explains; it never acts.

## What it does

You ask a question about an alert in plain words ("y did u flag this", "hw sure r u",
"can u undo"). The assistant:

1. **classifies** the question into one of thirteen intents with fixed word lists, casual-form
   and contraction expansion, and one-edit typo tolerance on words of five or more letters
   (`intents.py`, `lexicon.py`);
2. **answers** from the alert's typed facts with one template per intent (`templates.py`,
   `response_templates.py`);
3. **checks** every sentence against the facts it cites before showing it (`guard.py`), and
   withholds any sentence that fails; then the CLI checks the rendered text once more
   (`verify_rendered`) just before printing it.

| Intent | Answers from |
|---|---|
| `WHY_FLAGGED` | Stage 4 verdict and hand-off outcome; how many explanations are unresolved novel mechanisms (counted from the hypotheses); the observed events with the largest Stage 1 state change; the top lineage's accumulated state; the surviving explanations (hedged) |
| `WHAT_HAPPENED` | the Stage 1 events that changed state, ran a program, or were cited, shown in step order; when they do not all fit, the largest state changes are kept first, so this page never omits what `WHY_FLAGGED` ranks highest |
| `WHICH_PROCESS` | per-lineage state, capabilities earned by behaviour, and the program each lineage ran (or "unknown") |
| `HOW_SURE` | recorded confidence and uncertainty, quoted exactly; that 0.0 is not a statement of harmlessness (no cause is given: the record does not say which of Stage 4's three zero-confidence conditions applied); the engine's own note |
| `WHAT_UNKNOWN` | Stage 4 `UNK` claims, shadow regions worded by their recorded reason (with any observed contradiction beside them), truncations in plain words, dropped events, expired leases whose outcome is not recorded |
| `WHAT_ACTION` | the Stage 5 `ResponseRecordV1`: plan decision, receipts ("it ran" only for receipts that reached the host), SENTINEL verdicts and denials (each refusal once), record truncations (never called planner reasons) |
| `HOW_TO_UNDO` | receipt reversal operators, lease times, lease expiry and reversal outcome ("unknown" when the outcome is not recorded) |
| `FALSE_ALARM` | the verdict, the remaining explanations, and what would separate them. Never "yes" |
| `EVIDENCE` | exported evidence references, cited observations, event record locators and digests |
| `ADVICE` | "what should I do?", "should I reboot?": the hand-off outcome PocketSec recorded, and a note that remediation advice is out of scope |
| `HELP` / `OUT_OF_SCOPE` / `ACTION_REQUEST` | fixed notes (an unmatched question gets a friendly "didn't catch that"; only a detected injection gets the "can't take new instructions" note); for an action request, what SENTINEL already approved or refused |

### Every sentence says where it came from

Each factual line ends with a provenance tag and numbered sources:

| Tag | Kind | Meaning |
|---|---|---|
| `(observed)` | OBS | a sensor event, referenced by SHA-256 digest |
| `(derived by fixed rules from observed events)` | DER | Stage 1's deterministic state calculus over observed events |
| `(inferred, not certain)` | INF | a Stage 4 hypothesis. Always hedged ("possible") |
| `(unknown)` | UNK | something the record does not know. Never phrased as "did not happen" |
| `(as recorded by PocketSec)` | REC | a statement about PocketSec's own record (verdict, confidence, receipts) |
| `(counterfactual, not observed)` / `(external knowledge, ...)` | CF / EXT | supported, not emitted by today's stages |

`REC` is the one kind added to Stage 4's six. "The verdict is UNKNOWN" is a true statement
about the record, not an observation of the host; filing it under OBS would let a record
value borrow a sensor reading's authority.

A sentence citing several facts carries the **weakest** kind among them, computed rather
than chosen (`templates.say`). Notes (`Note: ...`) are fixed catalogue strings
(`wording.NOTES`) that explain how to read an answer; they never state a fact about an
alert.

## What the guard refuses

`guard.check_sentence` runs on every sentence before display, and `guard.verify_rendered`
parses the rendered text a person sees back to facts; `cli.py` runs it on every text answer
just before printing and prints a fixed refusal note instead if it fails. A sentence is
withheld if it:

- cites no fact, or a fact the alert does not have;
- carries a kind other than the weakest of its cited facts;
- contains a number that is not, as a **whole token**, one of its cited facts' own values
  (`198.51.100.9` is not supported by `198.51.100.91`, nor `5` by `65`; a shortened
  decimal is accepted only as `about <prefix>`; provenance ids and digests are excluded);
- names a path its cited facts do not hold;
- names a security dimension or mandatory signal (`privilege`, `credential`,
  `reachability`, ...) that its cited facts do not hold;
- names a step, a process id, a relation verb or a rank word that does not match the cited
  event or lineage ("Step 66" for step 65, "deleted" for a READ, "lowest" for rank 1);
- uses a completed-compromise word (`stolen`, `exfiltrated`, `compromised`, `breached`,
  `hacked`, `attacker`, ...), unless it is a hedged INF whose cited fact carries the word;
- is an INF without a hedge, or an INF stated as settled ("determined", "ruled out", "the
  cause"), or an UNK that is not a coverage statement;
- matches an exoneration pattern ("did not happen", "there was no", "this is a false alarm");
- has a negated clause that is not a coverage statement, when the sentence cites an unknown
  or the clause mentions an unknown's subject. This is Stage 4 verbalizer rule (d) applied
  per clause with a narrow exemption: only phrases whose subject is knowledge ("unknown",
  "not observed", "no evidence that", "no X was observed") exempt a clause. Stage 4's own
  marker list ("data", "recorded", "sensor", ...) is not used, because "the recorded data
  shows no file was modified" contains one of those words.

Numbers are quoted exactly when short and truncated with "about" otherwise (0.3333... is
"about 0.3333"), never rounded up. A confidence of 0.0 stays "0.0" and is explained.

## What it refuses to do

- **Act.** The package imports nothing from `pocketsec.stage5`. Stage 5's seam module
  imports the transactional executor, so the response record is read as plain JSON rows
  (`response_rows.py`). There is no code path from a question to a token, an executor or a
  shell. A test replaces `subprocess`, `os.system`, `os.kill`, `socket` and friends with
  tripwires and asks thirteen malicious questions.
- **Be read as having acted.** An action verb is a request by default ("go ahead and kill
  it", "you should suspend it", "approve it"); only a question auxiliary before it ("did
  you kill it?", "was it blocked?") makes it a question, and "should I" / "how do I" / "how
  to" make it a request for advice. Whenever an action or undo verb appears, answers about
  actions, undo and advice carry the no-authority note, so a list of receipts is never read
  as the assistant's own doing. "rollback", "unblock", "resume" and the like, used as
  requests, keep the undo answer and gain the same note.
- **Take instructions or facts from a question.** "ignore previous instructions", "you are
  now ...", and fake `[OBS]` claim text are classified `OUT_OF_SCOPE`. Shell
  metacharacters or command words force `ACTION_REQUEST`.
- **Echo user text.** Answers contain only fact values and catalogue strings. Matched terms
  are lexicon words, not the user's tokens. Canary strings in malicious questions never
  appear in text or JSON output.
- **Read corpus ground truth.** `capture.py` never touches `run.case` (a test wraps it in a
  tripwire). `IncidentCase.truth` would manufacture certainty.
- **Use Stage 1's `StateCalculusSlot` verdict.** It reads `final_state` for a lineage the
  re-identified Stage 4 corpus never uses, and returns BENIGN with confidence 1.0 on
  incidents whose lineages accumulated credential, persistence and external reach. Per-lineage
  state comes from `compiler.lineage_state(actor)` instead. The defect is Stage 1's, and is
  reported, not patched here.

## Where alerts come from

One wire form, the **alert handoff** (`pocketsec.assistant.alert_handoff.v1`, `handoff.py`):

- `resolution` — Stage 4's `CBFResolutionV1.to_dict()`, re-validated with
  `CBFResolutionV1.from_dict` so Stage 4's own export refusals run on load;
- `synthetic` — required bool;
- `events`, `events_total`, `lineages` — Stage 1 transitions resolved by digest, and
  per-lineage state (`capture.handoff_from_run`). At most 128 events per alert (cited first,
  then state changes, then program runs), and the drop count is itself a fact;
- `assessment` — confidence, horizon and detail from the live `IncidentResolution`;
- `response`, `leases` — optional Stage 5 `ResponseRecordV1.to_dict()` and seam-safe lease
  rows. A response for a different incident is refused.

Strings are cut to 240 characters and control characters are replaced, because a recorded
path is chosen by whoever controls the host and ends up on an analyst's terminal.

## Usage

```
pocketsec-chat demo                               # scripted walk-through (synthetic alerts)
pocketsec-chat                                    # interactive: /alerts, /open N, /sources, /help, /quit
pocketsec-chat --ask "why?" --alert 4             # one question
pocketsec-chat --ask "why?" --alert 4 --json      # JSON with the provenance list
pocketsec-chat --ask "why?" --alert 4 --sources   # full source ids and evidence digests
pocketsec-chat --bundle alert.json --ask "can u undo" --alert 1
python -m pocketsec.assistant.cli demo            # without installing the entry point
```

## Example session (real output)

Five one-shot questions about demo alert 4, run with `PYTHONHASHSEED=0` on 2026-09-27
(Python 3.14.7). One per kind: why, how sure, what is unknown, a request to act, and a typo.
Default output shows fact ids and kinds under `Sources:`; `--sources` adds each fact's claim
id or record path and its evidence digest.

```
$ python -m pocketsec.assistant.cli --ask "y did u flag this" --alert 4
Alert 4 | s4-inc-0011-0006 | SYNTHETIC lab data
Question type: WHY_FLAGGED (matched: why, flag, why did)
- PocketSec's reasoning engine recorded the verdict UNKNOWN for incident s4-inc-0011-0006: it could not single out one leading explanation. (as recorded by PocketSec) [1]
- All 4 possible explanations it holds are unresolved novel mechanisms. (inferred, not certain) [2,3,4,5]
- When it handed the incident on, it asked for a human analyst to look at the incident. (as recorded by PocketSec) [1]
- Step 65: process 10000604 connected to the network address 198.51.100.91:8443. (observed) [6]
- By PocketSec's fixed state rules this raised network reachability to external (change score 8.0). (derived by fixed rules from observed events) [7]
- PocketSec's rules classify 198.51.100.91:8443 as an external network address; the strongest reading those rules allow is possible external communication. (derived by fixed rules from observed events) [6,7]
- Step 65's evidence reference was one of 7 cut from the exported record, which keeps at most 64 evidence references; the event itself comes from PocketSec's event record. (as recorded by PocketSec) [6,8]
- Step 49: process 10000604 wrote to the file /etc/cron.d/sysupdate. (observed) [9]
- By PocketSec's fixed state rules this raised modification capability to user files and persistence to service (change score 4.75). (derived by fixed rules from observed events) [10]
- PocketSec's rules classify /etc/cron.d/sysupdate as a persistence location (something placed there can run again later); the strongest reading those rules allow is possible persistence write. (derived by fixed rules from observed events) [9,10]
- Step 26: process 10000604 read the file /root/.ssh/id_rsa. (observed) [11]
- By PocketSec's fixed state rules this raised credential exposure to readable (change score 4.0). (derived by fixed rules from observed events) [12]
- PocketSec's rules classify /root/.ssh/id_rsa as credential material; the strongest reading those rules allow is possible credential access. (derived by fixed rules from observed events) [11,12]
- Taken together, process 10000604 ends with privilege level elevated, credential exposure readable, network reachability external, persistence service and modification capability user files; its security-state score is 18.5, the highest of the 7 processes PocketSec tracked here. (derived by fixed rules from observed events) [13]
- PocketSec is weighing 4 possible explanations and gives each the same weight, 0.25: unresolved novel mechanism, 4 variants. (inferred, not certain) [2,3,4,5]
Note: The events above are ranked by how much PocketSec's state rules say each one changed the host's security state. The reasoning engine itself did not single them out as its reasons.
Note: 'Unresolved novel mechanism' is PocketSec's name for activity that matches none of the mechanisms it knows. It is a label for the unfamiliar, not a finding of harm.
Sources:
  [1] rec:assessment (REC)
  [2] inf:0 (INF)
  [3] inf:1 (INF)
  [4] inf:2 (INF)
  [5] inf:3 (INF)
  [6] evt:7dbe94993654c69f (OBS)
  [7] der:7dbe94993654c69f (DER)
  [8] trunc:max_field_evidence_refs (REC)
  [9] evt:ff0457465a7364f6 (OBS)
  [10] der:ff0457465a7364f6 (DER)
  [11] evt:b7c291865504af56 (OBS)
  [12] der:b7c291865504af56 (DER)
  [13] lin:10000604 (DER)
(exit 0)

$ python -m pocketsec.assistant.cli --ask "how sure are you?" --alert 4
Alert 4 | s4-inc-0011-0006 | SYNTHETIC lab data
Question type: HOW_SURE (matched: sure, how sure)
- PocketSec's recorded confidence is 0.0 and its recorded uncertainty is 1.0. (as recorded by PocketSec) [1]
- A confidence of 0.0 is not a statement that the activity is harmless. (as recorded by PocketSec) [1]
- The verdict UNKNOWN is an abstention: PocketSec records UNKNOWN rather than guess when the evidence does not decide. (as recorded by PocketSec) [1]
- PocketSec is weighing 4 possible explanations and gives each the same weight, 0.25: unresolved novel mechanism, 4 variants. (inferred, not certain) [2,3,4,5]
- The engine's own note reads: "field holds only UNKNOWN-family worlds (4); novel residuals are not mechanisms that could be identified or told apart". (as recorded by PocketSec) [1]
- Which of the remaining explanations is right is unknown: PocketSec knows of no affordable observation that would separate them. (unknown) [6]
Note: 'Unresolved novel mechanism' is PocketSec's name for activity that matches none of the mechanisms it knows. It is a label for the unfamiliar, not a finding of harm.
Sources:
  [1] rec:assessment (REC)
  [2] inf:0 (INF)
  [3] inf:1 (INF)
  [4] inf:2 (INF)
  [5] inf:3 (INF)
  [6] unk:unk.identifiability (UNK)
(exit 0)

$ python -m pocketsec.assistant.cli --ask "what don't you know?" --alert 4
Alert 4 | s4-inc-0011-0006 | SYNTHETIC lab data
Question type: WHAT_UNKNOWN (matched: not know)
- Which of the remaining explanations is right is unknown: PocketSec knows of no affordable observation that would separate them. (unknown) [1]
- PocketSec's sensor-visibility model has no evidence that auditd, ebpf, procfs, journald and lsm can observe the modification signal, so its coverage of that signal is unknown; this is a statement about sensor coverage only, and leaves the host's activity undecided. (unknown) [2]
- Even so, observed events in this incident did change modification capability, for example step 8. (derived by fixed rules from observed events) [3]
- PocketSec's sensor-visibility model has no evidence that auditd, ebpf, procfs, journald and lsm can observe the reachability signal, so its coverage of that signal is unknown; this is a statement about sensor coverage only, and leaves the host's activity undecided. (unknown) [4]
- Even so, observed events in this incident did change network reachability, for example step 3. (derived by fixed rules from observed events) [5]
- Whether any response was taken is unknown to me: no record from PocketSec's response stage is attached to this alert, so nothing about a response is recorded here. (unknown) [6]
- The program each of these processes ran is unknown, because no program start by them was observed: 10000604, 10000601, 10000602 and 10000606. (unknown) [7,8,9,10]
- 8 links in PocketSec's causal record were dropped because one end was outside this incident's record. (as recorded by PocketSec) [11]
- 7 evidence references were left out of the exported record because it keeps at most 64 evidence references. (as recorded by PocketSec) [12]
- The reasoning engine stopped at its work limit before settling the incident. (as recorded by PocketSec) [13]
Note: PocketSec's event record keeps the order of events, not clock times.
Sources:
  [1] unk:unk.identifiability (UNK)
  [2] unk:unk.shadow.0 (UNK)
  [3] der:6008efe2e9a12ccd (DER)
  [4] unk:unk.shadow.1 (UNK)
  [5] der:d06bc84deb86ec7e (DER)
  [6] unk:response (UNK)
  [7] unk:program:10000604 (UNK)
  [8] unk:program:10000601 (UNK)
  [9] unk:program:10000602 (UNK)
  [10] unk:program:10000606 (UNK)
  [11] trunc:endpoint_absent (REC)
  [12] trunc:max_field_evidence_refs (REC)
  [13] trunc:resolution_horizon_exhausted (REC)
(exit 0)

$ python -m pocketsec.assistant.cli --ask "go ahead and kill it" --alert 4
Alert 4 | s4-inc-0011-0006 | SYNTHETIC lab data
Question type: ACTION_REQUEST (matched: kill)
- Whether anything was approved is unknown to me: no record from PocketSec's response stage is attached to this alert, so nothing about a response is recorded here. (unknown) [1]
Note: I can only explain what PocketSec recorded. I cannot run commands, change the host, or approve anything, and nothing you type here is ever run.
Note: Changes to a host are made only by PocketSec's response stage, behind its SENTINEL safety checks, or by a human operator working through that stage.
Sources:
  [1] unk:response (UNK)
(exit 0)

$ python -m pocketsec.assistant.cli --ask "wat hapened" --alert 4
Alert 4 | s4-inc-0011-0006 | SYNTHETIC lab data
Question type: WHAT_HAPPENED (matched: ~happened, what happened)
- PocketSec's event record holds 71 events for this incident. Below, in step order, are the ones that changed the security state most, then events the reasoning engine cited, then program runs. (as recorded by PocketSec) [1]
- Step 3: process 10000602 accepted a network connection involving 127.0.0.1:6379. (observed) [2]
- By PocketSec's fixed state rules this raised network reachability to local (change score 0.75). (derived by fixed rules from observed events) [3]
- Step 8: process 10000603 wrote to the file /var/cache/apt/state. (observed) [4]
- By PocketSec's fixed state rules this raised modification capability to user files (change score 0.75). (derived by fixed rules from observed events) [5]
- Step 9: process 10000604 switched to the user identity uid=0. (observed) [6]
- By PocketSec's fixed state rules this raised privilege level to elevated (change score 1.0). (derived by fixed rules from observed events) [7]
- Step 16: process 10000601 wrote to the file /var/lib/db/wal.log. (observed) [8]
- By PocketSec's fixed state rules this raised modification capability to user files (change score 0.75). (derived by fixed rules from observed events) [9]
- Step 17: process 10000606 accepted a network connection involving 127.0.0.1:51001. (observed) [10]
- By PocketSec's fixed state rules this raised network reachability to local (change score 0.75). (derived by fixed rules from observed events) [11]
- Step 26: process 10000604 read the file /root/.ssh/id_rsa. (observed) [12]
- By PocketSec's fixed state rules this raised credential exposure to readable (change score 4.0). (derived by fixed rules from observed events) [13]
- Step 49: process 10000604 wrote to the file /etc/cron.d/sysupdate. (observed) [14]
- By PocketSec's fixed state rules this raised modification capability to user files and persistence to service (change score 4.75). (derived by fixed rules from observed events) [15]
- Step 65: process 10000604 connected to the network address 198.51.100.91:8443. (observed) [16]
- By PocketSec's fixed state rules this raised network reachability to external (change score 8.0). (derived by fixed rules from observed events) [17]
Note: PocketSec's event record keeps the order of events, not clock times.
Note: These are the most significant events first. Ask 'tell me more' to see more of them.
Sources:
  [1] rec:events (REC)
  [2] evt:d06bc84deb86ec7e (OBS)
  [3] der:d06bc84deb86ec7e (DER)
  [4] evt:6008efe2e9a12ccd (OBS)
  [5] der:6008efe2e9a12ccd (DER)
  [6] evt:0bb8acdcf75d4210 (OBS)
  [7] der:0bb8acdcf75d4210 (DER)
  [8] evt:f79e71ea5b708ca0 (OBS)
  [9] der:f79e71ea5b708ca0 (DER)
  [10] evt:1fe78cb4e3a84839 (OBS)
  [11] der:1fe78cb4e3a84839 (DER)
  [12] evt:b7c291865504af56 (OBS)
  [13] der:b7c291865504af56 (DER)
  [14] evt:ff0457465a7364f6 (OBS)
  [15] der:ff0457465a7364f6 (DER)
  [16] evt:7dbe94993654c69f (OBS)
  [17] der:7dbe94993654c69f (DER)
(exit 0)
```

`python -m pocketsec.assistant.cli demo` opens with the alert list (first 7 of its 390
lines):

```
PocketSec alert explainer: 4 alerts loaded in 2.17 s.
This alert is synthetic: it comes from PocketSec's lab corpus, not from real telemetry.
Alerts (* marks the open one):
* 1. s4-inc-0011-0000 [SYNTHETIC], 58 events: it asked for more detailed monitoring before deciding; highest process state: privilege level elevated, credential exposure readable, network reachability local (score 5.75)
  2. s4-inc-0011-0001 [SYNTHETIC], 74 events: it asked for a human analyst to look at the incident; highest process state: credential exposure readable, network reachability local (score 2.75)
  3. s4-inc-0011-0003 [SYNTHETIC], 81 events: it asked for a human analyst to look at the incident; highest process state: privilege level elevated, credential exposure readable, network reachability external (score 14.5)
  4. s4-inc-0011-0006 [SYNTHETIC], 71 events: it asked for a human analyst to look at the incident; highest process state: privilege level elevated, credential exposure readable, network reachability external (score 18.5)
```

An ambiguous question is sent back rather than guessed
(`--ask "how sure are you that this is a false alarm" --alert 4`):

```
Alert 4 | s4-inc-0011-0006 | SYNTHETIC lab data
Question type: unclear (candidates: HOW_SURE, FALSE_ALARM)
Note: I'm not sure which question you mean. Did you mean one of these?
Note: Try: "how sure are you?"
Note: Try: "is this a false alarm?"
```

A real Stage 5 response: a Stage 5 fixture case executed by the B9 human-only arm through
the real executor, leased, and swept after the clock advanced (bundle built by
`tests/_assistant_support.py`), `--ask "how do I undo it?"`:

```
Alert 1 | INC-corpus-011-001 | SYNTHETIC lab data
Question type: HOW_TO_UNDO (matched: undo)
- SUSPEND_PROCESS can be reversed with RESUME_PROCESS. (as recorded by PocketSec) [1]
- Its lease lease.act.corpus-011-001.cand04.SUSPEND-PROCESS was granted at time 1000 for 900 seconds, so it expires at time 1900 (hard limit 4600). (as recorded by PocketSec) [2]
- The lease expired at time 1901 and the change was reversed with RESUME_PROCESS. (as recorded by PocketSec) [2]
- The reversal RESUME_PROCESS ran: it was carried out and its checks confirmed the effect (COMMITTED_VERIFIED). (as recorded by PocketSec) [3]
Note: I can't undo anything myself. A human operator performs reversals through PocketSec's response stage.
Sources:
  [1] resp:receipt:0 (REC)
  [2] resp:lease:0 (REC)
  [3] resp:receipt:1 (REC)
```

A SENTINEL denial (critical-service bait, gate G5.8's own path), `--ask "what did pocketsec
do about it?"`. The refused receipt is reported once, as a refusal, never as "it ran":

```
Alert 1 | INC-bait-031-000 | SYNTHETIC lab data
Question type: WHAT_ACTION (matched: do about, did pocketsec do)
- PocketSec's response planner decided ACT: act on the host. (as recorded by PocketSec) [1]
- This response ran on a simulated host, not a real machine. (as recorded by PocketSec) [1]
- The safety checker SENTINEL refused SUSPEND_PROCESS (REFUSED_SENTINEL; reasons: PRECONDITION and MISSION_INVARIANT). (as recorded by PocketSec) [2]
Note: Changes to a host are made only by PocketSec's response stage, behind its SENTINEL safety checks, or by a human operator working through that stage.
Sources:
  [1] resp:record (REC)
  [2] resp:denial:0 (REC)
```

## Measured on this machine (2026-09-27, Python 3.14.7)

| What | Result | How |
|---|---|---|
| Demo alert build | "4 alerts loaded in 1.50 s" and "... in 2.17 s" (`demo` banner, two runs the same day) | `python -m pocketsec.assistant.cli demo` |
| One-shot `--ask` wall time, cold process | 2.57 s, 2.19 s, 2.87 s | `/usr/bin/time -f "%e s %M KB" python -m pocketsec.assistant.cli --ask why --alert 1`, 3 runs |
| Peak RSS of that process | 32112 KB, 32256 KB, 32168 KB | same runs, `%M` |
| Intent table (the one the lexicon was tuned on) | 62 of 62 | `tests/test_assistant_intents.py::PHRASINGS`. Not a generalisation measure |
| The review's 96-question non-specialist set, before / after the review fixes | 64 of 96 / 89 of 96 | the reviewer's script, labels unchanged. The 7 misses after: "what should i do now" and "what now" go to the new `ADVICE` intent (the set labels them `HELP`); "what about #2" is deliberately not an alert reference (`#N` is a step); "how bad is it" and "who is the attacker" get a clarification; "what is a lineage" goes to `WHICH_PROCESS`; "and the other one?" is not understood. The fixed phrasings are now rows in `tests/test_assistant_review_fixes.py::HELD_OUT`, so this set is no longer held out |
| Dictionary words that typo tolerance rewrites into a keyword, before / after | 318 / 179 of 63993 (`/usr/share/dict/words`, lower-case alphabetic) | 115 of the 179 share their first four letters with the keyword ("alerts" to "alert"); the other 64 are mostly rare words ("flogs" to "flags"). Rules added: first letter must match, imperatives and undo verbs are exempt, short new keywords are never targets, common words found by the scan are exempt |
| Review mutants caught by the assistant test suite, before / after | 2 of 6 / 6 of 6 | the review's six template edits (UNK line exonerates, INF stated as certain, READ verb swapped, lineage rank inverted, step off by one, response unknown negated), each applied to a mirror of the repo and the suite run: 2 to 5 tests fail per mutant after the fixes |

## Limits, stated plainly

- **No real telemetry yet.** Demo alerts are SYNTHETIC: incidents 0, 1, 3 and 6 of Stage 4's
  `build_incident_corpus(count=10, seed=11)`, replayed through Stage 1 and the LUCID engine.
  The visibility model is fitted on that 10-case corpus (5 fitted, 5 held out), not the
  gate's 60, so shadow regions can differ from a full gate run.
- **Current Stage 4 verdicts say little.** Every demo alert is verdict UNKNOWN,
  identifiability UNKNOWN, confidence 0.0, uncertainty 1.0, with uniform-weight
  "unresolved novel mechanism" hypotheses. The assistant says so in those words rather than
  dressing it up. The substance of "why" comes from Stage 1's observed events, ranked by
  state change, and a note says the engine did not single them out.
- **No process names.** Stage 1 names processes by lineage (pid and start time). The program
  is known only when that lineage's own EXECUTE was observed; otherwise the answer says the
  name is unknown. There is no "web server" field.
- **No clock times.** The event record keeps order only.
- **No action for a real Stage 4 incident.** Stage 4 exports carry no target, so Stage 5
  proposes nothing for them. Response and undo answers for the demo alerts are therefore
  "unknown: no response record attached". Stage 5 receipts exist only for Stage 5's own
  fixture corpus, whose incident ids differ, and every one is SIMULATED.
- **Raw bytes are not kept.** Evidence is referenced by digest; a digest cannot be
  re-checked against bytes here.
- **The classifier is word lists.** Unusual phrasings get a clarification or "help", never a
  guess. Typo tolerance is one edit, on words of five or more letters, never changes the
  first letter, and common English words are exempt ("please" is not "lease", "locked" is
  not "blocked"). It still rewrites some rarer real words (179 in the word-list scan
  above).
- **"What should I do?" gets no advice.** The `ADVICE` answer repeats what PocketSec's
  hand-off asked for and says remediation advice is out of scope.

## Tests

```
PYTHONHASHSEED=0 python -m pytest -q tests/test_assistant_*.py
```

`test_assistant_intents.py` (phrasing table, clarification, typo rules, determinism),
`test_assistant_answers.py` (grounding of every sentence of every intent on every demo alert,
rendered-text parse-back, UNK never negated, INF always hedged, exact confidence, Stage 5
receipts and leases, the ground-truth tripwire), `test_assistant_safety.py` (refusals,
injection canaries, process/socket tripwires, import boundary, bounds),
`test_assistant_cli.py` (demo, `--ask`, `--json`, REPL, bundles, exit codes),
`test_assistant_review_fixes.py` (one or more regression tests per review finding G1-G9,
AUTH-1..3, ROBUST-1..2, DOC-1 and U1-U11; the G2 mutation tests inject the review's
template edits into the real builders and require every mutated sentence to be withheld).

## Review fixes (2026-09-27)

A grounding, authority and usability review reported 26 findings; each was reproduced before
it was fixed. The ones that changed what the explainer may say:

- **Guard (G1, G2).** Rule (d) now applies per clause with a narrow coverage-phrase
  exemption; numbers are whole tokens; step, process, verb, path and rank are checked
  against the cited event or lineage; INF may not be stated as settled. The review's
  surviving template mutants are now caught, and relation verbs plus golden lines for demo
  alert 4 are pinned in tests independently of the phrasing table.
- **Response record (G3, G4, G5).** "It ran X" only for receipts that reached the host, and
  a refusal is listed once; an expired lease with no recorded outcome is an unknown, not
  "no reversal was attempted"; `ResponseSummary.reasons` is now `truncations`, rendered as
  record truncation, never as the planner's reason.
- **Over-read enums (G6, G7, G8).** Identifiability UNKNOWN says only that no leading
  explanation was singled out, with a count of novel explanations from the hypotheses;
  each of Stage 4's four shadow reasons has its own wording (`Unknown.shadow_reason`);
  the causal gloss on confidence 0.0 is gone.
- **Alert switching (G9, U2).** Only "alert N", "incident N", "same for N" or a full
  incident id switch alerts, and a switch is announced; "what about alert 2" repeats the
  last question for alert 2.
- **Authority (AUTH-1..3).** See "What it refuses to do" above.
- **Robustness (ROBUST-1, ROBUST-2, DOC-1).** Non-ASCII or huge digit references are
  refused, not raised; bundles are read only from regular files, capped while reading;
  out-of-range numbers and deep nesting are load errors (exit 2) in plain words; the
  rendered-text check runs at runtime.
- **Usability (U1-U11).** See the intent table and the measurements above. Also: `/sources`
  and `--sources`, `/alerts` rows that say what each alert asked for, "That is all I can
  show for this question." when "tell me more" has nothing more, and plain CLI errors.
