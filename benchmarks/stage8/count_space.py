import sys, time
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from pocketsec.stage8.labs.discovery_corpus import build_discovery_corpus, CorpusArm
from pocketsec.stage8.episode import Split
from pocketsec.stage8.genome.grammar import StepPredicate, Mechanism, MechanismRelation, Modifier, GrammarError
c = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
train = c.episodes(Split.TRAIN)
sig = {(s.relation, s.object_property_mask, s.state_delta_mask) for e in train for s in e.steps}
preds = set()
for r, p, d in sig:
    pb = [0] + [1 << i for i in range(p.bit_length()) if p >> i & 1]
    db = [0] + [1 << i for i in range(d.bit_length()) if d >> i & 1]
    for x in pb:
        for y in db:
            preds.add((r, x, y))
print("observed signatures", len(sig), "predicates (<=1 prop, <=1 raised)", len(preds))
P = [StepPredicate(r, x, 0, y) for r, x, y in sorted(preds)]
n = 0
for a in P:
    for b in P:
        if a == b: continue
        for rel in (MechanismRelation.PRECEDES, MechanismRelation.CO_OCCURS, MechanismRelation.WITHOUT):
            try: Mechanism(rel, (a, b)); n += 1
            except GrammarError: pass
print("pair mechanisms (incl. CO_OCCURS both orders)", n, "approx unique", n)
steps = sum(len(e.steps) for e in train)
print("train episodes", len(train), "steps", steps, "mean steps", steps/len(train))
t=time.perf_counter(); m = Mechanism(MechanismRelation.PRECEDES,(P[0],P[1]))
for _ in range(20):
    for e in train: m.matches(e.steps)
print("per matches call us", (time.perf_counter()-t)/20/len(train)*1e6)
