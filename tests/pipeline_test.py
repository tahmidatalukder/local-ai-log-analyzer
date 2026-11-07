import sys, json; sys.path.insert(0, ".")
import analyzer as A
from logparse import *
P = sys.argv[1]
chunks = plan_chunks(P, 850); ents = Entities(); raw = []
nl = sum(1 for _ in open(P, "rb"))
for i, c in enumerate(chunks):
    lines = read_chunk(P, c); text = "\n".join(compact(parse(r), n, r) for n, r in lines)
    for n, r in lines: ents.update(parse(r), n)
    facts = ents.summary(); out, st = A.call_model(facts, text, retries=0)
    f, rep = A.parse_findings(out); raw += [x for x in (A.sanitize(a, nl) for a in f) if x]
    print(i + 1, f"L{c[2]}-{c[3]}", "est_tok", est_tokens(A.SYSTEM + facts + text), "findings", len(f), "repaired" if rep else "")
lk = {n: l for n, l in enumerate(open(P), 1)}
for r in A.merge(raw, ents, lk, nl): print(r["severity"], r["attack_type"], r["entity"], r["evidence_lines"][:8], r["source"])
print("\nFACTS:\n" + ents.summary(2000))
