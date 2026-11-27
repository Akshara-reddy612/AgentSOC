"""
experiments/p9b_precheck.py

P9 B design pre-check (2026-11-28, read-only): fleet prevalence in training of the plantable attack keys and of
the keys an honest analyst teaches on clean traffic (F_d4).  python -m experiments.p9b_precheck
"""
import json, sqlite3
from collections import Counter, defaultdict
from experiments.dedale_plant import attack_keys, PLANTABLE
from perception.host_detection import DETECTORS
from dedale import data_dir

def hf(src, dst, key, et):
    """(host-free pattern, host) of a detector edge, or None."""
    key = json.loads(key) if isinstance(key, str) and key.startswith('"') else key
    if et == "SPAWNED":
        return (et, src, dst), key.split(":", 1)[1].lower()
    if et in ("LOGON", "READS_LSASS", "USES_PIPE", "WRITES_FILE_TYPE"):
        return (et, src, key), dst.split(":", 1)[1].lower()
    if et == "RUNS_SCRIPT":
        return (et, dst), src.split(":", 1)[1].lower()
    return None

def edges(path, prov):
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    return c.execute("select src,dst,key,edge_type from edges where learned_from=?", (prov,)).fetchall()

KS = str(data_dir().parent / "ks") + "/"
train = defaultdict(set)
for s, d, k, et in edges(KS + "dedale_host_frozen.sqlite", "training"):
    r = hf(s, d, k, et)
    if r: train[r[0]].add(r[1])
print("training hosts with a detector pattern:", len({h for v in train.values() for h in v}),
      "| distinct host-free patterns:", len(train))

def others(p, host): return len(train.get(p, set()) - {host})

# 1. cost: what an honest analyst teaches on clean traffic (F_d4: oracle, 4 h, no plants)
an = [hf(*e) for e in edges(KS + "dedale_host_gated_analyst_F_d4.sqlite", "analyst")]
an = [r for r in an if r]
c = Counter(min(others(p, h), 3) for p, h in an)
print(f"\nclean analyst-taught detector keys (F_d4): {len(an)}; other training hosts with the pattern: "
      f"0={c[0]} 1={c[1]} 2={c[2]} >=3={c[3]}")
print("  by type, share with >=1 other host:",
      {t: f"{sum(1 for p,h in an if p[0]==t and others(p,h)>=1)}/{sum(1 for p,h in an if p[0]==t)}"
       for t in sorted({p[0] for p, h in an})})

# 2. attack: every plantable attack key, and the attack hosts that share its host-free pattern
ak = attack_keys(PLANTABLE)
rows, by_pat = [], defaultdict(set)
for (d, k), (t, e) in ak.items():
    ed = DETECTORS[d].edge(k)
    p, h = hf(ed.src, ed.dst, json.dumps(ed.key), ed.edge_type)
    rows.append((d, p, h, t)); by_pat[p].add(h)
c = Counter(min(others(p, h), 3) for d, p, h, t in rows)
print(f"\nplantable attack keys: {len(rows)} on hosts {sorted({h for _,_,h,_ in rows})}")
print(f"  other training hosts with the pattern: 0={c[0]} 1={c[1]} 2={c[2]} >=3={c[3]}")
print(f"  patterns used by the attack on >1 host (self-corroboration risk): "
      f"{sum(1 for v in by_pat.values() if len(v) > 1)} of {len(by_pat)}")
print("  attack keys whose pattern is in training elsewhere:")
for d, p, h, t in sorted(rows, key=lambda r: r[3]):
    if others(p, h):
        print(f"    {t:%m-%d %H:%M} {h:8} {d:16} others={others(p,h):2}  {str(p[1:])[:110]}")

# 3. R1b: count other-host sightings in the test period too (here: the same pattern taught by the analyst elsewhere)
taught = defaultdict(set)
for p, h in an: taught[p].add(h)
def others_b(p, h): return len((train.get(p, set()) | taught.get(p, set())) - {h})
for m in (1, 2):
    ok = sum(1 for p, h in an if others_b(p, h) >= m)
    print(f"\nR1b M={m}: clean analyst-taught keys still learnable {ok}/{len(an)} (R1 training-only: "
          f"{sum(1 for p,h in an if others(p,h)>=m)})")
