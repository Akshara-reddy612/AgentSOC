#!/usr/bin/env bash
# Live queue for the paper checklist runs (2026-11-22; budget: see experiments/CHECKLIST_LIVE_RUNS.md).
# Usage (repo root, Git Bash):   bash tools/live_queue.sh            # runs every job in JOBS below, resumable
#
# Each job runs agent/run_v2_prompt_defences on the first 300 GUIDE dev alerts (the 150 pairs of T2.2), so every
# result is paired with the recorded undefended answers on the same pairs. The daily Gemini quota is per Google
# project and one exhausted key stops a whole run, so each round first probes every key (one tiny call each, 90 s
# limit), runs on the keys that answered, and starts a new round when a run stops on quota. It ends when nothing
# is missing or no key answers. ONE copy only. Stop it with taskkill /T /F on its bash.exe PID (stopping the
# background task alone does not stop this script on Windows). Keys are never printed.
cd "$(dirname "$0")/.." || exit 1
export HF_HUB_OFFLINE=1
export PYTHONPATH="$PWD"
PY=.venv/Scripts/python.exe
JOBS=(
  "telemetry"                       # A6: undefended agent + the pipeline's trusted context
  "none --temperature 0.7 --repeat 1"   # B1: repeat runs at temperature 0.7
  "none --temperature 0.7 --repeat 2"
  "none --temperature 0.7 --repeat 3"
)
[ $# -gt 0 ] && JOBS=("$@")         # e.g.  bash tools/live_queue.sh telemetry   runs that job only
results_file() {   # results path for a job, via the runner's own naming
  $PY -c "
import sys
from agent.run_v2_prompt_defences import results_path
a = sys.argv[1].split(); t = float(a[a.index('--temperature') + 1]) if '--temperature' in a else None
r = int(a[a.index('--repeat') + 1]) if '--repeat' in a else None
st = a[a.index('--set') + 1] if '--set' in a else 'dev'
print(results_path(st, a[0], t, r))" "$1"
}
missing() {        # alerts among the first 300 (B1 repeats: 100, 2026-11-23) without a verdict in the given results file
  $PY -c "
import json, os, sys
st = 'heldout' if 'v2_heldout_' in sys.argv[1] else 'dev'
alerts = json.load(open(f'GUIDE_Dataset/processed/v2/guide_v2_{st}.json', encoding='utf-8'))[:100 if '_promptdef_none_t' in sys.argv[1] else 300]
p = sys.argv[1]
done = {r['alert_id']: r for r in json.load(open(p, encoding='utf-8'))} if os.path.exists(p) else {}
print(sum(1 for a in alerts if 'verdict' not in done.get(a['alert_id'], {})))" "$1"
}
working_keys() {   # comma-separated keys that answer a tiny request within 90 s (stdout only, never echoed)
  $PY -c "
import concurrent.futures as cf, os, sys
from dotenv import dotenv_values
from google import genai
ks = [k.strip() for k in (dotenv_values('.env').get('GEMINI_API_KEYS') or '').split(',') if k.strip()]
def ok(k):
    try:
        c = genai.Client(api_key=k)
        c.models.generate_content(model='gemini-3.1-flash-lite', contents='Reply with the word ok.')
        return True
    except Exception:
        return False
ex = cf.ThreadPoolExecutor(len(ks))
futs = {ex.submit(ok, k): k for k in ks}
done, _ = cf.wait(futs, timeout=90)
good = [futs[f] for f in futs if f in done and f.result()]
sys.stdout.write(','.join(good)); sys.stdout.flush()
os._exit(0)" 2>/dev/null
}
total_missing() { local t=0; for j in "${JOBS[@]}"; do t=$((t + $(missing "$(results_file "$j")"))); done; echo $t; }

for round in 1 2 3 4 5 6 7 8 9 10; do
  tm=$(total_missing)
  [ "$tm" -eq 0 ] && { echo "$(date -u +%H:%M) all jobs complete"; exit 0; }
  GEMINI_API_KEYS="$(working_keys)"; export GEMINI_API_KEYS
  nk=$(echo -n "$GEMINI_API_KEYS" | tr ',' '\n' | grep -c .)
  echo "$(date -u +%H:%M) round $round: $tm alerts missing; $nk keys answer"
  [ "$nk" -eq 0 ] && { echo "no key answers: stop until the quota reset (~08:00 UTC)"; exit 3; }
  for j in "${JOBS[@]}"; do
    n=$(missing "$(results_file "$j")"); [ "$n" -eq 0 ] && continue
    echo "$(date -u +%H:%M)   [$j]: $n to do, $nk workers"
    $PY tools/run_fast.py --defence $j --workers "$nk" --limit "$n" >> "logs/live_$(echo "$j" | tr ' .-' '___').txt" 2>&1
    rc=$?; echo "$(date -u +%H:%M)   end [$j] rc=$rc ($(missing "$(results_file "$j")") still missing)"
    [ $rc -eq 3 ] && break
  done
done
echo "$(date -u +%H:%M) 10 rounds used; stopping"
