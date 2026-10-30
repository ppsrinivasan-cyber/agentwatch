"""Evaluate detections against the ground-truth `_label` field in the sample dataset.

    python scripts/evaluate.py [data/sample_agent_activity.ndjson]

attack     -> must raise >= 1 alert (recall)
benign     -> must raise 0 alerts   (false positives)
suspicious -> informational; either outcome is acceptable
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agentwatch.engine import Engine  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "data",
                                                           "sample_agent_activity.ndjson")
events = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
eng = Engine(output_dir=tempfile.mkdtemp(), respond=False)
by_event = {}
for e in events:
    by_event[e["event_id"]] = eng.process(e)["alerts"]

tp = fn = fp = tn = 0
missed, noisy = [], []
for e in events:
    n = len(by_event[e["event_id"]])
    lab = e.get("_label", "benign")
    if lab == "attack":
        tp += n > 0
        fn += n == 0
        if n == 0:
            missed.append(e["event_id"])
    elif lab == "benign":
        fp += n > 0
        tn += n == 0
        if n:
            noisy.append(e["event_id"])
print(f"events={len(events)} alerts={len(eng.alerts)}")
print(f"attack events detected : {tp}/{tp + fn}  (recall {tp / max(tp + fn, 1):.0%})")
print(f"benign events clean    : {tn}/{tn + fp}  (false-positive rate {fp / max(tn + fp, 1):.0%})")
if missed:
    print("missed:", missed)
if noisy:
    print("false positives:", noisy)
sys.exit(1 if (missed or noisy) else 0)
