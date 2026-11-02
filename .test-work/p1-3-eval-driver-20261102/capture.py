import json
from harness.eval_repeat import EvalReport, EvalRun, run_repeated
FIX = {
 "varied5": ([0.8,0.7,0.75,0.72,0.78],[0.6]*5),
 "lucky": ([0.95,0.70,0.70,0.70,0.70],[0.6]*5),
 "highvar": ([1.0,0.6,1.0,0.6,0.8],[0.7]*5),
 "stable": ([0.82,0.81,0.83,0.80,0.82],[0.6,0.61,0.59,0.6,0.6]),
 "single": ([0.123456789],[0.987654321]),
 "thirds": ([1/3,2/3,1/7],[1/9,5/11,3/13]),
 "empty": ([],[]),
}
out = {}
for k,(r,p) in FIX.items():
    rep = EvalReport(runs=[EvalRun(recall=a, precision=b, seed=i) for i,(a,b) in enumerate(zip(r,p))], recall_floor=0.75, precision_floor=0.5)
    out[k] = {"summary": rep.summary(), "floor": list(rep.passes_floor())}
print(json.dumps(out, sort_keys=True))
