"""
Detection fixture cache -- the thing that makes the detection benchmark swift.

It stores each LLM agent's raw findings per exchange, keyed by
    (label, agent, model, prompt_version)
so re-running the benchmark only pays real LLM cost for agents whose PROMPT or
MODEL actually changed. Everything else is read from a JSON cache in
milliseconds. This works because the agents are deterministic at temperature
0.1 (measured: identical output across repeated runs) -- identical input gives
identical output, so a cached answer is a valid answer.

Key facts a future editor must know:
 - The cache key includes `prompt_version` = sha256 of the agent's SYSTEM
   prompt. So editing an agent's prompt AUTOMATICALLY invalidates only that
   agent -- a normal bench run then re-runs just it. You do not need a flag.
 - The key also includes `model`, so swapping an agent's model invalidates it.
 - The key does NOT capture changes to SHARED code the prompt hash can't see
   (base_agent user-prompt template, security.redact_headers, truncation). For
   those, force a refresh: bench.py --refresh all (or --refresh <agent>).
 - The `anomaly` agent is deterministic pure-Python and cheap, so it is NEVER
   cached -- callers run it live every time.

Safety: agents are called directly (agent.run), so NO validators, NO mutating
replay, NO autonomous discovery ever fire -- this sends no traffic to any
target. State/cache DBs are redirected to temp files.

CLI:  python detection_fixture.py build            # pre-warm the default set
      python detection_fixture.py build --smoke     # just the 8-exchange smoke set
      python detection_fixture.py build --samples 2 # run each pair twice, flag flaky ones
      python detection_fixture.py stats             # show what's cached
"""
import asyncio, json, os, sys, argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS_DIR = PROJECT_ROOT / "harness"
sys.path.insert(0, str(PROJECT_ROOT))

from harness import store
store._DB_PATH = r"C:\tmp\detbench_state.db"
from harness import cache
cache.init_cache(db_path=r"C:\tmp\detbench_cache.db")

import yaml
from harness import fast_path
from harness.orchestrator import Orchestrator
from harness.models import HttpExchange

EXCHANGES_PATH = r"C:\tmp\pixelmart_exchanges.json"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixture"
FIXTURE_DIR.mkdir(exist_ok=True)
CACHE_PATH = FIXTURE_DIR / "detection_fixture.json"
MAX_BODY = 6000

# Smoke set: one TP per major class + the two nastiest true negatives.
SMOKE_LABELS = {"TP1", "TP3", "TP5", "TP7", "TP9", "TP10", "TN4", "TN5"}

cfg = yaml.safe_load(open(HARNESS_DIR / "config.yaml"))
cfg.setdefault("validators", {})["active_enabled"] = False
cfg["validators"]["allow_mutating_replay"] = False
cfg.setdefault("autonomous_discovery", {})["enabled"] = False
orch = Orchestrator(cfg)
AVAIL = set(orch.agent_manager.get_enabled_agents())

_raw = json.load(open(EXCHANGES_PATH))
EXCHANGES_BY_LABEL = {e["label"].split(":")[0].strip(): e for e in _raw
                      if e["label"][:2] in ("TP", "TN")}

def label_prefix(lab): return lab.split(":")[0].strip()

def make_exchange(e):
    return HttpExchange(url=e["url"], method=e["method"], request_headers=e["request_headers"],
                        request_body=e["request_body"], response_status=e["response_status"],
                        response_headers=e["response_headers"], response_body=e["response_body"])

def _load_cache():
    if CACHE_PATH.exists():
        return json.load(open(CACHE_PATH))
    return {}

def _save_cache(c):
    json.dump(c, open(CACHE_PATH, "w"), indent=1)

CACHE = _load_cache()

def _finding_dict(f):
    return {"class": f.vulnerability_class, "confidence": f.confidence,
            "severity": f.severity, "basis": f.basis, "summary": (f.summary or "")[:120]}

def _key(label, agent, model, pver):
    return f"{label}||{agent}||{model}||{pver}"

async def findings_for(agent_name, label, refresh=False):
    """Return this agent's findings on the exchange for `label`, from cache if
    the (agent, model, prompt) is unchanged, otherwise by running it live and
    caching the result. The anomaly agent is always run live (never cached)."""
    e = EXCHANGES_BY_LABEL[label]
    ex = make_exchange(e)
    agent = orch.agent_manager.get_agent(agent_name)
    if agent is None:
        return []
    rep = None
    if agent_name == "anomaly":
        rep = await agent.run(ex, MAX_BODY, "", None)
        return [_finding_dict(f) for f in rep.findings]
    model = getattr(agent, "model", "?")
    pver = agent._prompt_version()
    k = _key(label, agent_name, model, pver)
    if not refresh and k in CACHE:
        return CACHE[k]["findings"]
    rep = await agent.run(ex, MAX_BODY, "", None)
    fnds = [_finding_dict(f) for f in rep.findings]
    CACHE[k] = {"findings": fnds, "model": model, "prompt_version": pver,
                "error": rep.raw_error, "stable": None}
    _save_cache(CACHE)
    return fnds

def dispatch_for(label):
    """fast_path dispatch set for this exchange (deterministic, no LLM)."""
    ex = make_exchange(EXCHANGES_BY_LABEL[label])
    agents, _ = fast_path.select_fast_path_agents(ex, AVAIL)
    return set(agents) if agents else set(AVAIL)

async def build(labels, agents=None, samples=1):
    """Pre-warm the cache. For each label, run the given agents (default: that
    label's fast_path dispatch set, minus anomaly). With samples=2, run each
    pair twice and record a `stable` flag if the finding classes match."""
    for label in labels:
        target_agents = agents if agents else sorted(dispatch_for(label) - {"anomaly"})
        for a in target_agents:
            fnds = await findings_for(a, label, refresh=True)
            classes1 = sorted(f["class"] for f in fnds)
            stable = None
            if samples >= 2:
                fnds2 = await findings_for(a, label, refresh=True)
                classes2 = sorted(f["class"] for f in fnds2)
                stable = (classes1 == classes2)
                agent = orch.agent_manager.get_agent(a)
                k = _key(label, a, getattr(agent, "model", "?"), agent._prompt_version())
                if k in CACHE:
                    CACHE[k]["stable"] = stable
                    _save_cache(CACHE)
            flag = "" if stable is None else ("  stable" if stable else "  *** FLAKY ***")
            print(f"  {label:6} {a:20} findings={len(fnds)}{flag}")

def stats():
    print(f"cache: {CACHE_PATH}  entries={len(CACHE)}")
    flaky = [k for k, v in CACHE.items() if v.get("stable") is False]
    if flaky:
        print(f"FLAKY (non-deterministic) pairs -- do not trust cached, re-run with --refresh:")
        for k in flaky:
            print("   " + k)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "stats"])
    ap.add_argument("--smoke", action="store_true", help="only the 8-exchange smoke set")
    ap.add_argument("--agents", default="", help="comma list; default = each label's fast_path set")
    ap.add_argument("--samples", type=int, default=1, help="2 = run each pair twice and flag flaky")
    args = ap.parse_args()
    if args.cmd == "stats":
        stats()
    else:
        labels = sorted(SMOKE_LABELS) if args.smoke else sorted(EXCHANGES_BY_LABEL)
        agents = [a.strip() for a in args.agents.split(",") if a.strip()] or None
        asyncio.run(build(labels, agents, args.samples))
        print("done.")
