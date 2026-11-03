"""Live check (real Docker, real harness/ffuf:2.1.0): ffuf inside a run reaches the
loopback ToolProxy as host.docker.internal and every request it sends is charged.
Target: the owned SPA catch-all fixture on 127.0.0.1. Prints counts only."""
import asyncio
import sys

from harness.api_surface_discovery import SurfaceDiscovery
from harness.run_context import RunContext
from harness.test_discovery_spa_wildcards import _SpaCatchAll


def main(wordlist: str) -> int:
    target = _SpaCatchAll()
    try:
        run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=20000)
        disc = SurfaceDiscovery(target.base, allowed_hosts=["127.0.0.1"], max_probes=3000,
                                run_context=run, ffuf_in_runs=True, ffuf_wordlist=wordlist)

        async def go():
            try:
                async with run:
                    return await asyncio.wait_for(disc.discover(), 600)
            finally:
                await run.aclose()
        result = asyncio.run(go())
        ffuf_notes = [e for e in result.errors if "ffuf" in e]
        print(f"wordlist={wordlist} ffuf_requests={result.ffuf_requests} "
              f"probes_sent={result.probes_sent} budget_used={run.budget.used} "
              f"target_gets={len(target.requests)} routes={len(result.routes)} "
              f"disagreements={result.ffuf_soft404_disagreements}")
        for note in ffuf_notes:
            print("note:", note[:200])
        ok = result.ffuf_requests > 0 and run.budget.used == result.probes_sent \
            and len(target.requests) <= run.budget.used
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        target.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "harness"))
