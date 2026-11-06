"""Live check of ffuf_runner.pin_image against the real local image (no target traffic).

Run from the repo root: PYTHONPATH=. python .test-work/budget-evidence-20261103/live_ffuf_pin_check.py
"""
import harness
from harness import ffuf_runner, tool_runner

assert "worktrees" in harness.__file__, harness.__file__
lines = []
pinned, why = ffuf_runner.pin_image("harness/ffuf:2.1.0")
lines.append(f"tag -> {pinned} ({why})")
ok = pinned is not None and tool_runner.verify_pinned_digest(pinned)[0]
lines.append(f"pinned ID verifies locally: {ok}")
image_id, repo = tool_runner.local_image_digests("harness/ffuf:2.1.0")
for ref in repo:
    p, w = ffuf_runner.pin_image(ref)
    lines.append(f"repo digest {ref} -> {'PASS' if p == ref else 'FAIL'} ({w})")
bad = "harness/ffuf@sha256:" + "0" * 64
p, w = ffuf_runner.pin_image(bad)
lines.append(f"wrong digest -> {'PASS (refused)' if p is None else 'FAIL'} ({w})")
try:
    tool_runner.ToolBroker(image="harness/ffuf:2.1.0", timeout=5, require_digest=True)
    lines.append("broker with unpinned tag -> FAIL (accepted)")
except tool_runner.ImageReferenceError:
    lines.append("broker with unpinned tag -> PASS (refused)")
print("\n".join(lines))
