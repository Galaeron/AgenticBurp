# ⚠ The bundled `harness/` in this kit is a STALE SNAPSHOT

`testing/blind-test-kit/harness/` is a **copied fork** of the main `harness/`
package, taken for self-contained hand-off to a blind tester. It has **drifted
badly** from the real harness (at last check ~14 validators here vs ~41 in the
real tree, and dozens of modules differ by weeks). **A blind run against this
copy does NOT describe the current tool.**

Before any run whose result should reflect the shipped code, refresh it:

```bash
cd testing/blind-test-kit
python sync_harness.py          # copies the repo's harness/ over the fork
```

Caveat: the current `harness/` package uses absolute imports
(`from harness import …`). After syncing, `harness_driver.py` must put the kit
**directory** (the parent of `harness/`) on `sys.path` and import
`from harness import orchestrator`, not insert `harness/` itself and `import
orchestrator`. If the driver still uses the old bare-import style, update it, or
run the driver from a checkout of the full repo instead of this isolated kit.

The long-term fix (tracked in [../../docs/LIMITATIONS.md](../../docs/LIMITATIONS.md))
is to stop vendoring a fork at all and have the kit import the real package.
