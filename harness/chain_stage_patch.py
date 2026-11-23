"""Test support: patch a name where the engagement stages look it up (ARC-9).

`investigate_engagement` used to be one function in `orchestrator_chain.py`, so a test
patched `harness.orchestrator_chain.<name>` and every use of the name followed. The body
now runs in the `orchestrator_chain_*` stage modules, each of which imports what it uses
explicitly; patching the old module would leave the stages on the real object, a patch that
silently does nothing. `chain_patch("<name>", new=...)` patches `<name>` in every chain
module that has it (an explicit import means the module uses it), and refuses when no
module does, so a renamed or unused target fails loudly instead of testing nothing.

`CHAIN_MODULES` is checked against the files on disk by `test_orchestrator_split_guard`.
Not product code: only tests import this module.
"""
from __future__ import annotations

import importlib
from unittest import mock

CHAIN_MODULES = (
    "orchestrator_chain",
    "orchestrator_chain_support",
    "orchestrator_chain_discovery",
    "orchestrator_chain_legs",
    "orchestrator_chain_worklist",
    "orchestrator_chain_coverage",
    "orchestrator_chain_finish",
)


def chain_modules_with(name: str) -> list[str]:
    """The chain modules whose namespace holds `name` (they import or define it)."""
    found = []
    for module in CHAIN_MODULES:
        if hasattr(importlib.import_module(f"harness.{module}"), name):
            found.append(module)
    return found


class chain_patch:
    """`mock.patch` over every chain module that has `name`; usable like a patcher
    (`with`, `start()`/`stop()`, `ExitStack.enter_context`)."""

    def __init__(self, name: str, new=mock.DEFAULT, **kwargs):
        modules = chain_modules_with(name)
        if not modules:
            raise AttributeError(f"no orchestrator_chain* module has {name!r}; patch where it is used")
        self.name = name
        self.modules = modules
        self._patchers = [mock.patch(f"harness.{m}.{name}", new, **kwargs) for m in modules]
        self._started: list = []

    def start(self):
        result = None
        try:
            for patcher in self._patchers:
                value = patcher.start()
                self._started.append(patcher)
                result = value if result is None else result
        except BaseException:
            self.stop()
            raise
        return result

    def stop(self):
        while self._started:
            self._started.pop().stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc_info):
        self.stop()
        return False
