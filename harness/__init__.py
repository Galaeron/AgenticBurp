"""harness -- the agentic-AI-pentesting harness package.

W-18 package restructure: the modules here were historically flat top-level
imports (`import store`, `from models import ...`), which worked only because the
harness/ directory sat on sys.path. They now form a proper importable package with
absolute `harness.*` imports, so the harness is pip-installable and its namespace
no longer collides with the top level. Run the test suite from the repository root:

    python -m unittest discover -t . -s harness -p "test_*.py"
"""
from __future__ import annotations

__version__ = "0.1.0"
