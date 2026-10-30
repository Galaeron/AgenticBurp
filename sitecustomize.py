# Verification-only (untracked): drop the venv's editable-install finder so a
# module missing from this worktree fails here instead of loading from the
# main checkout.
import sys
sys.meta_path[:] = [f for f in sys.meta_path if "Editable" not in getattr(f, "__name__", "")]
sys.path_hooks[:] = [h for h in sys.path_hooks if "Editable" not in getattr(h, "__name__", "")]
