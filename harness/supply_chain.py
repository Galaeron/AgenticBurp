"""
Supply-chain inventory (P3-2): a CycloneDX SBOM of the harness's Python lockfiles
and tool images, and a check that tool images are pinned by digest.

Stdlib only and offline: it reads the committed requirement files and Dockerfiles,
never the network or the docker daemon. The output is deterministic for the same
inputs -- the serial number is derived from the content, and a timestamp is added
only when SOURCE_DATE_EPOCH (or --timestamp) asks for one -- so two runs on one
commit produce byte-identical SBOMs.

    python -m harness.supply_chain sbom [--out sbom.cdx.json]
    python -m harness.supply_chain images [--require-digest]

Vulnerability lookup is NOT done here (it needs the network); CI runs pip-audit
against harness/requirements.lock for that.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from harness.tool_runner import ImageReferenceError, parse_image_ref

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REQUIREMENTS = ("harness/requirements.lock", "harness/requirements-proxy.txt")
DEFAULT_DOCKERFILES = ("tools/sqlmap.Dockerfile", "tools/ffuf.Dockerfile")
SPEC_VERSION = "1.5"

_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[(?P<extras>[^\]]*)\])?\s*"
    r"(?P<spec>(?:[<>=!~]=?|===)[^;]*)?\s*(?:;\s*(?P<marker>.*))?$")


@dataclass(frozen=True)
class Requirement:
    name: str
    spec: str           # "" when unconstrained, else e.g. "==1.2.0" or ">=12.3.1"
    marker: str         # environment marker, "" when none
    source: str         # repo-relative file it came from

    @property
    def version(self) -> str | None:
        """The exact version for an `==` pin, else None."""
        m = re.fullmatch(r"===?\s*([^\s,]+)", self.spec)
        return m.group(1) if m else None


def normalize_name(name: str) -> str:
    """PEP 503 normalised project name (what a pkg:pypi purl uses)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path, *, root: Path = ROOT) -> list[Requirement]:
    """Parse a pip requirements file. Comments, blank lines and pip options are
    skipped; `-r other.txt` includes are NOT followed (each lockfile is listed
    explicitly, so the inventory never depends on include order)."""
    rel = _rel(path, root)
    out: list[Requirement] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if not m:
            raise ValueError(f"{rel}: cannot parse requirement {line!r}")
        out.append(Requirement(name=m.group("name"), spec=(m.group("spec") or "").strip(),
                               marker=(m.group("marker") or "").strip(), source=rel))
    return out


def dockerfile_base_images(path: Path) -> list[str]:
    """The image reference of every `FROM` line (build-stage aliases excluded)."""
    images: list[str] = []
    stages: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        parts = raw.strip().split()
        if len(parts) < 2 or parts[0].upper() != "FROM":
            continue
        args = [p for p in parts[1:] if not p.startswith("--")]
        if not args:
            continue
        ref = args[0]
        if len(args) >= 3 and args[1].upper() == "AS":
            stages.add(args[2].lower())
        if ref.lower() not in stages:
            images.append(ref)
    return images


def image_pin_report(dockerfiles: list[Path], *, root: Path = ROOT) -> list[dict]:
    """One row per base image: file, reference, pinned, and any parse error."""
    rows = []
    for path in dockerfiles:
        for ref in dockerfile_base_images(path):
            row = {"file": _rel(path, root), "image": ref, "pinned": False, "error": None}
            try:
                row["pinned"] = parse_image_ref(ref).pinned
            except ImageReferenceError as exc:
                row["error"] = str(exc)
            rows.append(row)
    return rows


def _purl(req: Requirement) -> str | None:
    return f"pkg:pypi/{normalize_name(req.name)}@{req.version}" if req.version else None


def _image_component(ref: str, source: str) -> dict:
    parsed = parse_image_ref(ref)
    comp: dict = {"type": "container", "name": parsed.name or ref,
                  "bom-ref": f"image:{ref}",
                  "properties": [{"name": "harness:source", "value": source},
                                 {"name": "harness:pinned", "value": str(parsed.pinned).lower()}]}
    if parsed.tag:
        comp["version"] = parsed.tag
    if parsed.digest:
        comp["hashes"] = [{"alg": "SHA-256", "content": parsed.digest.split(":", 1)[1]}]
    return comp


def build_sbom(requirement_files: list[Path], dockerfiles: list[Path] = (), *,
               root: Path = ROOT, timestamp: str | None = None) -> dict:
    """A CycloneDX 1.5 JSON document. A package that appears in several files
    becomes one component per distinct (name, spec, marker), each listing its
    sources, so a looser proxy constraint is not hidden behind the lock pin."""
    merged: dict[tuple, dict] = {}
    for path in requirement_files:
        for req in parse_requirements(path, root=root):
            key = (normalize_name(req.name), req.spec, req.marker)
            entry = merged.setdefault(key, {"req": req, "sources": []})
            if req.source not in entry["sources"]:
                entry["sources"].append(req.source)
    components = []
    for key in sorted(merged):
        req, sources = merged[key]["req"], merged[key]["sources"]
        comp: dict = {"type": "library", "name": normalize_name(req.name)}
        purl = _purl(req)
        comp["bom-ref"] = purl or f"req:{key[0]}{req.spec}{';' + req.marker if req.marker else ''}"
        if req.version:
            comp["version"] = req.version
            comp["purl"] = purl
        props = [{"name": "harness:source", "value": s} for s in sources]
        if not req.version:
            props.append({"name": "harness:constraint", "value": req.spec or "(unconstrained)"})
        if req.marker:
            props.append({"name": "harness:marker", "value": req.marker})
        comp["properties"] = props
        components.append(comp)
    for path in dockerfiles:
        for ref in dockerfile_base_images(path):
            components.append(_image_component(ref, _rel(path, root)))

    body = json.dumps(components, sort_keys=True).encode("utf-8")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "agenticvibe-sbom:" + hashlib.sha256(body).hexdigest())
    metadata: dict = {"component": {"type": "application", "name": "agenticvibe-harness",
                                    "bom-ref": "agenticvibe-harness"},
                      "tools": {"components": [{"type": "application",
                                                "name": "harness.supply_chain"}]}}
    if timestamp:
        metadata["timestamp"] = timestamp
    return {"bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
            "serialNumber": f"urn:uuid:{serial}", "version": 1,
            "metadata": metadata, "components": components}


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _timestamp(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness.supply_chain")
    sub = parser.add_subparsers(dest="command", required=True)
    sbom = sub.add_parser("sbom", help="emit a CycloneDX SBOM (JSON)")
    sbom.add_argument("--requirements", nargs="*", default=list(DEFAULT_REQUIREMENTS))
    sbom.add_argument("--dockerfiles", nargs="*", default=list(DEFAULT_DOCKERFILES))
    sbom.add_argument("--timestamp", default=None)
    sbom.add_argument("--out", default=None, help="write here instead of stdout")
    images = sub.add_parser("images", help="report whether Dockerfile base images are digest-pinned")
    images.add_argument("--dockerfiles", nargs="*", default=list(DEFAULT_DOCKERFILES))
    images.add_argument("--require-digest", action="store_true",
                        help="exit 1 when any base image is not pinned by digest")
    args = parser.parse_args(argv)

    if args.command == "sbom":
        doc = build_sbom([ROOT / p for p in args.requirements],
                         [ROOT / p for p in args.dockerfiles],
                         timestamp=_timestamp(args.timestamp))
        text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(text)
        return 0

    rows = image_pin_report([ROOT / p for p in args.dockerfiles])
    for row in rows:
        state = "ERROR" if row["error"] else ("pinned" if row["pinned"] else "UNPINNED")
        print(f"{state:8} {row['file']}: {row['image']}" + (f" ({row['error']})" if row["error"] else ""))
    if any(r["error"] for r in rows):
        return 2
    if args.require_digest and not all(r["pinned"] for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
