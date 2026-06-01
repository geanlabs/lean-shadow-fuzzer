#!/usr/bin/env python3
"""Execute and render Jupyter notebooks for completed fuzzer runs.

Usage:
    python scripts/render_notebooks.py --run-dir fuzzer-output/truthful-metal-dingo
    python scripts/render_notebooks.py --all
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NOTEBOOKS_DIR = REPO_ROOT / "notebooks"
SITE_RENDERED_DIR = REPO_ROOT / "site" / "rendered"
MANIFEST_PATH = SITE_RENDERED_DIR / "manifest.json"


def _load_manifest() -> dict:
    if MANIFEST_PATH.is_file():
        data = json.loads(MANIFEST_PATH.read_text())
        if "runs" not in data:
            data["runs"] = {}
        return data
    return {"runs": {}}


def _save_manifest(manifest: dict) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))


def _find_notebooks() -> list[Path]:
    """Find all .ipynb files in notebooks/ directory."""
    if not NOTEBOOKS_DIR.is_dir():
        print(f"ERROR: {NOTEBOOKS_DIR} not found", file=sys.stderr)
        sys.exit(1)
    return sorted(NOTEBOOKS_DIR.glob("*.ipynb"))


def _decode_numpy_binary(obj: dict) -> list:
    """Decode a numpy binary-serialized value {"bdata": "...", "dtype": "..."} to a plain list."""
    import base64
    import struct

    bdata = obj["bdata"]
    dtype = obj.get("dtype", "f8")

    raw = base64.b64decode(bdata)

    # Map numpy dtype names to struct format chars + item size
    # Supports both single-char (b, h, i, l, f, d) and numpy names (i1, i2, i4, f4, f8, etc.)
    _DTYPE_MAP = {
        # Single-char aliases
        "b": ("b", 1),   "B": ("B", 1),
        "h": ("h", 2),   "H": ("H", 2),
        "i": ("i", 4),   "I": ("I", 4),
        "l": ("l", 8),   "L": ("L", 8),
        "f": ("f", 4),   "d": ("d", 8),
        "e": ("e", 2),
        # Numpy dtype names: type + byte size
        "i1": ("b", 1),  "u1": ("B", 1),
        "i2": ("h", 2),  "u2": ("H", 2),
        "i4": ("i", 4),  "u4": ("I", 4),
        "i8": ("l", 8),  "u8": ("L", 8),
        "f2": ("e", 2),
        "f4": ("f", 4),
        "f8": ("d", 8),
        "bool": ("b", 1),
    }

    # Handle endianness prefix
    if dtype[0] in ("<", ">", "|"):
        byte_order = dtype[0]
        dtype_core = dtype[1:]
    else:
        byte_order = "<"  # default little-endian
        dtype_core = dtype

    info = _DTYPE_MAP.get(dtype_core)
    if not info:
        # Fallback: try to treat as float64
        info = ("d", 8)

    fmt_char, item_size = info
    count = len(raw) // item_size
    fmt = f"{byte_order}{count}{fmt_char}"
    return list(struct.unpack(fmt, raw))


def _sanitize_plotly_json(obj):
    """Recursively convert numpy binary-encoded values to plain JSON-compatible lists."""
    if isinstance(obj, dict):
        # Check if this is a numpy binary blob
        if "bdata" in obj and ("dtype" in obj or "shape" in obj or len(obj) <= 3):
            try:
                return _decode_numpy_binary(obj)
            except Exception:
                pass  # Fall through to treat as regular dict
        return {k: _sanitize_plotly_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_plotly_json(item) for item in obj]
    return obj


def _convert_plotly_outputs(nb: "nbformat.NotebookNode") -> None:
    """Convert Plotly JSON outputs to embedded HTML divs with Plotly.js calls."""
    import uuid
    
    for cell in nb.cells:
        if cell.cell_type != "code":
            continue
        outputs = cell.get("outputs", [])
        for output in outputs:
            if output.get("output_type") not in ("display_data", "execute_result"):
                continue
            data = output.get("data", {})
            plotly_json = data.get("application/vnd.plotly.v1+json")
            if plotly_json:
                # Sanitize: convert numpy binary data to plain arrays for Plotly.js
                sanitized = _sanitize_plotly_json(plotly_json)
                div_id = f"plotly-{uuid.uuid4().hex[:8]}"
                html = (
                    f'<div id="{div_id}" class="plotly-graph-div" '
                    f'style="height:100%; width:100%;"></div>\n'
                    f'<script>Plotly.newPlot("{div_id}", '
                    f'{json.dumps(sanitized)});</script>'
                )
                data["text/html"] = html


def render_run(run_dir: Path) -> None:
    """Execute and render notebooks for a single run."""
    import papermill
    import nbformat
    from nbconvert import HTMLExporter

    metadata_path = run_dir / "run-metadata.json"
    if not metadata_path.is_file():
        print(f"  SKIP: no run-metadata.json in {run_dir}", file=sys.stderr)
        return

    metadata = json.loads(metadata_path.read_text())
    run_id = metadata.get("run_id", run_dir.name)

    stats_path = run_dir / "stats.json"
    if not stats_path.is_file():
        print(f"  SKIP: no stats.json in {run_dir} (run may not be complete)", file=sys.stderr)
        return

    print(f"  Rendering notebooks for run: {run_id}")

    output_dir = SITE_RENDERED_DIR / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = _load_manifest()
    rendered_notebooks = {}

    for notebook_path in _find_notebooks():
        notebook_id = notebook_path.stem
        print(f"    Executing {notebook_path.name}...")

        executed_path = output_dir / f"{notebook_id}.ipynb"
        try:
            papermill.execute_notebook(
                str(notebook_path),
                str(executed_path),
                parameters={"run_dir": str(run_dir.resolve()), "run_id": run_id},
                kernel_name="python3",
                request_save_on_cell_execute=False,
            )
        except papermill.PapermillExecutionError as e:
            print(f"    WARNING: Notebook execution error in {notebook_id}: {e}", file=sys.stderr)

        # Convert to HTML
        html_path = output_dir / f"{notebook_id}.html"
        with open(executed_path) as f:
            nb = nbformat.read(f, as_version=4)

        # Pre-process: convert Plotly JSON outputs to embedded HTML divs
        _convert_plotly_outputs(nb)

        exporter = HTMLExporter()
        exporter.template_name = "classic"
        body, _ = exporter.from_notebook_node(nb)

        # Inject Plotly.js CDN so embedded plots render
        plotly_cdn = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

        # Inject CSS + toggle to hide code cells by default
        _CODE_TOGGLE_CSS = """<style>
/* Hide code input cells by default */
.jp-InputArea, .input { display: none !important; }
/* Leave output cells visible */
.jp-OutputArea, .output_wrapper, .output { display: block !important; }
/* Toggle button */
.code-toggle-btn {
    position: fixed; top: 12px; right: 16px; z-index: 9999;
    padding: 6px 14px; font-size: 12px; font-family: system-ui, sans-serif;
    background: var(--muted, #f0f0f0); color: var(--muted-foreground, #333);
    border: 1px solid var(--border, #ddd); border-radius: 6px; cursor: pointer;
    opacity: 0.7; transition: opacity 0.15s;
}
.code-toggle-btn:hover { opacity: 1; }
/* When code is shown */
body.show-code .jp-InputArea, body.show-code .input { display: block !important; }
</style>
<script>
document.addEventListener('DOMContentLoaded', function() {
    var btn = document.createElement('button');
    btn.className = 'code-toggle-btn';
    btn.textContent = 'Show code';
    btn.onclick = function() {
        document.body.classList.toggle('show-code');
        btn.textContent = document.body.classList.contains('show-code') ? 'Hide code' : 'Show code';
    };
    document.body.appendChild(btn);
});
</script>"""

        if "Plotly.newPlot" in body:
            body = body.replace(
                '<div class="plotly-graph-div"',
                f'{plotly_cdn}\n{_CODE_TOGGLE_CSS}\n<div class="plotly-graph-div"',
                1,
            )
        else:
            body = body.replace('</body>', f'{plotly_cdn}\n{_CODE_TOGGLE_CSS}\n</body>', 1)

        html_path.write_text(body, encoding="utf-8")
        print(f"    -> {html_path}")

        # Clean up executed notebook
        executed_path.unlink(missing_ok=True)

        rendered_notebooks[notebook_id] = {
            "html_path": f"{run_id}/{notebook_id}.html",
        }

    # Update manifest
    manifest["runs"][run_id] = {
        "rendered_at": datetime.now(timezone.utc).isoformat(),
        "notebooks": rendered_notebooks,
        "metadata": {
            "total_nodes": metadata.get("simulation", {}).get("total_nodes"),
            "clients": metadata.get("node_counts", {}),
            "status": "complete",
            "duration_secs": metadata.get("fuzzer", {}).get("duration_secs"),
            "runner": metadata.get("fuzzer", {}).get("runner"),
            "seed": metadata.get("fuzzer", {}).get("seed"),
        },
    }
    _save_manifest(manifest)
    print(f"  Updated manifest for {run_id}")


def render_all(output_dir: Path) -> None:
    """Render notebooks for all completed runs in output directory."""
    if not output_dir.is_dir():
        print(f"ERROR: {output_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    run_dirs = sorted(
        d for d in output_dir.iterdir()
        if d.is_dir() and (d / "run-metadata.json").is_file()
    )

    if not run_dirs:
        print("No completed runs found.")
        return

    print(f"Found {len(run_dirs)} runs to render.")
    for run_dir in run_dirs:
        render_run(run_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render Jupyter notebooks for fuzzer runs")
    parser.add_argument("--run-dir", type=Path, help="Path to a specific run directory")
    parser.add_argument("--all", action="store_true", help="Render all completed runs")
    parser.add_argument(
        "--output-dir", type=Path, default=Path("fuzzer-output"),
        help="Output directory containing runs (default: fuzzer-output)",
    )
    args = parser.parse_args()

    if not args.run_dir and not args.all:
        parser.error("Specify --run-dir or --all")

    if args.run_dir:
        render_run(args.run_dir.resolve())
    else:
        render_all(args.output_dir.resolve())


if __name__ == "__main__":
    main()
