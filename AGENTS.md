# AGENTS.md

Behavioral guidelines for working in this repo. These bias toward caution over speed — for trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

- State assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- Remove only imports/variables that YOUR changes made unused.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

- "Fix the bug" → reproduce it first, then fix, then confirm it's gone.
- "Add feature X" → describe how to verify it works before calling it done.
- For multi-step tasks, state a brief plan with verification per step.

---

## Project: Shadow Fuzzer

Randomized reproducible Shadow network simulation sweeps. Reads a template config.toml
with optional `{min, max}` range values, generates per-run concrete configs with
deterministic sampling, and runs Shadow simulations locally or in Docker ARM.

### Commands

```bash
uv sync                          # install dependencies
uv run shadow-fuzzer.py config.toml           # run a sweep
uv run shadow-fuzzer.py --dry-run config.toml # dry run
uv run shadow-fuzzer.py --serve config.toml   # run with dashboard
cd web && npm install && npm run build        # build dashboard frontend
```

### Architecture

```
shadow-fuzzer.py          # main entry point — config parsing, run orchestration
├── _resolve_config()     #   parse TOML, sample ranges, validate
├── _ensure_docker_image()#   build composite Docker image (docker-arm runner)
├── _execute_runs()       #   per-run loop:
│   ├── _run_genesis()           #   copy genesis template, run generate-genesis.sh
│   ├── _run_topology()          #   run generate_shadow_topology.py
│   ├── _run_shadow_yaml()       #   run generate-shadow-yaml.sh
│   ├── _run_shadow()            #   invoke shadow simulator (local or docker)
│   └── _run_stats()             #   parse shadow output via stats_shadow.py
│
├── shadow_fuzzer/        # package containing fuzzer modules and tools
│   ├── generate_shadow_topology.py  # GML topology + bandwidths/regions JSON
│   ├── stats_shadow.py              # parse shadow output → stats.json
│   ├── dashboard_server.py   # FastAPI + WebSocket dashboard backend
│   ├── dashboard_db.py       # SQLite store for runs, events, snapshots
│   ├── dashboard_events.py   # wraps stats_shadow.py; normalizes events
│   ├── dashboard_live.py     # live log watcher for dashboard updates
│   └── dashboard_time.py     # chain slot ↔ simulated seconds conversion
│
├── scripts/              # bundled shell scripts
│   ├── generate-genesis.sh
│   ├── generate-shadow-yaml.sh
│   ├── parse-vc.sh
│   └── client-cmds/      # per-client command templates (10 clients)
├── templates/genesis/    # default genesis template
├── web/                  # React + Vite dashboard frontend
└── tests/
```

### Config

Two example configs:
- `config.example.docker-arm.toml` — docker-arm runner with Docker image references
- `config.example.local.toml` — local runner using host binaries on PATH

Key config sections: `[fuzzer]`, `[simulation]`, `[clients]`, `[network]`, `[network.regions]`, `[network.bandwidths]`.

### Key constraints

- Python >= 3.11, dependencies in `pyproject.toml` (managed with uv)
- `yq` must be installed for shell scripts (`brew install yq`)
- Local runner requires `shadow` on PATH and client binaries on PATH
- Docker ARM runner requires Docker with ARM emulation
- Genesis template uses hash-sig keys; key cache is at `_hash-sig-key-cache/`
- Output goes to `fuzzer-output/` (gitignored); dashboard DB is `fuzzer-output/runs.db`
