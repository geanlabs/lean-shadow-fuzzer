# Shadow Fuzzer

Randomized reproducible Shadow network simulation sweeps.

Reads a template config.toml with optional `{min, max}` range values, generates per-run concrete configs with deterministic sampling, and runs Shadow simulations either locally or inside a Docker ARM container.

## Quickstart

```bash
# Install Python dependencies
uv sync

# Copy and edit the example config
cp config.example.toml config.toml

# Run a dry-run to see what would happen
uv run shadow-fuzzer.py --dry-run config.toml

# Run the full sweep
uv run shadow-fuzzer.py config.toml

# Run with the live dashboard
uv run shadow-fuzzer.py --serve config.toml
```

## Dashboard

The dashboard provides a web UI for monitoring fuzzer runs.

```bash
# Build the frontend (one time)
cd web && npm install && npm run build

# Start the dashboard server
uv run shadow-fuzzer.py --serve config.toml
```

Open `http://127.0.0.1:8000` in your browser.

## Project Structure

```
├── scripts/               # Shell scripts (genesis, shadow YAML generation)
│   ├── generate-genesis.sh
│   ├── generate-shadow-yaml.sh
│   ├── parse-vc.sh
│   └── client-cmds/       # Per-client command templates
├── templates/genesis/     # Genesis template
├── web/                   # Dashboard frontend (React + Vite)
├── tests/                 # Test suite
├── shadow-fuzzer.py       # Main entry point
├── generate-shadow-topology.py
├── stats-shadow.py
├── dashboard_server.py    # FastAPI dashboard backend
└── config.example.toml    # Example configuration
```

## Requirements

- Python >= 3.11
- Node.js (for dashboard frontend)
- Docker (for ARM-based Shadow runner)
- `yq` (for shell scripts: `brew install yq`)
