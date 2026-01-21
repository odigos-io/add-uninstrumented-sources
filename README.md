# Odigos Uninstrumented Sources Tool

A command-line tool that identifies and instruments Kubernetes workloads that are not currently instrumented by Odigos. The tool connects to your Odigos installation, queries for workloads missing instrumentation, and can automatically enable instrumentation for them.

## What It Does

1. Checks if `kubectl` is available in your PATH
2. Establishes a port-forward to the Odigos UI service (`svc/ui` in `odigos-system` namespace)
3. Connects to the Odigos GraphQL API at `http://localhost:3000/graphql`
4. Fetches all workloads and identifies those that are not instrumented
5. Optionally exports uninstrumented workloads to a CSV file
6. Updates the instrumentation status for uninstrumented workloads (unless `--dry-run` is specified)

## Requirements

- **Python 3.10+**
- **kubectl** - Must be installed and available in PATH
- **Kubernetes cluster access** - kubectl must have access to the `odigos-system` namespace
- **Odigos installation** - The Odigos UI service must be running in the cluster

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd add-uninstrumented-sources

# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

## Usage

```bash
python odigos_instrument.py [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--log-level` | Set logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `INFO`) |
| `--log-file FILE` | Write logs to a file in addition to console |
| `--export-csv FILE` | Export uninstrumented workloads to a CSV file |
| `--dry-run` | Preview changes without updating instrumentation |
| `--help` | Display help message |

## Examples

### Basic Usage

Run with default INFO logging level:

```bash
python odigos_instrument.py
```

### Dry Run (Preview Only)

See what would be updated without making changes:

```bash
python odigos_instrument.py --dry-run
```

### Export to CSV

Export uninstrumented sources to a CSV file without updating:

```bash
python odigos_instrument.py --export-csv uninstrumented.csv --dry-run
```

Export to CSV and update instrumentation:

```bash
python odigos_instrument.py --export-csv sources.csv
```

### Logging Options

Run with DEBUG logging for detailed output:

```bash
python odigos_instrument.py --log-level DEBUG
```

Run with WARNING level to suppress info messages:

```bash
python odigos_instrument.py --log-level WARNING
```

Log to a file:

```bash
python odigos_instrument.py --log-file /path/to/logfile.log
```

Combine DEBUG level with file logging:

```bash
python odigos_instrument.py --log-level DEBUG --log-file debug.log
```

## CSV Output Format

When using `--export-csv`, the tool creates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `namespace` | Kubernetes namespace of the workload |
| `name` | Name of the workload |
| `kind` | Workload type (e.g., Deployment, StatefulSet, DaemonSet) |

## License

See LICENSE file for details.
