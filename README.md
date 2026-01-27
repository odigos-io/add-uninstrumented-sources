# Odigos Uninstrumented Sources Tool

A command-line tool that identifies and instruments Kubernetes workloads that are not currently instrumented by Odigos. The tool connects to your Odigos installation, queries for workloads missing instrumentation, and can automatically enable instrumentation for them.

## What It Does

1. Checks if `kubectl` is available in your PATH
2. Establishes a port-forward to the Odigos UI service (`svc/ui` in the specified namespace)
3. Connects to the Odigos GraphQL API at `http://localhost:3000/graphql`
4. Fetches all namespaces from the cluster
5. Filters out ignored namespaces (default: `kube-system`, `kube-public`, `default`)
6. Fetches workloads for each remaining namespace
7. Identifies workloads that are not instrumented
8. Optionally exports uninstrumented workloads to a CSV file
9. Updates the instrumentation status for uninstrumented workloads (unless `--dry-run` is specified)

## Requirements

- **Python 3.10+**
- **kubectl** - Must be installed and available in PATH
- **Kubernetes cluster access** - kubectl must have access to the Odigos namespace (specified via `--odigos-namespace`)
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
| `--odigos-namespace NAMESPACE` | **Required.** The namespace where Odigos is installed (e.g., `odigos-system`) |
| `--log-level` | Set logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `INFO`) |
| `--log-file FILE` | Write logs to a file in addition to console |
| `--export-csv FILE` | Export uninstrumented workloads to a CSV file |
| `--ignore-namespaces NAMESPACE [NAMESPACE ...]` | List of namespaces to ignore when fetching workloads (default: `kube-system kube-public default`) |
| `--dry-run` | Preview changes without updating instrumentation |
| `--help` | Display help message |

## Examples

### Basic Usage

Run with default INFO logging level (namespace is required):

```bash
python odigos_instrument.py --odigos-namespace odigos-system
```

### Dry Run (Preview Only)

See what would be updated without making changes:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --dry-run
```

### Export to CSV

Export uninstrumented sources to a CSV file without updating:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --export-csv uninstrumented.csv --dry-run
```

Export to CSV and update instrumentation:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --export-csv sources.csv
```

### Ignoring Namespaces

By default, the tool ignores `kube-system`, `kube-public`, and `default` namespaces. You can customize this:

```bash
# Ignore only kube-system
python odigos_instrument.py --odigos-namespace odigos-system --ignore-namespaces kube-system

# Ignore multiple custom namespaces
python odigos_instrument.py --odigos-namespace odigos-system --ignore-namespaces kube-system monitoring logging
```

### Logging Options

Run with DEBUG logging for detailed output:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --log-level DEBUG
```

Run with WARNING level to suppress info messages:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --log-level WARNING
```

Log to a file:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --log-file /path/to/logfile.log
```

Combine DEBUG level with file logging:

```bash
python odigos_instrument.py --odigos-namespace odigos-system --log-level DEBUG --log-file debug.log
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
