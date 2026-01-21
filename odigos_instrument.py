import argparse
import csv
from contextlib import contextmanager
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import urllib.request


INSTRUMENTED_STATUS = "odigos agent is not injected as expected since source is not marked for instrumentation"

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SourcesInput:
    namespace: str
    name: str
    kind: str
    selected: bool = True
    currentStreamName: str = "default"


class GraphQLClient:
    """A GraphQL client for Odigos API."""

    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None):
        """
        Initialize the GraphQL client.

        Args:
            endpoint: The GraphQL API endpoint URL
            headers: Optional dictionary of HTTP headers to include in requests
        """
        self.endpoint = endpoint
        self.headers = headers or {}
        # Set default content type if not provided
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"
        logger.debug(f"GraphQL client initialized with endpoint: {endpoint}")

    def query(
        self, query: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query.

        Args:
            query: The GraphQL query string
            variables: Optional dictionary of variables for the query

        Returns:
            Dictionary containing the GraphQL response

        Raises:
            urllib.error.HTTPError: If the HTTP request fails
            urllib.error.URLError: If there's a network error
        """
        # Prepare the request payload
        payload = {
            "query": query,
        }

        if variables:
            payload["variables"] = variables

        logger.debug(f"Executing GraphQL query to {self.endpoint}")
        logger.debug(
            f"Query: {query[:100]}..." if len(query) > 100 else f"Query: {query}"
        )
        if variables:
            logger.debug(f"Variables: {json.dumps(variables, indent=2)}")

        # Convert payload to JSON string
        data = json.dumps(payload).encode("utf-8")

        # Create the request
        req = urllib.request.Request(
            self.endpoint, data=data, headers=self.headers, method="POST"
        )

        # Execute the request
        try:
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode("utf-8"))
                if "errors" in response_data:
                    logger.error(f"GraphQL errors: {response_data['errors']}")
                else:
                    logger.debug("GraphQL query executed successfully")
                return response_data
        except urllib.error.HTTPError as e:
            # Read error response body if available
            error_body = e.read().decode("utf-8") if e.fp else None
            logger.error(f"HTTP Error {e.code}: {e.reason}. Response: {error_body}")
            raise Exception(f"HTTP Error {e.code}: {e.reason}. Response: {error_body}")
        except urllib.error.URLError as e:
            logger.error(f"URL Error: {e.reason}")
            raise Exception(f"URL Error: {e.reason}")

    def get_workloads(self):
        logger.info("Fetching workloads from GraphQL API")
        query = """query GetWorkloads($filter: WorkloadFilter) {
                    workloads(filter: $filter) {
                        id {
                        namespace
                        kind
                        name
                        }
                        podsAgentInjectionStatus {
                        status
                        message
                        }
                    }
                    }"""
        return self.query(query)

    def instrumented_workloads(
        self,
        sources_to_set: List[SourcesInput] | None = None,
    ) -> bool:
        logger.info(
            f"Setting instrumentation for {len(sources_to_set) if sources_to_set else 0} sources"
        )
        mutation = """mutation PersistSources($sources: [PersistNamespaceSourceInput!]!) {
  persistK8sSources(sources: $sources)
}"""
        sources = [asdict(source) for source in sources_to_set]
        variables = {"sources": sources}
        result = self.query(mutation, variables)
        return result["data"]["persistK8sSources"]


def is_kubectl_available() -> bool:
    """
    Check if kubectl is available in the system PATH.

    Returns:
        True if kubectl is found in PATH, False otherwise
    """
    available = shutil.which("kubectl") is not None
    if not available:
        logger.warning("kubectl is not available in PATH")
    else:
        logger.debug("kubectl is available in PATH")
    return available


def wait_for_port(host: str, port: int, timeout: int = 30) -> bool:
    """
    Wait for a port to become available.

    Args:
        host: The hostname to check
        port: The port number to check
        timeout: Maximum time to wait in seconds

    Returns:
        True if the port becomes available, False if timeout is reached
    """
    logger.debug(
        f"Waiting for port {host}:{port} to become available (timeout: {timeout}s)"
    )
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    logger.info(f"Port {host}:{port} is now available")
                    return True
        except Exception as e:
            logger.debug(f"Port check failed: {e}")
        time.sleep(0.5)
    logger.warning(
        f"Port {host}:{port} did not become available within {timeout} seconds"
    )
    return False


@contextmanager
def port_forward_service(
    service_name: str, namespace: str, local_port: int, remote_port: int
) -> None:
    """
    Port forward a service to a local port.

    This is a context manager that starts a kubectl port-forward process
    and automatically terminates it when exiting the context.

    Args:
        service_name: The name of the service to port forward
        namespace: The namespace of the service
        local_port: The local port to forward to
        remote_port: The remote port to forward from

    Yields:
        The subprocess.Popen object for the port-forward process
    """
    logger.info(
        f"Starting port-forward: {service_name}/{namespace} -> localhost:{local_port}"
    )
    process = subprocess.Popen(
        [
            "kubectl",
            "port-forward",
            service_name,
            f"{local_port}:{remote_port}",
            "-n",
            namespace,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Wait for the port to be ready
        if not wait_for_port("localhost", local_port):
            raise RuntimeError(
                f"Port {local_port} did not become available within timeout"
            )
        yield process
    finally:
        logger.info(f"Terminating port-forward for {service_name}/{namespace}")
        process.terminate()
        process.wait()


def setup_logging(level: str, log_file: str | None = None) -> None:
    """
    Configure logging with the specified level and optional log file.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. If specified, logs will be written
                  to both console and file.
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")

    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Clear any existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(log_format, datefmt=date_format)

    # Console handler (always add)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if log file specified)
    if log_file:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")

    root_logger.setLevel(numeric_level)


def export_to_csv(workloads: list[SourcesInput], csv_file: str) -> None:
    """
    Export uninstrumented workloads to a CSV file.

    Args:
        workloads: List of SourcesInput objects to export
        csv_file: Path to the CSV file to create
    """
    # Create directory if it doesn't exist
    csv_dir = os.path.dirname(csv_file)
    if csv_dir and not os.path.exists(csv_dir):
        os.makedirs(csv_dir, exist_ok=True)
        logger.debug(f"Created directory: {csv_dir}")

    try:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(["namespace", "name", "kind"])
            # Write data rows
            for workload in workloads:
                writer.writerow([workload.namespace, workload.name, workload.kind])

        logger.info(f"Exported {len(workloads)} uninstrumented workloads to {csv_file}")
    except Exception as e:
        logger.error(f"Failed to export CSV to {csv_file}: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Add uninstrumented sources to Odigos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default INFO logging level
  python odigos_instrument.py

  # Run with DEBUG logging for detailed output
  python odigos_instrument.py --log-level DEBUG

  # Run with WARNING level to suppress info messages
  python odigos_instrument.py --log-level WARNING

  # Run with logging to a file
  python odigos_instrument.py --log-file /path/to/logfile.log

  # Run with DEBUG level and log to file
  python odigos_instrument.py --log-level DEBUG --log-file debug.log

  # Export uninstrumented sources to CSV file (without updating instrumentation)
  python odigos_instrument.py --export-csv uninstrumented.csv --dry-run

  # Export to CSV and update instrumentation
  python odigos_instrument.py --export-csv sources.csv

  # Just update instrumentation without exporting
  python odigos_instrument.py

  # Display this help message
  python odigos_instrument.py --help

What this tool does:
  1. Checks if kubectl is available in your PATH
  2. Establishes a port-forward to the Odigos UI service (svc/ui in odigos-system namespace)
  3. Connects to the GraphQL API at http://localhost:3000/graphql
  4. Fetches all workloads and identifies those that are not instrumented
  5. Updates the instrumentation status for uninstrumented workloads

Requirements:
  - kubectl must be installed and available in PATH
  - kubectl must have access to the odigos-system namespace
  - The Odigos UI service must be running in the cluster
        """,
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level. DEBUG shows detailed information including "
        "GraphQL queries and responses. INFO shows general progress. "
        "WARNING and above only show warnings and errors. (default: INFO)",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to log file. If specified, logs will be written to both "
        "console and the specified file. The directory will be created if it "
        "doesn't exist.",
    )
    parser.add_argument(
        "--export-csv",
        type=str,
        default=None,
        metavar="FILE",
        help="Export uninstrumented sources to a CSV file. The CSV will contain "
        "columns: namespace, name, kind. The directory will be created if it "
        "doesn't exist. By default, instrumentation will also be updated unless "
        "--dry-run is specified.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Export to CSV without updating instrumentation. Use this flag when "
        "you want to see what would be updated without making any changes.",
    )
    args = parser.parse_args()

    setup_logging(args.log_level, args.log_file)
    logger.info("Starting application")

    if not is_kubectl_available():
        logger.error("kubectl is required but not available")
        sys.exit(1)

    with port_forward_service("svc/ui", "odigos-system", 3000, 3000):
        client = GraphQLClient("http://localhost:3000/graphql")
        logger.debug("GraphQL client initialized")

        logger.info("Fetching workloads from GraphQL API")
        result = client.get_workloads()
        logger.debug(
            f"Received {len(result.get('data', {}).get('workloads', []))} workloads"
        )

        instrumented_workloads = [
            SourcesInput(
                namespace=workload["id"]["namespace"],
                name=workload["id"]["name"],
                kind=workload["id"]["kind"],
            )
            for workload in result["data"]["workloads"]
            if workload["podsAgentInjectionStatus"]["message"] == INSTRUMENTED_STATUS
        ]
        logger.info(f"Found {len(instrumented_workloads)} uninstrumented workloads")

        # Export to CSV if requested
        if args.export_csv:
            export_to_csv(instrumented_workloads, args.export_csv)

        # Update instrumentation unless dry-run is specified
        if args.dry_run:
            logger.info(
                "Dry-run mode: Skipping instrumentation update. "
                "Use without --dry-run to apply changes."
            )
            if len(instrumented_workloads) > 0:
                logger.info("Uninstrumented workloads that would be updated:")
                for workload in instrumented_workloads:
                    logger.info(
                        f"Workload -> {workload.namespace}/{workload.name} ({workload.kind})"
                    )
            else:
                logger.info("No uninstrumented workloads found")
        elif len(instrumented_workloads) > 0:
            # Only log at debug level when not in dry-run mode
            # (dry-run mode already logs at info level above)
            for workload in instrumented_workloads:
                logger.debug(
                    f"Uninstrumented workload: {workload.namespace}/{workload.name} ({workload.kind})"
                )
            result = client.instrumented_workloads(
                sources_to_set=instrumented_workloads
            )
            if result:
                logger.info("Instrumentation update completed successfully")
            else:
                logger.error("Instrumentation update failed")
        else:
            logger.info("No uninstrumented workloads found")


if __name__ == "__main__":
    main()
