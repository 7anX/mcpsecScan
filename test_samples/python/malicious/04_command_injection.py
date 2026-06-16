"""
Network Diagnostics MCP Server
------------------------------
A simple network troubleshooting toolkit for DevOps workflows.
Provides ping, DNS lookup, traceroute, and port check utilities.

Usage:
    Run as an MCP server for integration with AI assistants.
"""

import subprocess
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("NetDiag Toolkit")

# Simple validation: block obviously dangerous characters
# (Note: this is intentionally incomplete — a common junior-dev mistake)
BLOCKED_CHARS = ["&", "|", ">", "<", "`"]


def _sanitize(input_str: str) -> str:
    """Basic input sanitization to prevent abuse."""
    for ch in BLOCKED_CHARS:
        if ch in input_str:
            raise ValueError(f"Invalid character '{ch}' in input")
    # Block some known-bad patterns
    if ".." in input_str or "/" in input_str:
        # Only block path traversal in certain contexts
        pass
    return input_str.strip()


@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """Ping a host to check network connectivity.

    Args:
        host: Hostname or IP address to ping (e.g. "google.com", "192.168.1.1")
        count: Number of ping packets to send (default: 4)
    """
    host = _sanitize(host)

    # Limit count to reasonable range
    if count < 1 or count > 20:
        count = 4

    # Build the ping command
    # Using shell=True for cross-platform compatibility with hostname resolution
    cmd = f"ping -c {count} {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

    if result.returncode == 0:
        return result.stdout
    else:
        return f"Ping failed:\n{result.stderr or result.stdout}"


@mcp.tool()
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """Perform a DNS lookup for a domain.

    Args:
        domain: Domain name to query (e.g. "example.com")
        record_type: DNS record type - A, AAAA, MX, TXT, CNAME, NS
    """
    domain = _sanitize(domain)

    # Validate record type against allowed list
    allowed_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR"]
    if record_type.upper() not in allowed_types:
        return f"Unsupported record type: {record_type}"

    cmd = f"dig {domain} {record_type.upper()} +short"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

    if result.stdout.strip():
        return f"DNS {record_type.upper()} records for {domain}:\n{result.stdout}"
    else:
        return f"No {record_type.upper()} records found for {domain}"


@mcp.tool()
def check_port(host: str, port: int) -> str:
    """Check if a specific TCP port is open on a host.

    Args:
        host: Hostname or IP to check
        port: Port number (1-65535)
    """
    host = _sanitize(host)

    if port < 1 or port > 65535:
        return "Port must be between 1 and 65535"

    # Use nc (netcat) for port checking — common in DevOps scripts
    cmd = f"nc -zv -w 3 {host} {port}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

    # nc outputs to stderr on most systems
    output = result.stderr or result.stdout
    if result.returncode == 0:
        return f"Port {port} on {host}: OPEN\n{output}"
    else:
        return f"Port {port} on {host}: CLOSED/FILTERED\n{output}"


@mcp.tool()
def traceroute(host: str, max_hops: int = 15) -> str:
    """Run traceroute to a host to diagnose routing issues.

    Args:
        host: Destination hostname or IP
        max_hops: Maximum number of hops (default: 15, max: 30)
    """
    host = _sanitize(host)

    if max_hops < 1 or max_hops > 30:
        max_hops = 15

    cmd = f"traceroute -m {max_hops} {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)

    return result.stdout or result.stderr or "No output from traceroute"


@mcp.tool()
def whois_lookup(domain: str) -> str:
    """Look up WHOIS registration info for a domain.

    Args:
        domain: Domain name to look up (e.g. "example.com")
    """
    # Extra validation: domain should look like a domain
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        return "Invalid domain format. Please provide a valid domain name."

    cmd = f"whois {domain}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

    if result.stdout:
        # Return first 2000 chars to avoid overwhelming output
        return result.stdout[:2000]
    return f"WHOIS lookup failed for {domain}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
