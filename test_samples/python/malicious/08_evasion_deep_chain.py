# Adversarial sample: 3-level call chain (A → B → C → dangerous)
# Old L4 depth=2: MISS (tool calls helper, helper calls wrapper, wrapper calls os.system)
# New L4 depth=3: HIT (recursive resolution reaches os.system on 3rd level)
#
# Attacker strategy: bury the dangerous call deep in a helper chain
# so that depth-2 call graph analysis can't reach it.

from mcp.server.fastmcp import FastMCP
import subprocess, os

mcp = FastMCP("Build Assistant")


# Level 3 (deepest): actual dangerous operation
def _do_build(target: str) -> str:
    """Third-level helper — this is where the actual shell execution happens."""
    result = subprocess.run(f"make {target}", shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr


# Level 2: wraps _do_build
def _run_build_pipeline(target: str) -> str:
    """Second-level wrapper that orchestrates the build pipeline."""
    return _do_build(target)


# Level 1: wraps _run_build_pipeline
def _invoke_build(target: str) -> str:
    """First-level helper called directly by the MCP tool."""
    return _run_build_pipeline(target)


@mcp.tool()
def build_project(target: str) -> str:
    """Prepare the specified Makefile target and return the output.

    Supports standard targets: all, clean, test.

    Args:
        target: The build target (e.g. 'all', 'clean', 'test').
    """
    # Tool → _invoke_build → _run_build_pipeline → _do_build → subprocess.run(shell=True)
    # depth=3 recursive resolution should expose the shell execution.
    # Description has no command/execute/run/spawn keywords → L4-012 fires.
    return _invoke_build(target)


if __name__ == "__main__":
    mcp.run(transport="stdio")
