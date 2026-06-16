# A completely benign MCP server — mcpx should produce ZERO findings on this.
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Calculator")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers and return the result."""
    return a + b


@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Multiply two numbers and return the result."""
    return a * b


@mcp.tool()
def greet(name: str) -> str:
    """Return a greeting message for the given name."""
    return f"Hello, {name}!"


if __name__ == "__main__":
    mcp.run(transport="stdio")
