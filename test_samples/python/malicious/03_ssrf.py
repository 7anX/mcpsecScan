# SSRF Realistic PoC — Website Preview Service
# A legitimate-looking MCP tool that fetches and previews web pages.
# The vulnerability: user-supplied URLs are passed directly to the HTTP
# client without restricting access to internal networks or cloud
# metadata endpoints.

from mcp.server.fastmcp import FastMCP
import urllib.request
import urllib.error
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("website-preview")

mcp = FastMCP("Website Preview Service")

# Reasonable defaults for a preview tool
MAX_RESPONSE_SIZE = 50_000  # 50 KB preview limit
REQUEST_TIMEOUT = 8         # seconds


def _fetch_page(url: str) -> dict:
    """Fetch a web page and extract metadata.

    Returns a dict with status, content_type, title, and a text preview.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "MCP-Preview/1.0 (Website Preview Service)",
            "Accept": "text/html, application/json, text/plain",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "unknown")
            raw = resp.read(MAX_RESPONSE_SIZE)

            # Try UTF-8, fall back to latin-1
            try:
                body = raw.decode("utf-8")
            except UnicodeDecodeError:
                body = raw.decode("latin-1")

            # Extract <title> if HTML
            title = ""
            if "html" in content_type.lower():
                import re
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:200]

            return {
                "status": resp.status,
                "content_type": content_type,
                "title": title or "(no title)",
                "preview": body[:2000],
                "size_bytes": len(raw),
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": str(e.reason)}
    except urllib.error.URLError as e:
        return {"status": 0, "error": str(e.reason)}
    except Exception as e:
        return {"status": 0, "error": str(e)}


@mcp.tool()
def preview_website(url: str) -> str:
    """Fetch a URL and return a text preview with metadata.

    Useful for quickly checking what a link contains without leaving
    the conversation.  Returns the page title, content type, and the
    first ~2 000 characters of the response body.

    Args:
        url: The full URL to preview (must start with http:// or https://).
    """
    if not url.startswith(("http://", "https://")):
        return json.dumps({"error": "URL must start with http:// or https://"})

    logger.info("Previewing %s", url)
    result = _fetch_page(url)
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def check_url_status(url: str) -> str:
    """Check whether a URL is reachable and return its HTTP status code.

    Args:
        url: The URL to check.
    """
    if not url.startswith(("http://", "https://")):
        return json.dumps({"error": "URL must start with http:// or https://"})

    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "MCP-Preview/1.0"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.dumps({"url": url, "status": resp.status, "reachable": True})
    except urllib.error.HTTPError as e:
        return json.dumps({"url": url, "status": e.code, "reachable": True})
    except Exception as e:
        return json.dumps({"url": url, "status": 0, "reachable": False, "error": str(e)})


# --- Why this is vulnerable (for mcpx reference) ---
#
# 1. The http/https prefix check is NOT sufficient — it does not block:
#      http://169.254.169.254/latest/meta-data/   (AWS IMDS)
#      http://metadata.google.internal/            (GCP metadata)
#      http://localhost:8080/admin/                 (local services)
#      http://10.0.0.1/                            (internal network)
#
# 2. urllib.request.urlopen follows redirects by default, so even
#    blocking internal IPs at the URL level can be bypassed with an
#    open redirect on an external host that points to 169.254.169.254.
#
# 3. Detection requires taint analysis: user input (url parameter)
#    flows to urllib.request.urlopen() without IP/hostname validation.

if __name__ == "__main__":
    mcp.run(transport="stdio")
