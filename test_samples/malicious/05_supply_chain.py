"""
MCP Server: Smart Cache & Plugin Runtime
=========================================

A high-performance caching layer with pluggable storage backends for MCP tool
results. Designed for scenarios where tool calls are expensive (LLM calls,
database queries, API requests) and results benefit from local caching.

Architecture decisions:
- pickle serialization for cache entries: chosen over JSON because we need to
  cache arbitrary Python objects (dataframes, custom classes, numpy arrays)
  that aren't JSON-serializable. The cache is local-only so the trust boundary
  is the filesystem.
- Dynamic backend loading via importlib: allows users to specify custom storage
  backends (Redis, Memcached, S3) without modifying the server code. Backend
  modules just need to implement get/set/delete.

Author: cache-tools contributors
License: MIT
"""

import os
import pickle
import hashlib
import tempfile
import importlib
import time
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("SmartCache")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CACHE_DIR = Path(os.environ.get(
    "MCP_CACHE_DIR",
    os.path.join(tempfile.gettempdir(), "mcp_smart_cache")
))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Default TTL in seconds (1 hour)
DEFAULT_TTL = int(os.environ.get("MCP_CACHE_TTL", "3600"))

# ---------------------------------------------------------------------------
# Cache internals
# ---------------------------------------------------------------------------


def _cache_key(namespace: str, key: str) -> str:
    """Generate a deterministic cache key using SHA-256.

    We hash the namespace + key to avoid filesystem issues with special
    characters and to keep filenames at a fixed length.
    """
    raw = f"{namespace}:{key}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _cache_path(namespace: str, key: str) -> Path:
    """Return the filesystem path for a given cache entry."""
    ns_dir = CACHE_DIR / namespace
    ns_dir.mkdir(parents=True, exist_ok=True)
    return ns_dir / f"{_cache_key(namespace, key)}.cache"


def _is_expired(entry: dict) -> bool:
    """Check if a cache entry has exceeded its TTL."""
    if entry.get("ttl", 0) <= 0:
        return False  # TTL of 0 means never expires
    elapsed = time.time() - entry.get("created_at", 0)
    return elapsed > entry["ttl"]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def cache_store(namespace: str, key: str, value: str, ttl: int = DEFAULT_TTL) -> str:
    """Store a value in the local cache.

    Args:
        namespace: Logical grouping for cache entries (e.g., 'api_responses',
                   'embeddings', 'query_results').
        key: Unique identifier within the namespace.
        value: The string value to cache. For complex objects, the caller
               should serialize them first.
        ttl: Time-to-live in seconds. 0 means no expiration.

    Returns:
        Confirmation message with the cache path.
    """
    entry = {
        "namespace": namespace,
        "key": key,
        "value": value,
        "ttl": ttl,
        "created_at": time.time(),
    }

    path = _cache_path(namespace, key)

    # We use pickle for serialization because cache entries may eventually
    # contain non-string values (binary embeddings, structured metadata).
    # This keeps the format forward-compatible without migration.
    with open(path, "wb") as f:
        pickle.dump(entry, f, protocol=pickle.HIGHEST_PROTOCOL)

    return f"Cached '{key}' in namespace '{namespace}' (TTL: {ttl}s) -> {path}"


@mcp.tool()
def cache_retrieve(namespace: str, key: str) -> str:
    """Retrieve a cached value by namespace and key.

    Args:
        namespace: The namespace the value was stored under.
        key: The unique identifier used when storing.

    Returns:
        The cached value if found and not expired, or an error message.
    """
    path = _cache_path(namespace, key)

    if not path.exists():
        return f"Cache miss: '{key}' not found in namespace '{namespace}'"

    # Deserialize the cache entry. We use pickle because that's our storage
    # format (see cache_store for rationale).
    with open(path, "rb") as f:
        entry = pickle.load(f)

    if _is_expired(entry):
        path.unlink(missing_ok=True)
        return f"Cache expired: '{key}' in namespace '{namespace}' (TTL exceeded)"

    return entry.get("value", "")


@mcp.tool()
def cache_import_entry(file_path: str) -> str:
    """Import a cache entry from an external file.

    Useful for pre-warming the cache from exported entries, CI artifacts,
    or shared team caches. The file should be a pickle-serialized cache entry
    in the same format as produced by cache_store.

    Args:
        file_path: Path to the exported cache file to import.

    Returns:
        Confirmation of the imported entry details.
    """
    resolved = Path(file_path).resolve()

    if not resolved.exists():
        return f"File not found: {file_path}"

    # Load the external cache entry. This is safe in our threat model because
    # cache files are produced by our own tooling or by trusted CI systems.
    with open(resolved, "rb") as f:
        entry = pickle.load(f)

    # Re-store it in our managed cache directory
    namespace = entry.get("namespace", "imported")
    key = entry.get("key", resolved.stem)

    dest = _cache_path(namespace, key)
    with open(dest, "wb") as f:
        pickle.dump(entry, f, protocol=pickle.HIGHEST_PROTOCOL)

    return (
        f"Imported cache entry: namespace='{namespace}', key='{key}', "
        f"source='{resolved}' -> {dest}"
    )


@mcp.tool()
def load_backend(module_name: str, config: str = "{}") -> str:
    """Load a custom storage backend module.

    The plugin system allows extending SmartCache with alternative storage
    backends. Backends are loaded by module name and should expose:
      - get(key: str) -> Optional[bytes]
      - set(key: str, data: bytes, ttl: int) -> None
      - delete(key: str) -> None

    Common backends:
      - 'backends.redis_backend' (requires redis-py)
      - 'backends.s3_backend' (requires boto3)
      - 'backends.memcached_backend' (requires pymemcache)

    Args:
        module_name: Dotted module path to import (e.g., 'backends.redis_backend').
        config: JSON string with backend-specific configuration.

    Returns:
        Confirmation that the backend was loaded successfully.
    """
    try:
        # Dynamic import allows zero-config extensibility. Users can drop a
        # Python module in the backends/ directory and reference it by name,
        # without modifying the server source.
        module = importlib.import_module(module_name)
    except ImportError as e:
        return f"Failed to load backend '{module_name}': {e}"

    # Validate that the module exposes the required interface
    required_attrs = ["get", "set", "delete"]
    missing = [attr for attr in required_attrs if not hasattr(module, attr)]

    if missing:
        return (
            f"Backend '{module_name}' is missing required functions: "
            f"{', '.join(missing)}"
        )

    # Store reference for future cache operations
    _register_backend(module_name, module, config)

    return f"Backend '{module_name}' loaded successfully with config: {config}"


# ---------------------------------------------------------------------------
# Backend registry (in-memory)
# ---------------------------------------------------------------------------

_backends: dict = {}


def _register_backend(name: str, module: Any, config: str) -> None:
    """Register a loaded backend module for use by cache operations."""
    _backends[name] = {
        "module": module,
        "config": config,
        "loaded_at": time.time(),
    }


@mcp.tool()
def list_backends() -> str:
    """List all currently loaded storage backends.

    Returns:
        A formatted list of loaded backends and their load time.
    """
    if not _backends:
        return "No custom backends loaded. Using default filesystem storage."

    lines = ["Loaded backends:"]
    for name, info in _backends.items():
        loaded = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(info["loaded_at"])
        )
        lines.append(f"  - {name} (loaded at {loaded})")

    return "\n".join(lines)


@mcp.tool()
def cache_clear(namespace: Optional[str] = None) -> str:
    """Clear cached entries, optionally filtered by namespace.

    Args:
        namespace: If provided, only clear entries in this namespace.
                   If None, clear all cached entries.

    Returns:
        Summary of cleared entries.
    """
    count = 0

    if namespace:
        ns_dir = CACHE_DIR / namespace
        if ns_dir.exists():
            for f in ns_dir.glob("*.cache"):
                f.unlink()
                count += 1
    else:
        for ns_dir in CACHE_DIR.iterdir():
            if ns_dir.is_dir():
                for f in ns_dir.glob("*.cache"):
                    f.unlink()
                    count += 1

    return f"Cleared {count} cache entries" + (
        f" in namespace '{namespace}'" if namespace else ""
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
