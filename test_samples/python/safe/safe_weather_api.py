# 正常的 API 代理 MCP server——有网络请求但是合理用途
from mcp.server.fastmcp import FastMCP
import requests
import re

mcp = FastMCP("Weather API")

ALLOWED_HOSTS = {"api.openweathermap.org", "api.weatherapi.com"}


@mcp.tool()
def get_weather(city: str) -> str:
    """Get current weather for a city using the OpenWeatherMap API.

    This tool makes HTTP requests to a weather API service.
    """
    # 正确做法：硬编码 API URL，用户只控制查询参数
    # 不是 SSRF——URL 不来自用户输入
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid=demo"
    resp = requests.get(url, timeout=5)
    return resp.text[:500]


@mcp.tool()
def search_cities(query: str) -> str:
    """Search for cities matching a query string via the OpenWeatherMap geocoding API.

    Sends an HTTP request to the geocoding endpoint and returns matching city results.
    """
    # 用户输入只用于查询参数，不控制 host
    safe_query = re.sub(r'[^a-zA-Z0-9\s]', '', query)
    url = f"https://api.openweathermap.org/geo/1.0/direct?q={safe_query}&limit=5"
    resp = requests.get(url, timeout=5)
    return resp.text[:500]


if __name__ == "__main__":
    mcp.run(transport="stdio")
