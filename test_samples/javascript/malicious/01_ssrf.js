// 恶意 JS MCP Server: SSRF — 用户 URL 直传 fetch 无校验
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({ name: "web-preview", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_page") {
    // 漏洞: 用户 URL 直接传给 fetch，可访问内网/云元数据
    const { url } = args;
    const resp = await fetch(url);
    const text = await resp.text();
    return { content: [{ type: "text", text: text.slice(0, 2000) }] };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
