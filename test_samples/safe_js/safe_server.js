// 安全 JS MCP Server — 硬编码 URL + 路径校验
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "fs";
import path from "path";

const server = new Server({ name: "safe-tools", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

const DOCS_DIR = path.resolve("./documents");

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "get_time") {
    // 安全: 无外部输入，纯计算
    return { content: [{ type: "text", text: new Date().toISOString() }] };
  }

  if (name === "read_doc") {
    // 安全: path.resolve + startsWith 校验
    const resolved = path.resolve(DOCS_DIR, args.filename);
    if (!resolved.startsWith(DOCS_DIR)) {
      return { content: [{ type: "text", text: "Error: path outside allowed directory" }] };
    }
    const content = fs.readFileSync(resolved, "utf-8");
    return { content: [{ type: "text", text: content }] };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
