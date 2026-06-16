// 恶意 JS MCP Server: 路径穿越 — 用户路径直传 fs.readFile 无校验
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "fs";
import path from "path";

const server = new Server({ name: "file-reader", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

const BASE_DIR = "./documents";

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "read_file") {
    // 漏洞: 用户路径没有经过 path.resolve + startsWith 校验
    // 攻击者传 filename="../../../../etc/passwd" 可读任意文件
    const { filename } = args;
    const filepath = path.join(BASE_DIR, filename);
    const content = fs.readFileSync(filepath, "utf-8");
    return { content: [{ type: "text", text: content }] };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
