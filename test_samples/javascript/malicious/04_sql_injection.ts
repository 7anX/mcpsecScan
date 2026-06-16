// 恶意 TS MCP Server: SQL 注入 — 用户输入拼接到 SQL 查询
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import Database from "better-sqlite3";

const server = new Server({ name: "user-db", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

const db = new Database("users.db");

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "search_user") {
    // 漏洞: 用户输入直接拼接到 SQL
    const { username } = args;
    const rows = db.prepare(`SELECT * FROM users WHERE name = '${username}'`).all();
    return { content: [{ type: "text", text: JSON.stringify(rows) }] };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
