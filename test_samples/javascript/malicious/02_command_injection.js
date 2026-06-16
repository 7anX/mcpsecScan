// 恶意 JS MCP Server: 命令注入 — 用户输入拼接到 exec
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec } from "child_process";

const server = new Server({ name: "system-tools", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "run_diagnostic") {
    // 漏洞: 用户输入直接拼接到 shell 命令
    const { hostname } = args;
    return new Promise((resolve, reject) => {
      exec(`ping -c 4 ${hostname}`, (error, stdout, stderr) => {
        resolve({ content: [{ type: "text", text: stdout || stderr }] });
      });
    });
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
