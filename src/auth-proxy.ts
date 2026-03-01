import "dotenv/config";
import express from "express";
import cors from "cors";
import httpProxy from "http-proxy";
import {
  descopeMcpAuthRouter,
  descopeMcpBearerAuth,
  DescopeMcpProvider,
} from "@descope/mcp-express";
import { Readable } from "stream";

const app = express();
app.use(cors());

const PORT = process.env.PORT || process.env.AUTH_PROXY_PORT || 3000;
const N8N_URL = process.env.N8N_MCP_SERVER_URL!;

// 1. Initialize Descope provider — enable Authorization Server for /authorize + /register
const descopeProvider = new DescopeMcpProvider({
  projectId: process.env.DESCOPE_PROJECT_ID!,
  managementKey: process.env.DESCOPE_MANAGEMENT_KEY!,
  serverUrl: process.env.SERVER_URL!,
  authorizationServerOptions: {
    isDisabled: false,
  },
  dynamicClientRegistrationOptions: {
    authPageUrl: `https://api.descope.com/login/${process.env.DESCOPE_PROJECT_ID!}?flow=mcp-auth-consent`,
  },
});

// 2. Serve OAuth metadata, DCR (/register), authorize (/authorize), and bearer auth on /mcp
app.use(descopeMcpAuthRouter(undefined, descopeProvider));

// 4. Budget policy middleware — check role + amount before forwarding
app.use("/mcp", express.json(), async (req: any, res: any, next: any) => {
  if (req.method !== "POST" || !req.body) return next();

  // Enforce budget policy on payment tools
  if (req.body.method === "tools/call") {
    const toolName = req.body.params?.name;
    const args = req.body.params?.arguments;

    if (toolName === "process_payment" || toolName === "pay_invoice") {
      // Decode JWT payload to extract roles
      const token = req.auth?.token;
      let roles: string[] = [];

      if (token) {
        try {
          const payload = JSON.parse(
            Buffer.from(token.split(".")[1], "base64").toString()
          );
          roles = payload.roles || [];
        } catch (e) {
          console.error("Failed to decode token for role check:", e);
        }
      }

      const isCFO = roles.includes("CFO");
      const amount = parseFloat(args?.amount || "0");

      if (!isCFO && amount > 500) {
        return res.status(403).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: `Policy denied: $${amount} exceeds spending authority for your role. Max: $500.`,
          },
          id: req.body.id || null,
        });
      }
    }
  }

  // Re-serialize body for proxy (express.json() consumed the raw stream)
  const serialized = JSON.stringify(req.body);
  req.body = serialized;
  req.headers["content-length"] = Buffer.byteLength(serialized).toString();
  next();
});

// 5. Proxy to n8n
const proxy = httpProxy.createProxyServer({
  target: N8N_URL,
  changeOrigin: true,
  ws: false,
});

proxy.on("error", (err, _req, res) => {
  console.error("Proxy error:", err);
  if ("writeHead" in res) {
    (res as any).writeHead?.(502, { "Content-Type": "application/json" });
    (res as any).end?.(JSON.stringify({ error: "Bad gateway" }));
  }
});

app.use("/mcp", (req: any, res: any) => {
  // Strip auth header — n8n doesn't need the Descope token
  delete req.headers["authorization"];

  proxy.web(req, res, {
    buffer: Readable.from([req.body ?? ""]),
    ignorePath: true,
  });
});

app.listen(PORT, () => {
  console.log(`Descope auth proxy listening on port ${PORT}`);
  console.log(`Forwarding authenticated requests to ${N8N_URL}`);
});
