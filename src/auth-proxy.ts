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
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Diagnostic: log every incoming request
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.path}`, {
    query: req.query,
    body: req.body,
  });
  next();
});

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
    authPageUrl: `https://api.descope.com/login/${process.env.DESCOPE_PROJECT_ID!}?flow=sign-in`,
    nonConfidentialClient: true,
  },
});

// 2. Override resource metadata — point authorization_servers to this proxy
// so Claude Desktop discovers our AS metadata (with DCR + authorize endpoints)
// instead of Descope's API (which lacks them at the RFC 8414 discovery path)
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const serverUrl = process.env.SERVER_URL!;
  res.json({
    resource: serverUrl,
    authorization_servers: [serverUrl],
    scopes_supported: ["openid"],
    bearer_methods_supported: ["header"],
  });
});

// 3. Override AS metadata — issuer must match proxy URL per RFC 8414 §3.3
// (library sets issuer = Descope API URL, which causes clients to reject the metadata)
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const serverUrl = process.env.SERVER_URL!;
  res.json({
    issuer: serverUrl,
    authorization_endpoint: `${serverUrl}/authorize`,
    token_endpoint: `${serverUrl}/token`,
    registration_endpoint: `${serverUrl}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint: "https://api.descope.com/oauth2/v1/apps/revoke",
    revocation_endpoint_auth_methods_supported: ["client_secret_post"],
    scopes_supported: ["openid", "profile"],
  });
});

// 4. In-memory store for redirect URIs (state → original redirect_uri)
const redirectUriStore = new Map<string, string>();

// 5. Intercept /register to add our callback URL to approved redirect URIs
app.use("/register", (req: any, _res, next) => {
  if (req.method === "POST" && req.body?.redirect_uris) {
    const callbackUrl = `${process.env.SERVER_URL}/callback`;
    if (!req.body.redirect_uris.includes(callbackUrl)) {
      req.body.redirect_uris.push(callbackUrl);
    }
    console.log("[/register] redirect_uris:", req.body.redirect_uris);
  }
  next();
});

// 6. Override /authorize — swap redirect_uri with our /callback intermediary
app.get("/authorize", (req, res) => {
  const params = { ...(req.query as Record<string, string>) };

  // Save original redirect_uri keyed by state
  const originalRedirectUri = params.redirect_uri;
  const state = params.state;
  if (originalRedirectUri && state) {
    redirectUriStore.set(state, originalRedirectUri);
  }

  // Replace with our callback
  params.redirect_uri = `${process.env.SERVER_URL}/callback`;
  if (!params.scope) params.scope = "openid";

  const descopeUrl = new URL("https://api.descope.com/oauth2/v1/apps/authorize");
  descopeUrl.search = new URLSearchParams(params).toString();

  console.log("[/authorize] Original redirect_uri:", originalRedirectUri);
  console.log("[/authorize] Replaced with:", params.redirect_uri);
  console.log("[/authorize] Redirecting to:", descopeUrl.toString());

  res.redirect(descopeUrl.toString());
});

// 7. /callback — receives redirect from Descope, logs params, forwards to Claude Desktop
app.get("/callback", (req, res) => {
  console.log("[/callback] Params from Descope:", JSON.stringify(req.query));

  const state = req.query.state as string;
  const originalRedirectUri = redirectUriStore.get(state);
  redirectUriStore.delete(state);

  if (!originalRedirectUri) {
    console.error("[/callback] No stored redirect_uri for state:", state);
    return res.status(400).send("Unknown OAuth state");
  }

  // Forward ALL params to the original redirect_uri
  const redirectUrl = new URL(originalRedirectUri);
  for (const [key, value] of Object.entries(req.query)) {
    redirectUrl.searchParams.set(key, value as string);
  }

  console.log("[/callback] Forwarding to:", redirectUrl.toString());
  res.redirect(redirectUrl.toString());
});

// 8. Proxy /token to Descope's token endpoint
// (Claude Desktop discovers this via AS metadata but it doesn't exist on our proxy natively)
app.post("/token", express.urlencoded({ extended: false }), async (req, res) => {
  try {
    console.log("[/token] Request body:", req.body);
    const descopeTokenUrl = "https://api.descope.com/oauth2/v1/apps/token";
    const response = await fetch(descopeTokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(req.body).toString(),
    });
    const responseBody = await response.text();
    console.log("[/token] Descope response:", response.status, responseBody);
    res
      .status(response.status)
      .set("Content-Type", response.headers.get("Content-Type") || "application/json")
      .send(responseBody);
  } catch (err) {
    console.error("[/token] Proxy error:", err);
    res.status(502).json({ error: "server_error", error_description: "Token exchange failed" });
  }
});

// 9. Serve OAuth metadata, DCR (/register), authorize (/authorize), and bearer auth on /mcp
app.use(descopeMcpAuthRouter(undefined, descopeProvider));

// 10. Budget policy middleware — check role + amount before forwarding
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

// 11. Proxy to n8n
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
