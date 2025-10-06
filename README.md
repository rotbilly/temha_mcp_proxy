# temha-mcp-proxy

Local **STDIO ↔ HTTP MCP** proxy for **https://mcp.temha.io** with **OIDC discovery** and **Dynamic Client Registration**.

- Derives **OIDC issuer** from `https://mcp.temha.io` (root of REMOTE_MCP_URL)
- Runs as a **local MCP server** (STDIO NDJSON) for clients like **Claude for Desktop**
- Handles **Authorization Code + PKCE** in your default browser, then caches/refreshes tokens
- No env vars needed; **hardcoded** config for simple `npx` usage

## Requirements
- Node.js **18+** (built-in `fetch`)

## Run from GitHub (no publish required)
```bash
npx github:you/mcp-temha-proxy
```
Or after publishing to npm:
```bash
npx mcp-temha-proxy
```