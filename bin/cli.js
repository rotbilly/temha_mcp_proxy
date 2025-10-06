/**
 * MCP STDIO ⇄ HTTP Proxy for https://mcp.temha.io
 * - OIDC discovery (.well-known) from REMOTE_MCP_URL root
 * - Dynamic Client Registration (public native client, PKCE)
 * - Authorization Code + PKCE (opens browser) + token refresh
 * - STDIO NDJSON framing (1 JSON per line) for clarity
 *
 * Production notes:
 * - Consider LSP-style Content-Length framing or an MCP SDK for robustness
 * - Consider secure token storage (e.g., keytar) and logging hygiene
 * - SSE/Streamable forwarding not implemented in this minimal example
 */

import { createServer } from 'http';
import { randomBytes, createHash } from 'crypto';
import { homedir } from 'os';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { spawn } from 'child_process';

// ----------------------------- HARD-CODED CONFIG -----------------------------
// Remote MCP endpoint for temha
const CONFIG = {
    REMOTE_MCP_URL: 'https://devmcp.temha.io/',
    OAUTH_REDIRECT_URI: 'http://127.0.0.1:38573/callback',
    OAUTH_SCOPES: 'openid profile mcp'
};
if (!CONFIG.REMOTE_MCP_URL) { console.error('[proxy] missing REMOTE_MCP_URL'); process.exit(1); }
// Derive issuer from remote root (scheme + host)
const remote = new URL(CONFIG.REMOTE_MCP_URL);
const OIDC_ISSUER = `${remote.protocol}//${remote.host}`;

// ------------------------- SIMPLE STORAGE -------------------------
const STORE_DIR = join(homedir(), '.mcp-proxy', 'temha');
mkdirSync(STORE_DIR, { recursive: true });
const TOKENS_FILE = join(STORE_DIR, 'tokens.json');
const DISCOVERY_FILE = join(STORE_DIR, 'oidc-discovery.json');
const CLIENT_FILE = join(STORE_DIR, 'client-metadata.json');

function readJSON(path){ try{ if(existsSync(path)) return JSON.parse(readFileSync(path,'utf8')); }catch{} return null; }
function writeJSON(path,obj){ writeFileSync(path, JSON.stringify(obj,null,2),'utf8'); }

function b64url(buf){ return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function genPKCE(){ const code_verifier=b64url(randomBytes(32)); const challenge=createHash('sha256').update(code_verifier).digest(); return {code_verifier, code_challenge:b64url(challenge)}; }
function openInBrowser(u){ const cmd=process.platform==='darwin'?'open':process.platform==='win32'?'start':'xdg-open'; try{spawn(cmd,[u],{stdio:'ignore',shell:true,detached:true});}catch{console.error('[proxy] Open manually:',u);} }

// --------------------------- OIDC FLOW ---------------------------
async function discover(){
    const cached = readJSON(DISCOVERY_FILE);
    if(cached && cached.issuer===OIDC_ISSUER) return cached;
    const wellKnown = `${OIDC_ISSUER}/.well-known/openid-configuration`;
    const res = await fetch(wellKnown);
    if(!res.ok) throw new Error(`[oidc] discovery failed ${res.status}`);
    const conf = await res.json();
    if(!conf.authorization_endpoint || !conf.token_endpoint){ throw new Error('[oidc] invalid discovery doc'); }
    conf.issuer = OIDC_ISSUER;
    writeJSON(DISCOVERY_FILE, conf);
    return conf;
}

async function dynamicRegister(conf){
    const cached = readJSON(CLIENT_FILE);
    if(cached && cached.issuer===conf.issuer) return cached;
    if(!conf.registration_endpoint) throw new Error('[oidc] no registration endpoint: enable DCR or pre-provision a client');
    const body = {
        application_type:'native',
        grant_types:['authorization_code','refresh_token'],
        response_types:['code'],
        token_endpoint_auth_method:'none',
        redirect_uris:[CONFIG.OAUTH_REDIRECT_URI],
        client_name:'MCP STDIO OAuth Proxy (temha)',
        scope:CONFIG.OAUTH_SCOPES,
    };
    const res = await fetch(conf.registration_endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!res.ok) throw new Error(`[oidc] registration failed ${res.status}: ${await res.text()}`);
    const reg = await res.json();
    const meta={issuer:conf.issuer,client_id:reg.client_id,redirect_uris:reg.redirect_uris||body.redirect_uris};
    writeJSON(CLIENT_FILE, meta);
    return meta;
}

async function fetchToken(conf, client, params){
    const body = new URLSearchParams({...params,client_id:client.client_id});
    const res = await fetch(conf.token_endpoint,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
    if(!res.ok) throw new Error(`[oauth] token error ${res.status}: ${await res.text()}`);
    const tok = await res.json();
    tok.expires_at=Math.floor(Date.now()/1000)+(tok.expires_in||3600)-30;
    writeJSON(TOKENS_FILE,tok);
    return tok;
}

async function ensureClient(conf){ return await dynamicRegister(conf); }

async function ensureToken(conf,client){
    let tok=readJSON(TOKENS_FILE);
    const now=Math.floor(Date.now()/1000);
    if(tok&&tok.expires_at>now+60) return tok;
    if(tok&&tok.refresh_token){
        try{ return await fetchToken(conf,client,{grant_type:'refresh_token',refresh_token:tok.refresh_token}); }
        catch(e){ console.error('[oauth] refresh failed; interactive login next:', e.message); }
    }
    return await interactiveLogin(conf,client);
}

async function interactiveLogin(conf,client){
    const {code_verifier,code_challenge}=genPKCE(); const state=b64url(randomBytes(16));
    const authURL=new URL(conf.authorization_endpoint);
    authURL.searchParams.set('response_type','code');
    authURL.searchParams.set('client_id',client.client_id);
    authURL.searchParams.set('redirect_uri',CONFIG.OAUTH_REDIRECT_URI);
    authURL.searchParams.set('scope',CONFIG.OAUTH_SCOPES);
    authURL.searchParams.set('code_challenge_method','S256');
    authURL.searchParams.set('code_challenge',code_challenge);
    authURL.searchParams.set('state',state);

    const {code}=await new Promise((resolve,reject)=>{
        const srv=createServer((req,res)=>{
            try{
                const url=new URL(req.url,CONFIG.OAUTH_REDIRECT_URI);
                if(url.pathname!=='/callback'){res.writeHead(404).end();return;}
                const rc=url.searchParams.get('code'); const st=url.searchParams.get('state');
                if(!rc||st!==state){res.writeHead(400).end('OAuth failed');reject(new Error('state mismatch'));return;}
                res.writeHead(200,{'Content-Type':'text/plain'});
                res.end('Login complete. You can close this window.');
                resolve({code:rc});
                setTimeout(()=>srv.close(),100);
            }catch(e){reject(e);} });
        const { port } = new URL(CONFIG.OAUTH_REDIRECT_URI);
        srv.listen(Number(port)||38573,'127.0.0.1',()=>openInBrowser(authURL.toString()));
    });

    return await fetchToken(conf,client,{grant_type:'authorization_code',code,redirect_uri:CONFIG.OAUTH_REDIRECT_URI,code_verifier});
}

// ---------------------------- PROXY CORE ---------------------------
async function forwardJsonRpcToRemote(json,accessToken){
    const res=await fetch(CONFIG.REMOTE_MCP_URL,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${accessToken}`},body:JSON.stringify(json)});
    if(res.status===401) throw new Error('UNAUTHORIZED');
    if(!res.ok) throw new Error(`[remote] ${res.status}: ${await res.text()}`);
    return await res.json();
}

async function handleRequest(json){
    const conf=await discover();
    const client=await ensureClient(conf);
    let tok=await ensureToken(conf,client);
    try{ return await forwardJsonRpcToRemote(json,tok.access_token); }
    catch(e){ if(e.message==='UNAUTHORIZED'){ tok=await ensureToken(conf,client); return await forwardJsonRpcToRemote(json,tok.access_token);} return {jsonrpc:'2.0',id:json.id??null,error:{code:-32001,message:String(e.message)}}; }
}

// ---------------------------- STDIO LOOP ---------------------------
let buf='';
process.stdin.setEncoding('utf8');
process.stdin.on('data', async chunk => {
    buf+=chunk; let i;
    while((i=buf.indexOf('\n'))>=0){
        const line=buf.slice(0,i).trim(); buf=buf.slice(i+1); if(!line) continue;
        let j; try{ j=JSON.parse(line); } catch { process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}})+'\n'); continue; }
        try{ const r=await handleRequest(j); process.stdout.write(JSON.stringify(r)+'\n'); }
        catch(e){ process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:j.id??null,error:{code:-32000,message:String(e.message)}})+'\n'); }
    }
});
process.stdin.on('end',()=>process.exit(0));
console.error(`[proxy] STDIO ↔ HTTP(OIDC) proxy ready (issuer: ${OIDC_ISSUER}) using ${CONFIG.REMOTE_MCP_URL}`);