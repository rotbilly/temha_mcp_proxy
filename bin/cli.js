#!/usr/bin/env node
/**
 * MCP STDIO ⇄ HTTP Proxy (PRM + AS discovery)
 * - RFC 9728: /.well-known/oauth-protected-resource (PRM)
 * - RFC 8414: /.well-known/oauth-authorization-server (AS metadata)
 * - DCR (RFC 7591) + Auth Code + PKCE
 * - STDIO NDJSON framing (1 JSON per line)
 */

import { createServer } from 'http';
import { randomBytes, createHash } from 'crypto';
import { homedir } from 'os';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { spawn } from 'child_process';

// ----------------------------- HARD-CODED CONFIG -----------------------------
const CONFIG = {
    REMOTE_MCP_URL: 'http://127.0.0.1:4000/', // your HTTP MCP endpoint
    OAUTH_REDIRECT_URI: 'http://127.0.0.1:38573/callback',
    OAUTH_SCOPES: 'openid profile mcp'
};
if (!CONFIG.REMOTE_MCP_URL) { console.error('[proxy] missing REMOTE_MCP_URL'); process.exit(1); }

// Derive resource origin (scheme + host) for PRM discovery
const remote = new URL(CONFIG.REMOTE_MCP_URL);
const RESOURCE_ORIGIN = `${remote.protocol}//${remote.host}`; // e.g., https://mcp.temha.io

// ------------------------- SIMPLE STORAGE -------------------------
const STORE_DIR = join(homedir(), '.mcp-proxy', 'temha');
mkdirSync(STORE_DIR, { recursive: true });
const TOKENS_FILE = join(STORE_DIR, 'tokens.json');
const DISCOVERY_FILE = join(STORE_DIR, 'as-metadata.json'); // store AS metadata
const CLIENT_FILE = join(STORE_DIR, 'client-metadata.json');

function readJSON(path){ try{ if(existsSync(path)) return JSON.parse(readFileSync(path,'utf8')); }catch{} return null; }
function writeJSON(path,obj){ writeFileSync(path, JSON.stringify(obj,null,2),'utf8'); }

function b64url(buf){ return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function genPKCE(){ const code_verifier=b64url(randomBytes(32)); const challenge=createHash('sha256').update(code_verifier).digest(); return {code_verifier, code_challenge:b64url(challenge)}; }

function openInBrowser(url) {
    const platform = process.platform;
    try {
        if (platform === 'win32') {
            // Use cmd.exe 'start' with empty title and quoted URL to avoid & being parsed
            spawn('cmd', ['/c', 'start', '', `"${url}"`], {
                stdio: 'ignore',
                windowsVerbatimArguments: true,
                detached: true,
                shell: false,
            });
        } else if (platform === 'darwin') {
            spawn('open', [url], { stdio: 'ignore', detached: true });
        } else {
            spawn('xdg-open', [url], { stdio: 'ignore', detached: true });
        }
    } catch (e) {
        console.error('[proxy] Please open this URL manually:\n', url);
    }
}
// --------------------------- DISCOVERY (RFC 9728 + 8414) ---------------------------
async function fetchJSON(u){ const r = await fetch(u); if(!r.ok) throw new Error(`${u} ${r.status}`); return r.json(); }

// RFC 9728 – protected resource metadata
async function getPRM(resourceOrigin){
    const url = `${resourceOrigin}/.well-known/oauth-protected-resource`;
    return await fetchJSON(url);
}

// RFC 8414 – build AS well-known URL from issuer (handles path-based issuers)
function asWellKnownFromIssuer(issuer){
    const iu = new URL(issuer);
    const base = `${iu.protocol}//${iu.host}`;
    const path = iu.pathname.replace(/\/+$/, '');
    if (path && path !== '/') {
        // If issuer has path, RFC 8414 places it after the well-known segment
        return `${base}/.well-known/oauth-authorization-server${path}`;
    }
    return `${base}/.well-known/oauth-authorization-server`;
}

async function getASMetadata(issuer){
    const url = asWellKnownFromIssuer(issuer);
    const json = await fetchJSON(url);
    // normalize issuer field
    if (!json.issuer) json.issuer = issuer;
    return json;
}

async function discover(){
    // cache hit
    const cached = readJSON(DISCOVERY_FILE);
    if (cached && cached.issuer) return cached;

    // 1) PRM
    const prm = await getPRM(RESOURCE_ORIGIN);
    // Common fields per RFC 9728 drafts/implementations
    const issuer = (prm.authorization_servers?.[0]) || prm.authorization_server || prm.issuer;
    if (!issuer) throw new Error('[prm] no authorization server listed');

    // 2) AS metadata (RFC 8414)
    const asMeta = await getASMetadata(issuer);
    if (!asMeta.authorization_endpoint || !asMeta.token_endpoint) {
        throw new Error('[as] invalid AS metadata: missing endpoints');
    }

    writeJSON(DISCOVERY_FILE, asMeta);
    return asMeta;
}

// --------------------------- DCR + TOKENS ---------------------------
async function dynamicRegister(as){
    const cached = readJSON(CLIENT_FILE);
    if (cached && cached.issuer === as.issuer) return cached;
    if (!as.registration_endpoint) throw new Error('[oidc] no registration endpoint: enable DCR or pre-provision a client');
    const body = {
        application_type:'native',
        grant_types:['authorization_code','refresh_token'],
        response_types:['code'],
        token_endpoint_auth_method:'none',
        redirect_uris:[CONFIG.OAUTH_REDIRECT_URI],
        client_name:'MCP STDIO OAuth Proxy (temha)',
        scope:CONFIG.OAUTH_SCOPES,
    };
    const res = await fetch(as.registration_endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!res.ok) throw new Error(`[oidc] registration failed ${res.status}: ${await res.text()}`);
    const reg = await res.json();
    const meta={issuer:as.issuer,client_id:reg.client_id,redirect_uris:reg.redirect_uris||body.redirect_uris};
    writeJSON(CLIENT_FILE, meta);
    return meta;
}

async function fetchToken(as, client, params){
    const body = new URLSearchParams({...params,client_id:client.client_id});
    const res = await fetch(as.token_endpoint,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
    if(!res.ok) throw new Error(`[oauth] token error ${res.status}: ${await res.text()}`);
    const tok = await res.json();
    tok.expires_at=Math.floor(Date.now()/1000)+(tok.expires_in||3600)-30;
    writeJSON(TOKENS_FILE,tok);
    return tok;
}

async function ensureClient(as){ return await dynamicRegister(as); }

async function ensureToken(as,client){
    let tok=readJSON(TOKENS_FILE);
    const now=Math.floor(Date.now()/1000);
    if(tok&&tok.expires_at>now+60) return tok;
    if(tok&&tok.refresh_token){
        try{ return await fetchToken(as,client,{grant_type:'refresh_token',refresh_token:tok.refresh_token}); }
        catch(e){ console.error('[oauth] refresh failed; interactive login next:', e.message); }
    }
    return await interactiveLogin(as,client);
}

function appendQuery(base, params) {
    // base에 기존 query가 있으면 병합
    const [origin, existing] = base.split('?', 2);
    const out = new URLSearchParams(existing || '');
    for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) out.set(k, String(v));
    }
    return `${origin}?${out.toString()}`;
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
    const as=await discover();
    const client=await ensureClient(as);
    let tok=await ensureToken(as,client);
    try{ return await forwardJsonRpcToRemote(json,tok.access_token); }
    catch(e){ if(e.message==='UNAUTHORIZED'){ tok=await ensureToken(as,client); return await forwardJsonRpcToRemote(json,tok.access_token);} return {jsonrpc:'2.0',id:json.id??null,error:{code:-32001,message:String(e.message)}}; }
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
console.error(`[proxy] STDIO ↔ HTTP(OAuth) proxy ready (resource: ${RESOURCE_ORIGIN}) using ${CONFIG.REMOTE_MCP_URL}`);
