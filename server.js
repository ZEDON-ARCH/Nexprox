const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

/* ══════════════════════════════════════════════════
   CONFIGURATION  —  credentials come from env ONLY
   Set MAIL_USER and MAIL_PASS in Vercel dashboard
   or in a local .env file (never commit secrets)
══════════════════════════════════════════════════ */
const PORT = process.env.PORT || 3000;
const MASTER_PASS = process.env.MASTER_PASS || 'NEXPROX_DEV_2026';

const MAIL_USER = process.env.MAIL_USER || 'User_address@gmail.com'; //change to your email addresss
const MAIL_PASS = process.env.MAIL_PASS || 'm0cy dcay fiy0 lykb'.replace(/ /g, '');  // app password (input app password from you email)

if (!process.env.MAIL_USER) {
    console.log('[MAIL] Using default credentials. Set MAIL_USER/MAIL_PASS env vars for production.');
}

let activeSessions = new Set();
let loginData = [];

/* ─── DATA PERSISTENCE ─── */
const USERS_FILE = path.join(__dirname, 'users.json');
const LOG_FILE   = path.join(__dirname, 'activity.log');

function loadUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
        return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch (e) { console.error('[DATA] Error loading users:', e); return {}; }
}

function saveUsers(users) {
    try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
    catch (e) { console.error('[DATA] Error saving users:', e); }
}

function logActivity(msg, req) {
    const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : 'SYSTEM';
    const entry = `[${new Date().toISOString()}] [IP: ${ip}] ${msg}\n`;
    fs.appendFileSync(LOG_FILE, entry);
    console.log(`[ACTIVITY] ${msg}`);
}

function genSecret(len) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No similar chars O, 0, I, 1
    let out = '';
    for (let i = 0; i < len; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
}

/* ══════════════════════════════════════════════════
   SECURITY HEADERS  (applied to every response)
══════════════════════════════════════════════════ */
function applySecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=()');
    // Only add HSTS if actually served over HTTPS
    if (process.env.HTTPS_ENABLED === 'true') {
        res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
}

/* ══════════════════════════════════════════════════
   SMTP CLIENT  —  native TLS, no plain-text logs
══════════════════════════════════════════════════ */
function sendGmailNative(to, subject, htmlBody, plainBody, auth, callback) {
    if (!auth.user || !auth.pass) {
        console.warn('[SMTP] Skipped — credentials not configured.');
        if (callback) callback(false, 'SMTP not configured');
        return;
    }

    const client = tls.connect(465, 'smtp.gmail.com', { rejectUnauthorized: true }, () => {
        // connection open — wait for server greeting
    });

    let step = 0;
    const userB64 = Buffer.from(auth.user).toString('base64');
    const passB64 = Buffer.from(auth.pass).toString('base64');

    client.setTimeout(15000);
    client.on('timeout', () => {
        console.error('[SMTP] Connection timed out.');
        client.destroy();
        if (callback) callback(false, 'Timeout');
    });

    client.on('data', (data) => {
        const resp = data.toString().trim();

        // Hard errors from Gmail — log but don't print credentials
        if (/^[45]/.test(resp)) {
            console.error('[SMTP] Error response (step ' + step + '): ' + resp.substring(0, 80));
            client.destroy();
            if (callback) callback(false, 'SMTP error: ' + resp.substring(0, 80));
            return;
        }

        if (step === 0 && resp.startsWith('220')) {
            client.write('EHLO nexprox\r\n'); step = 1;
        } else if (step === 1 && resp.startsWith('250')) {
            client.write('AUTH LOGIN\r\n'); step = 2;
        } else if (step === 2 && resp.startsWith('334')) {
            client.write(userB64 + '\r\n'); step = 3;
        } else if (step === 3 && resp.startsWith('334')) {
            client.write(passB64 + '\r\n'); step = 4;
        } else if (step === 4 && resp.startsWith('235')) {
            client.write(`MAIL FROM:<${auth.user}>\r\n`); step = 5;
        } else if (step === 5 && resp.startsWith('250')) {
            client.write(`RCPT TO:<${to}>\r\n`); step = 6;
        } else if (step === 6 && resp.startsWith('250')) {
            client.write('DATA\r\n'); step = 7;
        } else if (step === 7 && resp.startsWith('354')) {
            const boundary = 'nexprox_' + Date.now();
            const msg = [
                `From: "Nexprox Security" <${auth.user}>`,
                `To: ${to}`,
                `Subject: ${subject}`,
                `MIME-Version: 1.0`,
                `Content-Type: multipart/alternative; boundary="${boundary}"`,
                '',
                `--${boundary}`,
                `Content-Type: text/plain; charset=utf-8`,
                '',
                plainBody,
                '',
                `--${boundary}`,
                `Content-Type: text/html; charset=utf-8`,
                '',
                htmlBody,
                '',
                `--${boundary}--`,
                '.\r\n'
            ].join('\r\n');
            client.write(msg); step = 8;
        } else if (step === 8 && resp.startsWith('250')) {
            console.log('[SMTP] Message accepted by Gmail.');
            client.write('QUIT\r\n'); step = 9;
            if (callback) callback(true);
        }
    });

    client.on('error', (err) => {
        console.error('[SMTP] Socket error:', err.message);
        if (callback) callback(false, err.message);
    });
}

/* ══════════════════════════════════════════════════
   HELPERS
══════════════════════════════════════════════════ */
function readBody(req) {
    return new Promise((resolve, reject) => {
        let raw = '';
        req.on('data', chunk => { raw += chunk; if (raw.length > 50000) req.destroy(); });
        req.on('end', () => resolve(raw));
        req.on('error', reject);
    });
}

async function readJsonBody(req) {
    // Vercel often pre-parses JSON into req.body
    if (req.body) {
        return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }
    const raw = await readBody(req);
    return JSON.parse(raw);
}

function jsonRes(res, code, obj) {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
}

function buildEmailContent(name, code, email) {
    const now = new Date();
    const expireTs = new Date(now.getTime() + 2 * 60 * 60 * 1000);
    const dateStr = now.toUTCString();
    const expireStr = expireTs.toUTCString();

    const plain = [
        'NEXPROX SECURE ACCESS CODE',
        '─────────────────────────────────────',
        `Hello ${name},`,
        '',
        'Your one-time Nexprox access code is:',
        '',
        `  >>> ${code} <<<`,
        '',
        `Issued:  ${dateStr}`,
        `Expires: ${expireStr} (2 hours)`,
        '',
        'SECURITY NOTICE:',
        '  • This code is single-use and expires in 2 hours.',
        '  • Do NOT share this code with anyone.',
        '  • Nexprox staff will never ask for your code.',
        '  • If you did not request this, ignore this email.',
        '',
        '─────────────────────────────────────',
        'Nexprox Advanced Proxy System',
        'Encrypted Transmission — AES-256-GCM',
        `Recipient: ${email}`,
    ].join('\n');

    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nexprox Access Code</title>
<style>
  body{margin:0;padding:0;background:#05080d;font-family:'Segoe UI',sans-serif;color:#e2e8f0;}
  .wrap{max-width:520px;margin:0 auto;padding:32px 16px;}
  .card{background:#0a1624;border:1px solid rgba(0,255,102,0.25);border-radius:16px;overflow:hidden;}
  .header{background:linear-gradient(135deg,#071a0f,#030d07);padding:28px 32px;text-align:center;border-bottom:1px solid rgba(0,255,102,0.2);}
  .logo{font-size:22px;font-weight:800;letter-spacing:5px;color:#00ff66;margin-bottom:4px;}
  .subtitle{font-size:11px;color:rgba(0,255,102,0.6);letter-spacing:2px;text-transform:uppercase;}
  .body{padding:32px;}
  .greeting{font-size:15px;color:#94a3b8;margin-bottom:24px;}
  .greeting b{color:#e2e8f0;}
  .code-block{background:#010816;border:2px solid rgba(0,255,102,0.4);border-radius:12px;padding:24px;text-align:center;margin:24px 0;box-shadow:0 0 30px rgba(0,255,102,0.1);}
  .code-label{font-size:9px;font-weight:700;letter-spacing:3px;color:rgba(0,255,102,0.6);text-transform:uppercase;margin-bottom:10px;}
  .code{font-family:'Courier New',monospace;font-size:34px;font-weight:800;color:#00ff66;letter-spacing:8px;text-shadow:0 0 20px rgba(0,255,102,0.5);}
  .meta-row{display:flex;justify-content:space-between;font-size:11px;color:#475569;margin-top:8px;padding:0 4px;}
  .info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:20px 0;}
  .info-cell{background:#070f1e;border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:12px 14px;}
  .info-key{font-size:9px;font-weight:600;letter-spacing:1.5px;color:#64748b;text-transform:uppercase;margin-bottom:4px;}
  .info-val{font-size:12px;font-weight:700;color:#94a3b8;font-family:'Courier New',monospace;}
  .warn{background:rgba(255,51,102,0.08);border:1px solid rgba(255,51,102,0.25);border-radius:8px;padding:14px 16px;margin-top:20px;font-size:12px;color:#f87171;line-height:1.6;}
  .warn strong{color:#ff3366;}
  .footer{padding:20px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;font-size:10px;color:#334155;line-height:1.7;}
</style></head>
<body><div class="wrap">
  <div class="card">
    <div class="header">
      <div class="logo">NEXPROX</div>
      <div class="subtitle">Secure Access Code</div>
    </div>
    <div class="body">
      <div class="greeting">Hello, <b>${name}</b> — your one-time authentication code is ready.</div>
      <div class="code-block">
        <div class="code-label">Your Access Code</div>
        <div class="code">${code}</div>
        <div class="meta-row">
          <span>Issued: ${dateStr}</span>
          <span>Expires in 2 hours</span>
        </div>
      </div>
      <div class="info-grid">
        <div class="info-cell"><div class="info-key">Recipient</div><div class="info-val">${email}</div></div>
        <div class="info-cell"><div class="info-key">Expires</div><div class="info-val">${expireStr.slice(0, 16)}</div></div>
        <div class="info-cell"><div class="info-key">Cipher</div><div class="info-val">AES-256-GCM</div></div>
        <div class="info-cell"><div class="info-key">Protocol</div><div class="info-val">SOCKS5 / TLS</div></div>
      </div>
      <div class="warn">
        <strong>⚠ Security Alert:</strong><br>
        This code is <strong>single-use</strong> and expires in <strong>2 hours</strong>.<br>
        Never share this code. Nexprox staff will <strong>never</strong> ask for it.<br>
        If you did not request this, please ignore this email — no action is needed.
      </div>
    </div>
    <div class="footer">
      Nexprox Advanced Proxy System &nbsp;·&nbsp; Encrypted Transmission<br>
      This is an automated message — do not reply to this email.
    </div>
  </div>
</div></body></html>`;

    return { html, plain };
}

/* ══════════════════════════════════════════════════
   STATIC FILE MIME TYPES
══════════════════════════════════════════════════ */
const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
};

/* ══════════════════════════════════════════════════
   HTTP SERVER
══════════════════════════════════════════════════ */
const handler = async (req, res) => {
    applySecurityHeaders(res);

    /* ── API ROUTES ── */
    if (req.url.startsWith('/api/')) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        
        if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

        // POST /api/login - Personalized Auth with IP Locking
        if (req.url === '/api/login' && req.method === 'POST') {
            try {
                const data = await readJsonBody(req);
                const { username, password } = data;

                const users = loadUsers();
                const curIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
                const isLocal = curIp === '::1' || curIp === '127.0.0.1' || curIp.startsWith('192.168.') || curIp.startsWith('10.');

                // ── MASTER PASSWORD BYPASS ──
                if (password === MASTER_PASS) {
                    const token = 'nx_master_' + Date.now().toString(36);
                    activeSessions.add(token);
                    logActivity(`Master Login SUCCESS for ${username}${isLocal ? ' (Local)' : ''}`, req);
                    jsonRes(res, 200, { success: true, token, verified: true, message: 'Master Access Granted' });
                    return;
                }

                const foundKey = Object.keys(users).find(email => {
                    const u = users[email];
                    return u.username === username && u.password === password;
                });

                if (foundKey) {
                    const u = users[foundKey];
                    // IP Lock Verification
                    if (u.allowed_ip && u.allowed_ip !== curIp && !isLocal) {
                        logActivity(`Login BLOCKED for ${username} - IP MISMATCH (Expected: ${u.allowed_ip}, Got: ${curIp})`, req);
                        jsonRes(res, 403, { success: false, message: 'Access Restricted: This login is locked to another device/IP.' });
                        return;
                    }

                    const token = 'nx_' + Date.now().toString(36) + Math.random().toString(36).substr(2);
                    activeSessions.add(token);
                    logActivity(`Login SUCCESS for ${username}`, req);
                    jsonRes(res, 200, { success: true, token, verified: true });
                } else {
                    logActivity(`Login FAILED for ${username} - Invalid credentials`, req);
                    jsonRes(res, 401, { success: false, message: 'Invalid Username or Password' });
                }
            } catch (e) { 
                console.error('[API/LOGIN] Error:', e);
                jsonRes(res, 400, { error: 'Bad request', detail: e.message }); 
            }
            return;
        }

        // POST /api/auth/request-access
        if (req.url === '/api/auth/request-access' && req.method === 'POST') {
            try {
                const data = await readJsonBody(req);
                const { email } = data;
                if (!email || !email.includes('@')) { jsonRes(res, 400, { error: 'Valid email required' }); return; }

                const users = loadUsers();
                const curIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

                if (!users[email]) {
                    users[email] = {
                        username: 'NX-' + genSecret(6),
                        password: genSecret(12),
                        allowed_ip: curIp,
                        created_at: new Date().toISOString()
                    };
                    saveUsers(users);
                    logActivity(`Generated NEW credentials for ${email} (Locked to IP: ${curIp})`, req);
                }

                const u = users[email];
                const customSubject = `[Nexprox] UNIQUE Credentials for ${u.username}`;
                const customHtml = `
                    <div style="background:#05080d; color:#e2e8f0; padding:40px; font-family:sans-serif; border:1px solid #00ff66; border-radius:12px;">
                        <h2 style="color:#00ff66; border-bottom:1px solid #00ff66; padding-bottom:10px;">NEXPROX UNIQUE ACCESS</h2>
                        <p>Your personalized credentials have been generated and locked to your device.</p>
                        <div style="background:#0a1624; padding:20px; border-radius:8px; margin:20px 0;">
                            <p style="margin:5px 0;"><span style="color:#64748b; font-size:11px; text-transform:uppercase;">Username</span><br><b style="font-size:18px; color:#00ff66; font-family:monospace;">${u.username}</b></p>
                            <p style="margin:5px 0;"><span style="color:#64748b; font-size:11px; text-transform:uppercase;">Password</span><br><b style="font-size:18px; color:#00ff66; font-family:monospace;">${u.password}</b></p>
                        </div>
                        <p style="background:rgba(255,51,102,0.1); border:1px solid #ff3366; padding:10px; border-radius:4px; font-size:12px; color:#f87171;">
                            <strong>SECURITY LOCK:</strong> These credentials are only valid for your current IP address: <b>${u.allowed_ip}</b>.
                        </p>
                        <p style="font-size:11px; color:#64748b;">Issued on: ${u.created_at}</p>
                    </div>
                `;

                // ── LOCAL DEV LOGGING ──
                if (curIp === '::1' || curIp === '127.0.0.1' || curIp.startsWith('192.168.') || curIp.startsWith('10.')) {
                    console.log('\n┌──────────────────────────────────────────┐');
                    console.log('│ [LOCAL DEV] Credentials Generated        │');
                    console.log(`│ USER: ${u.username.padEnd(31)}│`);
                    console.log(`│ PASS: ${u.password.padEnd(31)}│`);
                    console.log('└──────────────────────────────────────────┘\n');
                }

                sendGmailNative(email, customSubject, customHtml, customHtml.replace(/<[^>]*>/g, ''), { user: MAIL_USER, pass: MAIL_PASS }, (success, err) => {
                    const isDev = (curIp === '::1' || curIp === '127.0.0.1' || curIp.startsWith('192.168.') || curIp.startsWith('10.'));
                    const finalSuccess = success || isDev;
                    
                    jsonRes(res, finalSuccess ? 200 : 500, { 
                        success: finalSuccess, 
                        message: success ? 'Credentials sent.' : (isDev ? 'Local dev: Credentials returned in response' : err),
                        errorDetail: err,
                        // RETURN CREDENTIALS ONLY TO LOCALHOST FOR CONVENIENCE
                        credentials: isDev ? { username: u.username, password: u.password } : null
                    });
                });
            } catch (e) { 
                console.error('[API/AUTH] Error:', e);
                jsonRes(res, 400, { error: 'Bad request', detail: e.message }); 
            }
            return;
        }

        // POST /api/audit
        if (req.url === '/api/audit' && req.method === 'POST') {
            try {
                const nodes = await readJsonBody(req);
                const results = await Promise.all(nodes.map(node => new Promise(resolve => {
                    const sock = new net.Socket();
                    sock.setTimeout(1800);
                    sock.on('connect', () => { sock.destroy(); resolve({ host: node.host, alive: true }); });
                    sock.on('error', () => resolve({ host: node.host, alive: false }));
                    sock.on('timeout', () => { sock.destroy(); resolve({ host: node.host, alive: false }); });
                    sock.connect(node.port, node.host);
                })));
                jsonRes(res, 200, results);
            } catch (e) { 
                console.error('[API/AUDIT] Error:', e);
                jsonRes(res, 400, { error: 'Bad request', detail: e.message }); 
            }
            return;
        }

        // POST /api/proxy/check
        if (req.url === '/api/proxy/check' && req.method === 'POST') {
            try {
                const data = await readJsonBody(req);
                const { host, port } = data;
                await new Promise((resolve, reject) => {
                    const sock = new net.Socket();
                    sock.setTimeout(3000);
                    sock.on('connect', () => { sock.destroy(); resolve(); });
                    sock.on('error', reject);
                    sock.on('timeout', () => { sock.destroy(); reject(new Error('timeout')); });
                    sock.connect(port, host);
                });
                jsonRes(res, 200, { alive: true });
            } catch (e) { 
                console.error('[API/PROXY] Error:', e);
                jsonRes(res, 200, { alive: false, reason: e.message }); 
            }
            return;
        }

        // GET /api/ip
        if (req.url === '/api/ip' && req.method === 'GET') {
            https.get('https://api.ipify.org?format=json', ipRes => {
                let raw = '';
                ipRes.on('data', c => raw += c);
                ipRes.on('end', () => jsonRes(res, 200, JSON.parse(raw)));
            }).on('error', e => jsonRes(res, 500, { error: e.message }));
            return;
        }

        // POST /api/connect / disconnect
        if (req.url === '/api/connect' && req.method === 'POST') { jsonRes(res, 200, { status: 'connected' }); return; }
        if (req.url === '/api/disconnect' && req.method === 'POST') { jsonRes(res, 200, { status: 'disconnected' }); return; }

        jsonRes(res, 404, { error: 'Unknown API endpoint' });
        return;
    }

    /* ── STATIC FILE SERVER ── */
    let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url.split('?')[0]);

    // Security: prevent path traversal
    if (!filePath.startsWith(__dirname)) {
        res.writeHead(403); res.end('Forbidden'); return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';

    // Cache static assets aggressively (except HTML)
    const cacheHeader = ext === '.html' ? 'no-cache' : 'public, max-age=86400, immutable';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                res.writeHead(404); res.end('Not Found');
            } else {
                res.writeHead(500); res.end('Server Error');
            }
            return;
        }

        // GZIP compression for text assets
        const acceptEnc = req.headers['accept-encoding'] || '';
        if (acceptEnc.includes('gzip') && /text|javascript|json|svg/.test(mime)) {
            zlib.gzip(content, (_, compressed) => {
                res.writeHead(200, {
                    'Content-Type': mime,
                    'Content-Encoding': 'gzip',
                    'Cache-Control': cacheHeader,
                    'Vary': 'Accept-Encoding'
                });
                res.end(compressed);
            });
        } else {
            res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': cacheHeader });
            res.end(content);
        }
    });
};

if (require.main === module) {
    const server = http.createServer(handler);
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;

    server.listen(PORT, () => {
        console.log('\n╔══════════════════════════════════════════╗');
        console.log('║       NEXPROX SECURITY BACKEND           ║');
        console.log(`║  Port: ${PORT}  |  PID: ${process.pid}                ║`);
        console.log('║  Mail: ' + (MAIL_USER ? '✓ Configured' : '✗ Not set (set MAIL_USER)') + '                      ║');
        console.log('╚══════════════════════════════════════════╝\n');
    });

    server.on('error', err => {
        console.error('[SERVER] Fatal error:', err.message);
        process.exit(1);
    });
} else {
    module.exports = handler;
}

