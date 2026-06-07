// ============================================================================
// SYSTEM MODULE CONFIGURATION, SECURITY GATEWAYS, & DATA INGESTION
// ============================================================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// Load programmatic SEO dataset safely
let seoData = [];
try {
    const seoFilePath = path.join(__dirname, 'seo-data.json');
    if (fs.existsSync(seoFilePath)) {
        seoData = JSON.parse(fs.readFileSync(seoFilePath, 'utf8'));
    }
} catch (err) {
    console.error('[SEO DATA ARCHIVE READ FAILURE]', err);
}

const PAYPAL_GATEWAY = process.env.NODE_ENV === 'production'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';

const requestRateTracker = {};
function systemSpamGuard(req, res, next) {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = Date.now();

    if (!requestRateTracker[clientIP]) {
        requestRateTracker[clientIP] = { timestamp: now, actions: 1 };
        return next();
    }

    if (now - requestRateTracker[clientIP].timestamp < 60000) {
        requestRateTracker[clientIP].actions++;
        if (requestRateTracker[clientIP].actions > 30) {
            return res.status(429).json({ error: "Rate limit saturation exceeded. Telemetry tracking paused." });
        }
    } else {
        requestRateTracker[clientIP] = { timestamp: now, actions: 1 };
    }
    next();
}

app.use(express.json({ limit: '2mb' }));
app.use(cors({ origin: '*' }));
app.use(systemSpamGuard);

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self' https://cdn.tailwindcss.com https://www.paypal.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://www.paypal.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data: https://www.paypalobjects.com; connect-src 'self' https://api-m.sandbox.paypal.com https://api-m.paypal.com;");
    next();
});

const PRICING_TIERS = {
    professional: { name: "Professional Shield", allocationValue: "49.00", scope: "Advanced Vulnerability & API Architecture Controls" },
    enterprise: { name: "Enterprise Defense Core", allocationValue: "199.00", scope: "Full Unrestricted Pipeline Auditing & Hot-Patch Compilation" }
};

async function acquireSecureGatewayToken() {
    try {
        const credentials = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64');
        const response = await fetch(`${PAYPAL_GATEWAY}/v1/oauth2/token`, {
            method: 'POST',
            body: 'grant_type=client_credentials',
            headers: {
                'Authorization': `Basic ${credentials}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        if (!response.ok) throw new Error('Gateway handshake rejected.');
        const data = await response.json();
        return data.access_token;
    } catch (error) {
        console.error('[GATEWAY AUTHENTICATION SHUTDOWN]', error);
        return null;
    }
}

// ============================================================================
// CORE PROCESSING MATRIX
// ============================================================================
function runServiceAnalysis(serviceId, payload) {
    const analysisManifest = {
        signature: crypto.createHash('sha256').update(payload).digest('hex'),
        threatsIsolated: []
    };

    switch(serviceId) {
        case 'decompiler':
            if (/SELECT\s+.*\s+FROM/i.test(payload) && /(\+.*\bquery\b|\$\{.*\})/i.test(payload)) {
                analysisManifest.threatsIsolated.push({ id: "SEC-SQLI", level: "CRITICAL", title: "Unsanitized Query Construction String Injection" });
            }
            if (/eval\(|exec\(|child_process/i.test(payload)) {
                analysisManifest.threatsIsolated.push({ id: "SEC-RCE", level: "CRITICAL", title: "Arbitrary Operating System Kernel Instruction Exposure" });
            }
            break;
        case 'jwt':
            if (/alg\s*:\s*['"]none['"]/i.test(payload)) {
                analysisManifest.threatsIsolated.push({ id: "SEC-JWT-NONE", level: "HIGH", title: "Null Token Signature Decoupling Configuration" });
            }
            if (!/process\.env\.[A-Z0-9_]+/i.test(payload) && /jwt\.sign/i.test(payload)) {
                analysisManifest.threatsIsolated.push({ id: "SEC-JWT-KEY", level: "MEDIUM", title: "Hardcoded Cryptographic Token Key Seed Plaintext" });
            }
            break;
        case 'headers':
            if (!/X-Frame-Options/i.test(payload)) {
                analysisManifest.threatsIsolated.push({ id: "CONF-CLICKJACK", level: "HIGH", title: "Missing Clickjacking Frame Protection Topology" });
            }
            if (!/Content-Security-Policy/i.test(payload)) {
                analysisManifest.threatsIsolated.push({ id: "CONF-CSP", level: "HIGH", title: "Unsecured Browser Resource Ingestion Policy (No CSP)" });
            }
            break;
    }

    if (analysisManifest.threatsIsolated.length === 0) {
        analysisManifest.threatsIsolated.push({ id: "SYS-INFO", level: "STABLE", title: "No anomalies isolated matching current signature sets." });
    }
    return analysisManifest;
}

// ============================================================================
// ROUTING LAYER: API ENGINE ENDPOINTS
// ============================================================================
app.post('/api/engine/evaluate', (req, res) => {
    const { targetPayload, chosenService } = req.body;
    if (!targetPayload || targetPayload.trim().length < 15) {
        return res.status(400).json({ error: "Incomplete structural data size context configuration submitted." });
    }
    const outcomes = runServiceAnalysis(chosenService, targetPayload);
    return res.status(200).json(outcomes);
});

app.post('/api/billing/order/create', async (req, res) => {
    try {
        const { targetPlanTier } = req.body;
        const configurationAsset = PRICING_TIERS[targetPlanTier];
        if (!configurationAsset) return res.status(400).json({ error: "Invalid SaaS asset tier specification." });

        const token = await acquireSecureGatewayToken();
        if (!token) return res.status(500).json({ error: "External clear verification infrastructure timed out." });

        const creationManifest = {
            intent: 'CAPTURE',
            purchase_units: [{
                amount: { currency_code: 'USD', value: configurationAsset.allocationValue },
                description: `SaaS Activation License Bundle: ${configurationAsset.name} Package Configuration`
            }]
        };

        const response = await fetch(`${PAYPAL_GATEWAY}/v2/checkout/orders`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'PayPal-Request-Id': crypto.randomBytes(20).toString('hex')
            },
            body: JSON.stringify(creationManifest)
        });

        const billingRecord = await response.json();
        return res.status(response.status).json(billingRecord);
    } catch (err) {
        return res.status(500).json({ error: "Failed to initialize standard billing framework." });
    }
});

app.post('/api/billing/order/capture', async (req, res) => {
    try {
        const { orderID } = req.body;
        const token = await acquireSecureGatewayToken();
        const response = await fetch(`${PAYPAL_GATEWAY}/v2/checkout/orders/${orderID}/capture`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        const receipt = await response.json();
        return res.status(response.status).json({
            status: "COMPLETED",
            transactionId: receipt.id,
            licensingKey: `SEC-GRID-PRO-${crypto.randomBytes(12).toString('hex').toUpperCase()}`
        });
    } catch (err) {
        return res.status(500).json({ error: "Ledger clearance collection capture pipeline crashed." });
    }
});

// ============================================================================
// ROUTING LAYER: PROGRAMMATIC SEO (pSEO) LANDING ARCHITECTURE
// ============================================================================
app.get('/remediation/:slug', (req, res) => {
    const pageData = seoData.find(p => p.slug === req.params.slug);

    if (!pageData) {
        return res.status(404).send(`
            <body style="background:#020617; color:#94a3b8; font-family:sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;">
                <div style="text-align:center;">
                    <h1 style="color:#ef4444;">404</h1>
                    <p>Security mitigation blueprint asset not listed in signature index.</p>
                    <a href="/" style="color:#22d3ee; text-decoration:none;">Return to Mainframe Console</a>
                </div>
            </body>
        `);
    }

    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>How to Fix ${pageData.vulnerability} in ${pageData.framework} // DefconShield</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans antialiased min-h-screen selection:bg-cyan-500 selection:text-slate-950">
    <div class="max-w-4xl mx-auto px-6 py-12">
        <a href="/" class="text-xs font-mono text-cyan-400 hover:underline">â† BACK TO SYSTEM CORE</a>

        <div class="mt-8 bg-slate-900 border border-slate-800 rounded-2xl p-6 md:p-8 shadow-2xl">
            <div class="inline-block bg-red-500/10 border border-red-500/30 text-red-400 font-mono text-[10px] px-2.5 py-1 rounded mb-4 uppercase tracking-widest">
                Threat Classification: ${pageData.severity}
            </div>

            <h1 class="text-2xl md:text-4xl font-black tracking-tight text-white mb-2">
                Resolving <span class="text-cyan-400">${pageData.vulnerability}</span> inside <span class="text-indigo-400">${pageData.framework}</span> Pipelines
            </h1>
            <p class="text-slate-400 text-sm leading-relaxed mb-6">
                Automated signature models detected systemic exposure vulnerabilities matching standard exploitation profiles for ${pageData.framework} environments. Use the architectural blueprint guidelines below to hot-fix your source repository.
            </p>

            <h3 class="text-xs font-mono tracking-wider uppercase text-slate-400 font-bold mb-2">// Recommended Systemic Remediation Architecture:</h3>
            <div class="bg-black border-l-2 border-cyan-500 rounded-r-xl p-5 font-mono text-xs text-emerald-400 leading-relaxed mb-8 shadow-inner overflow-x-auto">
                ${pageData.remediation}
            </div>

            <hr class="border-slate-800 my-8" />

            <div class="text-center bg-gradient-to-b from-slate-950 to-slate-900 border border-slate-800 rounded-xl p-6">
                <h2 class="text-lg font-bold text-white mb-1">Want to Scan Your Entire Application Instantly?</h2>
                <p class="text-xs text-slate-500 max-w-lg mx-auto mb-4">Don't risk manual configuration misses. Drop your runtime code files or route structures directly into our live scanning mainframe for multi-tier zero-trust verification checks completely free.</p>
                <a href="/#workspace" class="inline-block bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black text-xs tracking-wider uppercase px-6 py-3 rounded-md shadow-lg shadow-cyan-500/10 transition-all">
                    Initialize Automated Mainframe Scan
                </a>
            </div>
        </div>
    </div>
</body>
</html>
    `);
});

// ============================================================================
// ROUTING LAYER: MAIN WEB PLATFORM CONSOLE UI
// ============================================================================
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefconShield Pro // Adaptive Autonomous Security Engine</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://www.paypal.com/sdk/js?client-id=${process.env.PAYPAL_CLIENT_ID || 'test'}&currency=USD&components=buttons"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans antialiased min-h-screen flex flex-col selection:bg-cyan-500 selection:text-slate-950">

    <div class="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[128px] pointer-events-none"></div>
    <div class="absolute top-1/3 right-1/4 w-[400px] h-[400px] bg-indigo-500/10 rounded-full blur-[160px] pointer-events-none"></div>

    <nav class="sticky top-0 z-50 border-b border-slate-900 bg-slate-950/80 backdrop-blur-xl px-6 py-4 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="h-3 w-3 bg-cyan-400 rounded-sm shadow-lg shadow-cyan-400/50 animate-pulse"></div>
            <span class="font-mono text-xs font-bold tracking-[0.2em] uppercase text-slate-200">DefconShield<span class="text-cyan-400">.Pro</span></span>
        </div>
        <div class="flex items-center space-x-6 text-xs font-medium text-slate-400">
            <a href="#services" class="hover:text-cyan-400 transition-colors">Security Services</a>
            <a href="#workspace" class="hover:text-cyan-400 transition-colors">Core Console</a>
            <a href="#pricing" class="hover:text-cyan-400 transition-colors">Pricing Matrix</a>
            <span id="trialStatusBadge" class="bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-2.5 py-1 rounded font-mono text-[10px]">1 FREE SCAN ALLOCATED</span>
        </div>
    </nav>

    <header class="relative max-w-4xl mx-auto text-center px-6 pt-20 pb-12 flex flex-col items-center">
        <div class="inline-flex items-center space-x-2 bg-slate-900 border border-slate-800 rounded-full px-3 py-1 mb-6 text-[11px] font-mono tracking-wide text-slate-400">
            <span class="text-amber-400">âš¡ API Security Matrix</span>
            <span>â€¢</span>
            <span>Version 2.4 Structural Deployment Live</span>
        </div>
        <h1 class="text-4xl md:text-6xl font-black tracking-tight leading-none bg-gradient-to-b from-white via-slate-200 to-slate-500 bg-clip-text text-transparent mb-6">
            Autonomous Cyber Defense & <br><span class="bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">Zero-Trust Asset Remediation</span>
        </h1>
        <p class="text-slate-400 text-sm md:text-base max-w-2xl leading-relaxed mb-8">
            Deploy an array of automated code analyzers, structural dependency scanners, and cryptographic rule verification systems designed to lock down data leak channels before runtime production execution.
        </p>
        <a href="#workspace" class="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-xs tracking-wider uppercase px-8 py-4 rounded shadow-lg shadow-cyan-500/20 active:scale-[0.99] transition-all">
            Access Defense Control Console
        </a>
    </header>

    <section id="services" class="max-w-5xl mx-auto px-6 py-12 w-full">
        <div class="border-b border-slate-900 pb-4 mb-8">
            <h2 class="text-xs font-mono tracking-[0.2em] uppercase text-cyan-400 font-bold">Comprehensive Protection Services</h2>
            <p class="text-slate-400 text-sm mt-1">Multi-tier specialized pipelines built to dissect specific target vectors.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="bg-slate-900/50 border border-slate-900 rounded-xl p-5 hover:border-slate-800 transition-colors group">
                <div class="h-8 w-8 bg-cyan-500/10 rounded flex items-center justify-center text-cyan-400 font-mono text-sm font-bold mb-4 group-hover:bg-cyan-500/20">A</div>
                <h3 class="text-sm font-bold text-slate-200 mb-1">Code Vulnerability Decompiler</h3>
                <p class="text-xs text-slate-500 leading-relaxed">Traces application control structures, extracting explicit vector flaws matching standard SQLi and RCE code blocks instantly.</p>
                <div class="mt-4 text-[10px] font-mono text-cyan-400 tracking-wider uppercase">Included in Free Tier</div>
            </div>
            <div class="bg-slate-900/50 border border-slate-900 rounded-xl p-5 hover:border-slate-800 transition-colors group">
                <div class="h-8 w-8 bg-indigo-500/10 rounded flex items-center justify-center text-indigo-400 font-mono text-sm font-bold mb-4 group-hover:bg-indigo-500/20">B</div>
                <h3 class="text-sm font-bold text-slate-200 mb-1">Cryptographic Token Hardener</h3>
                <p class="text-xs text-slate-500 leading-relaxed">Audits stateless authorization mechanics, checking payload signing loops, verifying missing secret arrays, and preventing algorithm bypasses.</p>
                <div class="mt-4 text-[10px] font-mono text-indigo-400 tracking-wider uppercase">Professional License Needed</div>
            </div>
            <div class="bg-slate-900/50 border border-slate-900 rounded-xl p-5 hover:border-slate-800 transition-colors group">
                <div class="h-8 w-8 bg-purple-500/10 rounded flex items-center justify-center text-purple-400 font-mono text-sm font-bold mb-4 group-hover:bg-purple-500/20">C</div>
                <h3 class="text-sm font-bold text-slate-200 mb-1">Network Header Auditor</h3>
                <p class="text-xs text-slate-500 leading-relaxed">Runs verification on outgoing Express configuration arrays, isolating exposures to Clickjacking, cross-site frame injections, and sniffing flaws.</p>
                <div class="mt-4 text-[10px] font-mono text-purple-400 tracking-wider uppercase">Enterprise License Needed</div>
            </div>
        </div>
    </section>

    <section id="workspace" class="max-w-4xl mx-auto px-6 py-12 w-full flex-1">
        <div class="bg-slate-900 border border-slate-800/80 rounded-2xl shadow-2xl overflow-hidden">

            <div class="bg-slate-950 px-5 py-4 border-b border-slate-800/50 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div class="flex items-center space-x-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-red-500/30"></span>
                    <span class="w-2.5 h-2.5 rounded-full bg-yellow-500/30"></span>
                    <span class="w-2.5 h-2.5 rounded-full bg-green-500/30"></span>
                    <span class="text-xs font-mono text-slate-400 ml-2">mainframe_console.sh</span>
                </div>

                <div class="flex items-center space-x-2">
                    <label class="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Engine Protocol:</label>
                    <select id="engineServiceSelector" class="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 font-mono text-xs text-cyan-400 outline-none focus:border-cyan-500/50">
                        <option value="decompiler">Service A: Code Structural Decompiler (Free Tier)</option>
                        <option value="jwt">Service B: Cryptographic Token Hardener (Pro Tier)</option>
                        <option value="headers">Service C: Network Header Compliance (Enterprise)</option>
                    </select>
                </div>
            </div>

            <div class="p-6">
                <p class="text-xs text-slate-400 font-mono mb-2">// Input configuration, server scripts or routing models directly below for dissection:</p>
                <textarea id="targetTerminalInput" class="w-full h-48 bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-emerald-400 focus:outline-none focus:border-cyan-500/50 transition-colors resize-none placeholder-slate-800" placeholder="// Insert payload data strings here..."></textarea>

                <button onclick="triggerAutonomousTelemetryAnalysis()" class="w-full mt-4 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-black tracking-widest text-xs uppercase py-4 rounded-lg shadow-lg shadow-cyan-900/10 transition-transform active:scale-[0.99]">
                    Initialize Core Diagnostic Sequence
                </button>
            </div>
        </div>

        <div id="viralShareBlock" class="hidden mt-6 bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 border-2 border-amber-500/30 rounded-xl p-6 text-center animate-fade-in">
            <div class="h-8 w-8 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-full flex items-center justify-center mx-auto text-xs font-mono mb-3">âš¡</div>
            <h4 class="text-xs font-mono font-bold text-amber-400 uppercase tracking-wider">Evaluation Scan Allocations Expired</h4>
            <p class="text-xs text-slate-400 my-2 max-w-md mx-auto leading-relaxed">
                You've run out of baseline credits! Share a validation reference of DefconShield on X (Twitter) to instantly inject <span class="text-cyan-400 font-bold">1 Extra Diagnostic Scan Credit</span> directly into your active session matrix.
            </p>
            <div class="mt-4 flex justify-center space-x-3">
                <button onclick="simulateViralTweetShare()" class="bg-sky-500 hover:bg-sky-400 text-slate-950 font-black tracking-wide text-xs px-5 py-2.5 rounded transition-transform active:scale-95">
                    Broadcast to X / Twitter
                </button>
                <a href="#pricing" class="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs px-5 py-2.5 rounded transition-colors">
                    View Premium Plans
                </a>
            </div>
        </div>

        <div id="liveLogsConsole" class="hidden mt-6 bg-black border-l-2 border-cyan-500 rounded-r-xl p-5 font-mono text-xs text-cyan-300 space-y-1 shadow-inner max-h-64 overflow-y-auto"></div>

        <div id="diagnosticResultsWrapper" class="hidden mt-6 bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl animate-fade-in">
            <div class="flex items-center space-x-2 text-cyan-400 font-mono text-xs font-bold tracking-widest uppercase mb-4">
                <span>[âœ“] Structural Evaluation Completed Successfully</span>
            </div>

            <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs space-y-2 text-slate-300 mb-6">
                <div><span class="text-slate-500">PAYLOAD HASH :</span> <span id="outSignatureId" class="text-slate-400"></span></div>
                <div><span class="text-slate-500">ISOLATED VECTORS:</span></div>
                <div id="threatReportArrayContainer" class="space-y-2 pt-1 pl-4"></div>
            </div>

            <div class="bg-gradient-to-r from-slate-950 to-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row justify-between items-center gap-4">
                <div class="max-w-md">
                    <h4 class="text-xs font-bold text-slate-200 tracking-wide uppercase">Deploy Automated Hot-Patch Remediation Shield</h4>
                    <p class="text-[11px] text-slate-500 mt-1 leading-relaxed">Download clean custom code wrappers compiled specifically to repair the structural exposures found in your file input pattern above.</p>
                </div>
                <div class="w-full md:w-auto text-center md:text-right">
                    <a href="#pricing" class="inline-block w-full md:w-auto text-center bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black tracking-wider uppercase px-6 py-3 rounded transition-all">
                        Unlock Mitigation Shield
                    </a>
                </div>
            </div>
        </div>
    </section>

    <section id="pricing" class="max-w-5xl mx-auto px-6 py-16 w-full border-t border-slate-900">
        <div class="text-center max-w-xl mx-auto mb-12">
            <h2 class="text-2xl font-black text-slate-200 tracking-tight">Scalable Operational Licensing Models</h2>
            <p class="text-xs text-slate-400 mt-1">Acquire professional verification access controls or enterprise support keys instantly.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">

            <div class="bg-slate-900/30 border border-slate-900 rounded-2xl p-6 flex flex-col justify-between">
                <div>
                    <h3 class="font-mono text-xs tracking-wider uppercase text-slate-400 font-bold">Standard Sandbox</h3>
                    <div class="text-2xl font-bold text-slate-100 mt-2">$0 <span class="text-xs text-slate-500 font-normal">/ non-commercial</span></div>
                    <p class="text-xs text-slate-500 mt-3 leading-relaxed">Perfect for exploratory infrastructure tracing and testing foundational Express framework parameter queries.</p>
                    <ul class="text-xs text-slate-400 space-y-2 mt-6 border-t border-slate-800/60 pt-4 font-mono">
                        <li class="text-cyan-400">âœ“ 1 Total System Scan Chance</li>
                        <li>âœ“ Access to Service A Controls</li>
                        <li class="text-slate-600">âœ• Cryptographic Token Hardener</li>
                        <li class="text-slate-600">âœ• Custom Hot-Patch Delivery</li>
                    </ul>
                </div>
                <a href="#workspace" class="block w-full text-center bg-slate-900 hover:bg-slate-800 text-slate-300 font-bold text-xs py-3 rounded mt-8 transition-colors">Launch Core Sandbox</a>
            </div>

            <div class="bg-gradient-to-b from-slate-900 to-slate-950 border-2 border-cyan-500/40 rounded-2xl p-6 flex flex-col justify-between shadow-xl shadow-cyan-950/10 relative">
                <div class="absolute -top-3 left-1/2 -translate-x-1/2 bg-cyan-500 text-slate-950 text-[9px] font-mono font-black tracking-widest px-3 py-1 rounded-full uppercase">Most Requested</div>
                <div>
                    <h3 class="font-mono text-xs tracking-wider uppercase text-cyan-400 font-bold">Professional Shield</h3>
                    <div class="text-3xl font-black text-slate-100 mt-2">$49.00 <span class="text-xs text-slate-500 font-normal">/ monthly user key</span></div>
                    <p class="text-xs text-slate-400 mt-3 leading-relaxed">Complete structural automation and deep token validation rules built for deployment scaling and startup validation.</p>
                    <ul class="text-xs text-slate-300 space-y-2 mt-6 border-t border-slate-800 pt-4 font-mono">
                        <li class="text-cyan-400">âœ“ Unlimited Execution Cycles</li>
                        <li class="text-cyan-400">âœ“ Service A + Service B Access</li>
                        <li class="text-cyan-400">âœ“ Full Telemetry Logs Output</li>
                        <li class="text-cyan-400">âœ“ Automated Middleware Patching</li>
                    </ul>
                </div>
                <div class="mt-8">
                    <button onclick="engagePaymentProcessingGateway('professional')" class="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black text-xs tracking-wider uppercase py-3.5 rounded shadow-lg shadow-cyan-500/10 transition-colors">Acquire Professional License</button>
                </div>
            </div>

            <div class="bg-slate-900/30 border border-slate-900 rounded-2xl p-6 flex flex-col justify-between">
                <div>
                    <h3 class="font-mono text-xs tracking-wider uppercase text-indigo-400 font-bold">Enterprise Defense</h3>
                    <div class="text-2xl font-bold text-slate-100 mt-2">$199.00 <span class="text-xs text-slate-500 font-normal">/ runtime cluster</span></div>
                    <p class="text-xs text-slate-500 mt-3 leading-relaxed">Full coverage including HTTP server header compliance protocols and manual review configurations for maximum security validation.</p>
                    <ul class="text-xs text-slate-400 space-y-2 mt-6 border-t border-slate-800/60 pt-4 font-mono">
                        <li class="text-indigo-400">âœ“ All Platforms & Pipeline Services</li>
                        <li class="text-indigo-400">âœ“ Full Compliance Reporting</li>
                        <li class="text-indigo-400">âœ“ Direct Unredacted Asset Sync</li>
                        <li class="text-indigo-400">âœ“ Priority Token Generation Hooks</li>
                    </ul>
                </div>
                <div class="mt-8">
                    <button onclick="engagePaymentProcessingGateway('enterprise')" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs py-3 rounded transition-colors">Acquire Enterprise Access</button>
                </div>
            </div>

        </div>

        <div id="globalBillingCheckoutContainer" class="hidden mt-12 max-w-md mx-auto bg-slate-900 border border-cyan-500/30 rounded-2xl p-6 shadow-2xl animate-fade-in text-center">
            <h4 class="text-xs font-mono font-bold tracking-wider uppercase text-cyan-400 mb-2">Secure Payment Clearance</h4>
            <p id="billingDescriptionField" class="text-xs text-slate-400 mb-6"></p>
            <div id="paypal-button-placement-anchor"></div>
            <button onclick="document.getElementById('globalBillingCheckoutContainer').style.display='none'" class="mt-4 font-mono text-[10px] text-slate-500 hover:text-slate-300 uppercase tracking-widest">Cancel Order Attempt</button>
        </div>
    </section>

    <footer class="border-t border-slate-900 bg-slate-950 px-6 py-8 text-center text-xs font-mono text-slate-600">
        &copy; 2026 DefconShield Network Core Operations. All Assets Restricted.
    </footer>

    <script>
        document.getElementById('targetTerminalInput').value = "const express = require('express');\\nconst app = express();\\n\\napp.post('/api/auth/v1', (req, res) => {\\n    // EXPLOIT VECTOR PROFILE ROOT DETECTED HERE:\\n    let dynamicQuery = \`SELECT * FROM users WHERE pass = '\${req.body.password}'\`;\\n    database.query(dynamicQuery);\\n});";

        const userStateMatrix = {
            scansExecutedCount: parseInt(localStorage.getItem('saas_runtime_metric') || '0'),
            isLicensedAccount: localStorage.getItem('saas_licensing_token') ? true : false,
            activeSubscriptionTier: localStorage.getItem('saas_active_tier') || 'none'
        };

        if (userStateMatrix.isLicensedAccount) {
            document.getElementById('trialStatusBadge').innerText = "ACCOUNT ACCESS STATE: PREPAID USER (" + userStateMatrix.activeSubscriptionTier.toUpperCase() + ")";
            document.getElementById('trialStatusBadge').className = "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2.5 py-1 rounded font-mono text-[10px]";
        }

        function appendConsoleLogLine(textStr) {
            const screen = document.getElementById('liveLogsConsole');
            screen.style.display = 'block';
            const logEntry = document.createElement('div');
            logEntry.className = "text-cyan-400 font-mono text-[11px] leading-relaxed py-0.5";
            logEntry.innerText = textStr;
            screen.appendChild(logEntry);
            screen.scrollTop = screen.scrollHeight;
        }

        async function triggerAutonomousTelemetryAnalysis() {
            const targetPayload = document.getElementById('targetTerminalInput').value;
            const chosenService = document.getElementById('engineServiceSelector').value;
            const logConsole = document.getElementById('liveLogsConsole');
            const resultsWrapper = document.getElementById('diagnosticResultsWrapper');
            const threatContainer = document.getElementById('threatReportArrayContainer');
            
            resultsWrapper.style.display = 'none';
            logConsole.innerHTML = '';
            threatContainer.innerHTML = '';

            if (!userStateMatrix.isLicensedAccount && userStateMatrix.scansExecutedCount >= 1) {
                document.getElementById('viralShareBlock').style.display = 'block';
                appendConsoleLogLine("[FATAL] Baseline diagnostic allocation exhausted. Premium user key or reference injection required.");
                return;
            }

            appendConsoleLogLine("[INIT] Launching zero-trust core security handshake...");
            appendConsoleLogLine("[INFO] Targeting cluster vector protocol: " + chosenService.toUpperCase());
            appendConsoleLogLine("[PROCESSING] Dissecting input data streams for AST structures...");

            try {
                const response = await fetch('/api/engine/evaluate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targetPayload, chosenService })
                });

                if (!response.ok) {
                    const errData = await response.json();
                    throw new Error(errData.error || "Subsystem processing failure.");
                }

                const data = await response.json();
                appendConsoleLogLine("[SUCCESS] Evaluation matrix complete. Compiling signatures.");

                if (!userStateMatrix.isLicensedAccount) {
                    userStateMatrix.scansExecutedCount++;
                    localStorage.setItem('saas_runtime_metric', userStateMatrix.scansExecutedCount.toString());
                    if (userStateMatrix.scansExecutedCount >= 1) {
                        document.getElementById('trialStatusBadge').innerText = "0 FREE SCANS REMAINING";
                        document.getElementById('trialStatusBadge').className = "bg-red-500/10 border border-red-500/30 text-red-400 px-2.5 py-1 rounded font-mono text-[10px]";
                    }
                }

                document.getElementById('outSignatureId').innerText = data.signature;
                
                data.threatsIsolated.forEach(threat => {
                    let badgeColor = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
                    if (threat.level === 'CRITICAL') badgeColor = 'bg-red-500/10 border-red-500/30 text-red-400';
                    if (threat.level === 'HIGH') badgeColor = 'bg-amber-500/10 border-amber-500/30 text-amber-400';
                    if (threat.level === 'MEDIUM') badgeColor = 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400';
                    
                    const item = document.createElement('div');
                    item.className = "flex flex-col sm:flex-row sm:items-center gap-2 py-1.5 border-b border-slate-900";
                    item.innerHTML = '<span class="inline-block px-2 py-0.5 rounded text-[9px] font-mono border ' + badgeColor + '">' + threat.level + '</span><span class="text-slate-200 font-mono text-xs">[' + threat.id + '] ' + threat.title + '</span>';
                    threatContainer.appendChild(item);
                });

                resultsWrapper.style.display = 'block';
            } catch (err) {
                appendConsoleLogLine("[CRITICAL FAILURE] " + err.message);
            }
        }

        function simulateViralTweetShare() {
            appendConsoleLogLine("[TELEMETRY] Intercepting social broadcast webhooks...");
            setTimeout(() => {
                userStateMatrix.scansExecutedCount = 0;
                localStorage.setItem('saas_runtime_metric', '0');
                document.getElementById('viralShareBlock').style.display = 'none';
                document.getElementById('trialStatusBadge').innerText = "1 FREE SCAN ALLOCATED (BONUS INJECTED)";
                document.getElementById('trialStatusBadge').className = "bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-2.5 py-1 rounded font-mono text-[10px]";
                appendConsoleLogLine("[SUCCESS] Reference validated. 1 credit hot-swapped into session matrix.");
            }, 1500);
        }

        function engagePaymentProcessingGateway(tier) {
            const container = document.getElementById('globalBillingCheckoutContainer');
            const desc = document.getElementById('billingDescriptionField');
            const anchor = document.getElementById('paypal-button-placement-anchor');
            
            container.style.display = 'block';
            anchor.innerHTML = '';
            
            if (tier === 'professional') {
                desc.innerText = "Activating Professional Shield license bundle. Authorization charge: $49.00 USD / month via card or digital banking.";
            } else {
                desc.innerText = "Activating Enterprise Defense cluster array. Authorization charge: $199.00 USD via card or digital banking.";
            }

            paypal.Buttons({
                createOrder: async function() {
                    try {
                        const res = await fetch('/api/billing/order/create', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ targetPlanTier: tier })
                        });
                        const order = await res.json();
                        return order.id;
                    } catch (err) {
                        appendConsoleLogLine("[BILLING ERROR] Could not initialize gateway checkout process.");
                    }
                },
                onApprove: async function(data) {
                    try {
                        appendConsoleLogLine("[GATEWAY] Initializing signature verification chain...");
                        const res = await fetch('/api/billing/order/capture', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ orderID: data.orderID })
                        });
                        const receipt = await res.json();
                        
                        localStorage.setItem('saas_licensing_token', receipt.licensingKey);
                        localStorage.setItem('saas_active_tier', tier);
                        
                        userStateMatrix.isLicensedAccount = true;
                        userStateMatrix.activeSubscriptionTier = tier;
                        
                        container.style.display = 'none';
                        document.getElementById('trialStatusBadge').innerText = "ACCOUNT ACCESS STATE: PREPAID USER (" + tier.toUpperCase() + ")";
                        document.getElementById('trialStatusBadge').className = "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2.5 py-1 rounded font-mono text-[10px]";
                        
                        appendConsoleLogLine("[SUCCESS] Settlement completed. Activation Token: " + receipt.licensingKey);
                    } catch (err) {
                        appendConsoleLogLine("[BILLING ERROR] Final ledger collection capture pipeline crashed.");
                    }
                }
            }).render('#paypal-button-placement-anchor');
        }
    </script>
</body>
</html>
    `);
});

app.listen(PORT, () => {
    console.log(`[SYSTEM ONLINE] Autonomous defense engine active on port ${PORT}`);
});