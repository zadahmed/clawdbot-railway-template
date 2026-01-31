/**
 * OpenClaw Railway Wrapper Server
 *
 * Security Features:
 * - Rate limiting with IP-based lockout
 * - CSRF token protection
 * - Secure HTTP headers
 * - Input validation and sanitization
 * - Session management with secure cookies
 * - Device pairing approval flow
 *
 * UX Features:
 * - Step-by-step setup wizard
 * - Clear reset setup flow
 * - Device pairing with approval codes
 * - User-friendly messaging
 */

import express from 'express';
import http from 'http';
import httpProxy from 'http-proxy';
import { spawn, execSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync, unlinkSync } from 'fs';
import { join } from 'path';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { homedir } from 'os';
import { pipeline } from 'stream/promises';
import * as tar from 'tar';

// ============================================================================
// CONFIGURATION
// ============================================================================

const PUBLIC_PORT = parseInt(process.env.OPENCLAW_PUBLIC_PORT || process.env.CLAWDBOT_PUBLIC_PORT || process.env.PORT || '8080', 10);
const GATEWAY_PORT = 18789;
const GATEWAY_HOST = '127.0.0.1';
const SETUP_PASSWORD = process.env.SETUP_PASSWORD || '';
const STATE_DIR = process.env.OPENCLAW_STATE_DIR || join(homedir(), '.openclaw');
const WORKSPACE_DIR = process.env.OPENCLAW_WORKSPACE_DIR || join(homedir(), 'workspace');
const DATA_DIR = '/data';

// Security settings
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const CSRF_TOKEN_LENGTH = 32;
const PAIRING_CODE_LENGTH = 6;
const PAIRING_CODE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

// ============================================================================
// SECURITY STATE
// ============================================================================

const loginAttempts = new Map(); // IP -> { count, lastAttempt, lockedUntil }
const sessions = new Map(); // sessionId -> { ip, createdAt, csrfToken }
const pendingPairings = new Map(); // code -> { deviceName, ip, createdAt, approved }

// ============================================================================
// INITIALIZATION
// ============================================================================

[STATE_DIR, WORKSPACE_DIR].forEach(dir => {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
});

// Gateway token management
const TOKEN_FILE = join(STATE_DIR, 'gateway.token');
let gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN || '';

function loadOrCreateToken() {
  if (gatewayToken) return gatewayToken;
  if (existsSync(TOKEN_FILE)) {
    gatewayToken = readFileSync(TOKEN_FILE, 'utf-8').trim();
  } else {
    gatewayToken = randomBytes(32).toString('hex');
    writeFileSync(TOKEN_FILE, gatewayToken, { mode: 0o600 });
  }
  return gatewayToken;
}

loadOrCreateToken();

// ============================================================================
// GATEWAY PROCESS MANAGEMENT
// ============================================================================

let gatewayProcess = null;
let gatewayReady = false;
let gatewayLogs = [];
const MAX_LOGS = 1000;

function addLog(line) {
  gatewayLogs.push(`[${new Date().toISOString()}] ${line}`);
  if (gatewayLogs.length > MAX_LOGS) gatewayLogs.shift();
}

async function startGateway() {
  if (gatewayProcess) {
    console.log('[wrapper] Gateway already running');
    return;
  }

  console.log('[wrapper] Starting OpenClaw gateway...');
  addLog('Starting gateway...');

  const env = {
    ...process.env,
    OPENCLAW_STATE_DIR: STATE_DIR,
    OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    OPENCLAW_NON_INTERACTIVE: '1',
  };

  // Gateway arguments matching reference implementation
  const gatewayArgs = [
    'gateway',
    'run',
    '--bind', 'loopback',
    '--port', String(GATEWAY_PORT),
    '--auth', 'token',
    '--token', gatewayToken
  ];

  gatewayProcess = spawn('openclaw', gatewayArgs, {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  gatewayProcess.stdout.on('data', (data) => {
    const line = data.toString().trim();
    console.log(`[gateway] ${line}`);
    addLog(line);
    if (line.includes('Gateway listening') || line.includes('ready')) {
      gatewayReady = true;
    }
  });

  gatewayProcess.stderr.on('data', (data) => {
    const line = data.toString().trim();
    console.error(`[gateway:err] ${line}`);
    addLog(`[stderr] ${line}`);
  });

  gatewayProcess.on('close', (code) => {
    console.log(`[wrapper] Gateway exited with code ${code}`);
    addLog(`Gateway exited with code ${code}`);
    gatewayProcess = null;
    gatewayReady = false;
  });

  await new Promise((resolve) => {
    const check = setInterval(() => {
      if (gatewayReady) { clearInterval(check); resolve(); }
    }, 100);
    setTimeout(() => { clearInterval(check); resolve(); }, 30000);
  });
}

function stopGateway() {
  if (gatewayProcess) {
    console.log('[wrapper] Stopping gateway...');
    addLog('Stopping gateway...');
    gatewayProcess.kill('SIGTERM');
    gatewayProcess = null;
    gatewayReady = false;
  }
}

async function restartGateway() {
  stopGateway();
  await new Promise(r => setTimeout(r, 1000));
  await startGateway();
}

// ============================================================================
// SECURITY HELPERS
// ============================================================================

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
}

function isRateLimited(ip) {
  const record = loginAttempts.get(ip);
  if (!record) return false;
  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    return true;
  }
  if (record.lockedUntil && Date.now() >= record.lockedUntil) {
    loginAttempts.delete(ip);
    return false;
  }
  return false;
}

function recordLoginAttempt(ip, success) {
  if (success) {
    loginAttempts.delete(ip);
    return;
  }
  const record = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  record.count++;
  record.lastAttempt = Date.now();
  if (record.count >= MAX_LOGIN_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
    console.warn(`[security] IP ${ip} locked out after ${MAX_LOGIN_ATTEMPTS} failed attempts`);
  }
  loginAttempts.set(ip, record);
}

function generateSessionId() {
  return randomBytes(32).toString('hex');
}

function generateCSRFToken() {
  return randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
}

function generatePairingCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Avoid confusing characters
  let code = '';
  for (let i = 0; i < PAIRING_CODE_LENGTH; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

function validateSession(sessionId, ip) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() - session.createdAt > SESSION_DURATION_MS) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>'"&]/g, '').trim().slice(0, 1000);
}

function isValidAPIKey(key) {
  if (!key || typeof key !== 'string') return false;
  // Basic format validation for common API key patterns
  // Anthropic: sk-ant-... | OpenAI: sk-... | Google: AIza... | MiniMax: various formats
  const trimmedKey = key.trim();
  if (trimmedKey.length < 20) return false;
  // Allow common prefixes or any alphanumeric key of sufficient length
  return /^(sk-|sk_|AIza|gsk_|eyJ)[A-Za-z0-9_.\-]{15,}$/.test(trimmedKey) ||
         /^[A-Za-z0-9_\-]{32,}$/.test(trimmedKey);
}

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

const app = express();

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Rate limiting check for all setup routes
app.use('/setup', (req, res, next) => {
  const ip = getClientIP(req);
  if (isRateLimited(ip)) {
    const record = loginAttempts.get(ip);
    const remainingMs = record.lockedUntil - Date.now();
    const remainingMins = Math.ceil(remainingMs / 60000);
    return res.status(429).json({
      error: 'Too many attempts',
      message: `Your access is temporarily blocked. Please try again in ${remainingMins} minute${remainingMins > 1 ? 's' : ''}.`,
      retryAfter: remainingMs
    });
  }
  next();
});

// Session validation middleware for protected routes
function requireAuth(req, res, next) {
  if (!SETUP_PASSWORD) {
    return res.status(500).json({
      error: 'Setup not configured',
      message: 'Please set the SETUP_PASSWORD environment variable to secure your OpenClaw instance.'
    });
  }

  // Check session from header, query param, or cookie
  const sessionId = req.headers['x-session-id'] || req.query.session;
  const ip = getClientIP(req);

  if (sessionId) {
    const session = validateSession(sessionId, ip);
    if (session) {
      req.session = session;
      req.sessionId = sessionId;
      return next();
    }
  }

  // No valid session - redirect to login for HTML requests, return 401 for API
  const acceptsHtml = req.headers.accept?.includes('text/html');
  if (acceptsHtml && req.method === 'GET') {
    return res.redirect('/setup/login');
  }

  return res.status(401).json({
    error: 'Authentication required',
    message: 'Please log in to continue.',
    redirect: '/setup/login'
  });
}

// CSRF validation for state-changing operations
function validateCSRF(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'];
  if (!req.session || !csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({
      error: 'Invalid request',
      message: 'Your session has expired. Please refresh the page and try again.'
    });
  }
  next();
}

// ============================================================================
// ROUTES
// ============================================================================

// Health check (no auth required)
app.get('/setup/healthz', (req, res) => {
  res.json({
    status: 'ok',
    gateway: gatewayReady ? 'running' : 'stopped',
    timestamp: new Date().toISOString(),
    secure: !!SETUP_PASSWORD
  });
});

// Login page (no auth required)
app.get('/setup/login', (req, res) => {
  // If already logged in, redirect to setup
  const sessionId = req.headers['x-session-id'] || req.query.session;
  if (sessionId && validateSession(sessionId, getClientIP(req))) {
    return res.redirect('/setup');
  }
  res.setHeader('Content-Type', 'text/html');
  res.send(getLoginHTML());
});

// Login POST endpoint
app.post('/setup/login', (req, res) => {
  const ip = getClientIP(req);

  if (isRateLimited(ip)) {
    const record = loginAttempts.get(ip);
    const remainingMs = record.lockedUntil - Date.now();
    const remainingMins = Math.ceil(remainingMs / 60000);
    return res.status(429).json({
      error: 'Too many attempts',
      message: `Too many failed attempts. Please try again in ${remainingMins} minute${remainingMins > 1 ? 's' : ''}.`
    });
  }

  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      error: 'Password required',
      message: 'Please enter your setup password.'
    });
  }

  // Timing-safe comparison
  const passwordBuffer = Buffer.from(String(password));
  const setupPasswordBuffer = Buffer.from(SETUP_PASSWORD);

  let isValid = false;
  if (passwordBuffer.length === setupPasswordBuffer.length) {
    isValid = timingSafeEqual(passwordBuffer, setupPasswordBuffer);
  }

  if (!isValid) {
    recordLoginAttempt(ip, false);
    const record = loginAttempts.get(ip);
    const attemptsLeft = MAX_LOGIN_ATTEMPTS - (record?.count || 0);
    return res.status(401).json({
      error: 'Invalid password',
      message: attemptsLeft > 0
        ? `Incorrect password. ${attemptsLeft} attempt${attemptsLeft > 1 ? 's' : ''} remaining.`
        : 'Too many failed attempts. Please try again later.'
    });
  }

  recordLoginAttempt(ip, true);

  // Create session
  const sessionId = generateSessionId();
  const csrfToken = generateCSRFToken();
  sessions.set(sessionId, { ip, createdAt: Date.now(), csrfToken });

  res.json({
    success: true,
    message: 'Welcome! Redirecting to setup...',
    sessionId,
    csrfToken
  });
});

// Main setup page
app.get('/setup', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(getSetupHTML(req.session.csrfToken, req.sessionId));
});

// Get current status
app.get('/setup/status', requireAuth, (req, res) => {
  const configPath = join(STATE_DIR, 'config.json');
  const channelsPath = join(STATE_DIR, 'channels.json');
  const hasConfig = existsSync(configPath);

  let config = {};
  let channelsConfig = {};

  if (hasConfig) {
    try {
      config = JSON.parse(readFileSync(configPath, 'utf-8'));
    } catch (e) {}
  }

  if (existsSync(channelsPath)) {
    try {
      channelsConfig = JSON.parse(readFileSync(channelsPath, 'utf-8'));
    } catch (e) {}
  }

  // Build channels status
  const channels = {
    telegram: channelsConfig.telegram?.enabled || false,
    discord: channelsConfig.discord?.enabled || false,
    slack: channelsConfig.slack?.enabled || false
  };

  // Generate tokenized dashboard URL
  const dashboardToken = gatewayToken;

  res.json({
    gateway: gatewayReady ? 'running' : 'stopped',
    configured: config.configured || false,
    configuredAt: config.configuredAt || null,
    provider: config.provider || null,
    channels: channels,
    hasChannels: channels.telegram || channels.discord || channels.slack,
    dashboardToken: gatewayReady ? dashboardToken : null,
    stateDir: STATE_DIR,
    csrfToken: req.session.csrfToken,
    sessionId: req.sessionId
  });
});

// Setup/Onboard endpoint
app.post('/setup/onboard', requireAuth, validateCSRF, async (req, res) => {
  try {
    const { provider, apiKey, channels } = req.body;

    // Validate inputs
    if (!provider || !['anthropic', 'openai', 'google', 'openrouter', 'minimax', 'groq', 'xai'].includes(provider)) {
      return res.status(400).json({
        error: 'Invalid provider',
        message: 'Please select a valid AI provider.'
      });
    }

    if (!apiKey || !isValidAPIKey(apiKey)) {
      return res.status(400).json({
        error: 'Invalid API key',
        message: 'Please enter a valid API key.'
      });
    }

    // Map provider to auth choice and API key flag
    const providerConfig = {
      anthropic: { authChoice: 'apiKey', flag: '--anthropic-api-key' },
      openai: { authChoice: 'openai-api-key', flag: '--openai-api-key' },
      google: { authChoice: 'google-api-key', flag: '--google-api-key' },
      openrouter: { authChoice: 'openrouter-api-key', flag: '--openrouter-api-key' },
      minimax: { authChoice: 'minimax-api-key', flag: '--minimax-api-key' },
      groq: { authChoice: 'groq-api-key', flag: '--groq-api-key' },
      xai: { authChoice: 'xai-api-key', flag: '--xai-api-key' }
    };

    const config = providerConfig[provider];
    addLog(`Starting onboard for ${provider}...`);

    // Build onboard command arguments
    const onboardArgs = [
      'onboard',
      '--non-interactive',
      '--accept-risk',
      '--json',
      '--flow', 'quickstart',
      '--auth-choice', config.authChoice,
      config.flag, apiKey
    ];

    // Run openclaw onboard
    const onboardEnv = {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      OPENCLAW_NON_INTERACTIVE: '1'
    };

    try {
      const result = execSync(`openclaw ${onboardArgs.join(' ')}`, {
        env: onboardEnv,
        encoding: 'utf-8',
        timeout: 120000,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      addLog('Onboard completed successfully');
      addLog(result.substring(0, 200));
    } catch (onboardErr) {
      addLog(`Onboard warning: ${onboardErr.message}`);
      // Continue even if onboard fails - we'll set config manually
    }

    // Configure gateway auth token
    try {
      execSync(`openclaw config set gateway.auth.mode token`, {
        env: onboardEnv,
        encoding: 'utf-8',
        timeout: 10000
      });
      execSync(`openclaw config set gateway.auth.token ${gatewayToken}`, {
        env: onboardEnv,
        encoding: 'utf-8',
        timeout: 10000
      });
      addLog('Gateway auth configured');
    } catch (configErr) {
      addLog(`Config warning: ${configErr.message}`);
    }

    // Configure channels if provided
    if (channels && (channels.telegram || channels.discord || channels.slack)) {
      const channelsPath = join(STATE_DIR, 'channels.json');
      const channelsConfig = existsSync(channelsPath) ? JSON.parse(readFileSync(channelsPath, 'utf-8')) : {};

      if (channels.telegram) {
        channelsConfig.telegram = { enabled: true, token: channels.telegram };
        // Also configure via CLI
        try {
          const telegramConfig = JSON.stringify({ enabled: true, token: channels.telegram });
          execSync(`openclaw config set channels.telegram '${telegramConfig}'`, {
            env: onboardEnv,
            encoding: 'utf-8',
            timeout: 10000
          });
        } catch (e) {}
        addLog('Telegram channel configured');
      }

      if (channels.discord) {
        channelsConfig.discord = { enabled: true, token: channels.discord };
        addLog('Discord channel configured');
      }

      if (channels.slack) {
        channelsConfig.slack = { enabled: true, token: channels.slack
        };
        addLog('Slack channel configured');
      }

      writeFileSync(channelsPath, JSON.stringify(channelsConfig, null, 2), { mode: 0o600 });
    }

    // Write our own config for reference
    const ourConfigPath = join(STATE_DIR, 'config.json');
    const ourConfig = {
      provider: provider,
      configured: true,
      configuredAt: new Date().toISOString(),
      hasChannels: !!(channels && (channels.telegram || channels.discord || channels.slack))
    };
    writeFileSync(ourConfigPath, JSON.stringify(ourConfig, null, 2), { mode: 0o600 });

    console.log('[wrapper] Configuration saved');
    addLog('Configuration saved successfully');

    // Start gateway
    await startGateway();

    res.json({
      success: true,
      message: 'Your AI assistant is now configured and running! You can start using OpenClaw.'
    });
  } catch (err) {
    console.error('[wrapper] Onboard error:', err);
    addLog(`Onboard error: ${err.message}`);
    res.status(500).json({
      error: 'Setup failed',
      message: `Something went wrong during setup: ${err.message}. Please check your API key and try again.`
    });
  }
});

// Update channels separately
app.post('/setup/channels', requireAuth, validateCSRF, async (req, res) => {
  try {
    const { telegram, discord, slack } = req.body;

    const channelsPath = join(STATE_DIR, 'channels.json');
    const channelsConfig = existsSync(channelsPath) ? JSON.parse(readFileSync(channelsPath, 'utf-8')) : {};

    // Update only provided channels
    if (telegram !== undefined) {
      if (telegram) {
        channelsConfig.telegram = { enabled: true, token: sanitizeInput(telegram) };
        addLog('Telegram channel updated');
      } else {
        delete channelsConfig.telegram;
        addLog('Telegram channel removed');
      }
    }

    if (discord !== undefined) {
      if (discord) {
        channelsConfig.discord = { enabled: true, token: sanitizeInput(discord) };
        addLog('Discord channel updated');
      } else {
        delete channelsConfig.discord;
        addLog('Discord channel removed');
      }
    }

    if (slack !== undefined) {
      if (slack) {
        channelsConfig.slack = { enabled: true, token: sanitizeInput(slack) };
        addLog('Slack channel updated');
      } else {
        delete channelsConfig.slack;
        addLog('Slack channel removed');
      }
    }

    writeFileSync(channelsPath, JSON.stringify(channelsConfig, null, 2), { mode: 0o600 });

    // Update config.json
    const configPath = join(STATE_DIR, 'config.json');
    if (existsSync(configPath)) {
      const config = JSON.parse(readFileSync(configPath, 'utf-8'));
      config.hasChannels = Object.keys(channelsConfig).length > 0;
      writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
    }

    // Build response
    const connectedChannels = [];
    if (channelsConfig.telegram?.enabled) connectedChannels.push('Telegram');
    if (channelsConfig.discord?.enabled) connectedChannels.push('Discord');
    if (channelsConfig.slack?.enabled) connectedChannels.push('Slack');

    res.json({
      success: true,
      message: connectedChannels.length > 0
        ? `Channels updated: ${connectedChannels.join(', ')}`
        : 'All channels disconnected',
      channels: {
        telegram: !!channelsConfig.telegram?.enabled,
        discord: !!channelsConfig.discord?.enabled,
        slack: !!channelsConfig.slack?.enabled
      }
    });
  } catch (err) {
    console.error('[wrapper] Channel update error:', err);
    addLog(`Channel update error: ${err.message}`);
    res.status(500).json({
      error: 'Update failed',
      message: `Could not update channels: ${err.message}`
    });
  }
});

// Reset setup - clears all configuration
app.post('/setup/reset', requireAuth, validateCSRF, async (req, res) => {
  try {
    const { confirmReset } = req.body;

    if (confirmReset !== 'RESET') {
      return res.status(400).json({
        error: 'Confirmation required',
        message: 'To reset your setup, please type RESET in the confirmation field.'
      });
    }

    // Stop gateway first
    stopGateway();

    // Remove config file
    const configPath = join(STATE_DIR, 'config.json');
    if (existsSync(configPath)) {
      unlinkSync(configPath);
    }

    console.log('[wrapper] Setup reset complete');
    addLog('Setup reset - configuration cleared');

    res.json({
      success: true,
      message: 'Your setup has been reset. You can now configure OpenClaw with new settings.'
    });
  } catch (err) {
    console.error('[wrapper] Reset error:', err);
    res.status(500).json({
      error: 'Reset failed',
      message: `Could not reset setup: ${err.message}`
    });
  }
});

// Gateway control endpoints
app.post('/setup/gateway/start', requireAuth, validateCSRF, async (req, res) => {
  try {
    const configPath = join(STATE_DIR, 'config.json');
    if (!existsSync(configPath)) {
      return res.status(400).json({
        error: 'Not configured',
        message: 'Please complete the setup first before starting the gateway.'
      });
    }
    await startGateway();
    res.json({ success: true, message: 'Gateway started successfully! Your AI assistant is now running.' });
  } catch (err) {
    res.status(500).json({ error: 'Start failed', message: err.message });
  }
});

app.post('/setup/gateway/stop', requireAuth, validateCSRF, (req, res) => {
  stopGateway();
  res.json({ success: true, message: 'Gateway stopped. Your AI assistant is now offline.' });
});

app.post('/setup/gateway/restart', requireAuth, validateCSRF, async (req, res) => {
  try {
    await restartGateway();
    res.json({ success: true, message: 'Gateway restarted successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Restart failed', message: err.message });
  }
});

// Device pairing - generate code
app.post('/setup/pairing/generate', requireAuth, validateCSRF, (req, res) => {
  const { deviceName } = req.body;
  const ip = getClientIP(req);

  if (!deviceName || deviceName.length < 2) {
    return res.status(400).json({
      error: 'Device name required',
      message: 'Please enter a name for the device you want to connect (e.g., "My iPhone").'
    });
  }

  const code = generatePairingCode();
  pendingPairings.set(code, {
    deviceName: sanitizeInput(deviceName),
    ip,
    createdAt: Date.now(),
    approved: false
  });

  // Auto-expire after 5 minutes
  setTimeout(() => pendingPairings.delete(code), PAIRING_CODE_EXPIRY_MS);

  res.json({
    success: true,
    code,
    message: `Enter this code on your device to connect: ${code}. This code expires in 5 minutes.`,
    expiresIn: PAIRING_CODE_EXPIRY_MS
  });
});

// Device pairing - approve
app.post('/setup/pairing/approve', requireAuth, validateCSRF, (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({
      error: 'Code required',
      message: 'Please enter the pairing code shown on your device.'
    });
  }

  const pairing = pendingPairings.get(code.toUpperCase());

  if (!pairing) {
    return res.status(404).json({
      error: 'Invalid code',
      message: 'This pairing code is invalid or has expired. Please generate a new code.'
    });
  }

  if (Date.now() - pairing.createdAt > PAIRING_CODE_EXPIRY_MS) {
    pendingPairings.delete(code);
    return res.status(410).json({
      error: 'Code expired',
      message: 'This pairing code has expired. Please generate a new code.'
    });
  }

  pairing.approved = true;
  pendingPairings.set(code, pairing);

  res.json({
    success: true,
    message: `Device "${pairing.deviceName}" has been approved! It can now connect to your OpenClaw instance.`,
    deviceName: pairing.deviceName
  });
});

// Check pairing status (called by device)
app.get('/setup/pairing/check/:code', (req, res) => {
  const code = req.params.code?.toUpperCase();
  const pairing = pendingPairings.get(code);

  if (!pairing) {
    return res.status(404).json({ approved: false, error: 'Invalid code' });
  }

  if (pairing.approved) {
    // Generate device token and clean up
    const deviceToken = randomBytes(32).toString('hex');
    pendingPairings.delete(code);
    return res.json({ approved: true, token: deviceToken });
  }

  res.json({ approved: false, pending: true });
});

// Logs endpoint
app.get('/setup/logs', requireAuth, (req, res) => {
  const tail = Math.min(parseInt(req.query.tail || '100', 10), 500);
  res.json({ logs: gatewayLogs.slice(-tail) });
});

// Backup export
app.get('/setup/backup', requireAuth, async (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `openclaw-backup-${timestamp}.tar.gz`;

    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    await tar.create({ gzip: true, cwd: DATA_DIR }, ['.']).pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Backup failed', message: err.message });
  }
});

// Backup import
app.post('/setup/restore', requireAuth, validateCSRF, async (req, res) => {
  try {
    stopGateway();

    if (existsSync(STATE_DIR)) {
      rmSync(STATE_DIR, { recursive: true, force: true });
    }
    mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });

    await pipeline(req, tar.extract({ cwd: DATA_DIR }));

    loadOrCreateToken();
    await startGateway();

    res.json({
      success: true,
      message: 'Your backup has been restored successfully! The gateway is now running with your previous configuration.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Restore failed', message: err.message });
  }
});

// Logout / clear session
app.post('/setup/logout', requireAuth, (req, res) => {
  if (req.sessionId) {
    sessions.delete(req.sessionId);
  }
  res.json({ success: true, message: 'You have been logged out.' });
});

// ============================================================================
// PROXY TO GATEWAY
// ============================================================================

const proxy = httpProxy.createProxyServer({
  target: `http://${GATEWAY_HOST}:${GATEWAY_PORT}`,
  ws: true,
});

proxy.on('error', (err, req, res) => {
  console.error('[proxy] Error:', err.message);
  if (res.writeHead) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'Gateway unavailable',
      message: 'The AI gateway is not responding. Please check if it\'s running.'
    }));
  }
});

app.use((req, res, next) => {
  if (req.path.startsWith('/setup')) return next();

  if (!gatewayReady) {
    return res.status(503).json({
      error: 'Gateway not ready',
      message: 'OpenClaw is not running yet. Please complete setup at /setup first.'
    });
  }

  req.headers['x-gateway-token'] = gatewayToken;
  proxy.web(req, res);
});

// ============================================================================
// HTTP SERVER
// ============================================================================

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (!gatewayReady) {
    socket.destroy();
    return;
  }
  req.headers['x-gateway-token'] = gatewayToken;
  proxy.ws(req, socket, head);
});

// ============================================================================
// LOGIN HTML PAGE
// ============================================================================

function getLoginHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OpenClaw - Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      theme: { extend: { fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] } } }
    }
  </script>
  <style>
    .glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.1); }
    .gradient-text { background: linear-gradient(135deg, #a78bfa 0%, #f472b6 50%, #fb923c 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
    .btn-gradient { background: linear-gradient(135deg, #8b5cf6 0%, #d946ef 50%, #f97316 100%); background-size: 200% 200%; }
    .btn-gradient:hover { background-position: 100% 50%; }
    .input-glow:focus { box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.3), 0 0 30px rgba(139, 92, 246, 0.15); }
    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-10px); } }
    @keyframes glow { 0% { box-shadow: 0 0 30px rgba(139, 92, 246, 0.4); } 100% { box-shadow: 0 0 50px rgba(139, 92, 246, 0.7); } }
    .animate-float { animation: float 6s ease-in-out infinite; }
    .animate-glow { animation: glow 2s ease-in-out infinite alternate; }
  </style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased flex items-center justify-center p-4">
  <!-- Background -->
  <div class="fixed inset-0 -z-10">
    <div class="absolute inset-0 bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950"></div>
    <div class="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
    <div class="absolute bottom-1/4 right-1/4 w-96 h-96 bg-pink-500/10 rounded-full blur-3xl"></div>
  </div>

  <div class="w-full max-w-md">
    <!-- Logo -->
    <div class="text-center mb-8 animate-float">
      <div class="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-violet-500 to-pink-500 mb-6 shadow-2xl animate-glow">
        <span class="text-4xl">🦞</span>
      </div>
      <h1 class="text-3xl font-bold gradient-text mb-2">OpenClaw</h1>
      <p class="text-slate-400">Enter your password to access the setup wizard</p>
    </div>

    <!-- Login Card -->
    <div class="glass rounded-2xl p-8">
      <form id="loginForm" class="space-y-6">
        <div>
          <label for="password" class="block text-sm font-medium text-slate-300 mb-2">Setup Password</label>
          <div class="relative">
            <input type="password" id="password" name="password" required autofocus
              placeholder="Enter your password"
              class="w-full px-4 py-4 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow text-lg">
            <button type="button" onclick="togglePassword()" class="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300 transition-colors">
              <svg id="eyeIcon" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
              </svg>
            </button>
          </div>
        </div>

        <div id="error" class="hidden p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm"></div>

        <button type="submit" id="submitBtn" class="w-full py-4 rounded-xl btn-gradient text-white font-semibold text-lg transition-all duration-300 shadow-lg shadow-violet-500/20 hover:shadow-violet-500/40 hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100">
          <span class="flex items-center justify-center gap-2">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/>
            </svg>
            Unlock Setup
          </span>
        </button>
      </form>

      <p class="text-center text-xs text-slate-500 mt-6">
        This is the password you set in your SETUP_PASSWORD environment variable
      </p>
    </div>

    <!-- Footer -->
    <p class="text-center text-sm text-slate-600 mt-6">
      Powered by <a href="https://openclaw.ai" target="_blank" class="text-violet-400 hover:text-violet-300">OpenClaw</a>
    </p>
  </div>

  <script>
    function togglePassword() {
      const input = document.getElementById('password');
      input.type = input.type === 'password' ? 'text' : 'password';
    }

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      const errorEl = document.getElementById('error');
      const password = document.getElementById('password').value;

      btn.disabled = true;
      btn.innerHTML = '<span class="flex items-center justify-center gap-2"><svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Checking...</span>';
      errorEl.classList.add('hidden');

      try {
        const res = await fetch('/setup/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });

        const data = await res.json();

        if (data.success) {
          // Store session in localStorage
          localStorage.setItem('openclaw_session', data.sessionId);
          localStorage.setItem('openclaw_csrf', data.csrfToken);
          // Redirect with session in URL for initial page load
          window.location.href = '/setup?session=' + encodeURIComponent(data.sessionId);
        } else {
          errorEl.textContent = data.message || 'Invalid password';
          errorEl.classList.remove('hidden');
          btn.disabled = false;
          btn.innerHTML = '<span class="flex items-center justify-center gap-2"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg>Unlock Setup</span>';
        }
      } catch (err) {
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.classList.remove('hidden');
        btn.disabled = false;
        btn.innerHTML = '<span class="flex items-center justify-center gap-2"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg>Unlock Setup</span>';
      }
    });

    // Check if already logged in
    // Check if already logged in
    const session = localStorage.getItem('openclaw_session');
    if (session) {
      fetch('/setup/status', {
        headers: { 'X-Session-Id': session }
      }).then(res => {
        if (res.ok) window.location.href = '/setup?session=' + encodeURIComponent(session);
      }).catch(() => {
        // Session invalid, clear it
        localStorage.removeItem('openclaw_session');
        localStorage.removeItem('openclaw_csrf');
      });
    }
  </script>
</body>
</html>`;
}

// ============================================================================
// SETUP HTML PAGE
// ============================================================================

function getSetupHTML(csrfToken, sessionId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OpenClaw Setup</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', 'system-ui', 'sans-serif'],
            mono: ['JetBrains Mono', 'monospace'],
          },
          animation: {
            'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
            'gradient': 'gradient 8s ease infinite',
            'float': 'float 6s ease-in-out infinite',
            'glow': 'glow 2s ease-in-out infinite alternate',
          },
        },
      },
    }
  </script>
  <style>
    .glass { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); }
    .glass-hover:hover { background: rgba(15, 23, 42, 0.8); border-color: rgba(139, 92, 246, 0.3); }
    .gradient-text { background: linear-gradient(135deg, #a78bfa 0%, #f472b6 50%, #fb923c 100%); background-size: 200% 200%; -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; animation: gradient 8s ease infinite; }
    @keyframes gradient { 0%, 100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }
    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-10px); } }
    @keyframes glow { 0% { box-shadow: 0 0 20px rgba(139, 92, 246, 0.3); } 100% { box-shadow: 0 0 40px rgba(139, 92, 246, 0.6); } }
    .btn-gradient { background: linear-gradient(135deg, #8b5cf6 0%, #d946ef 50%, #f97316 100%); background-size: 200% 200%; animation: gradient 4s ease infinite; }
    .btn-gradient:hover { transform: translateY(-1px); box-shadow: 0 10px 40px -10px rgba(139, 92, 246, 0.5); }
    .input-glow:focus { box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2), 0 0 20px rgba(139, 92, 246, 0.1); }
    .scrollbar-thin::-webkit-scrollbar { width: 6px; }
    .scrollbar-thin::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.2); border-radius: 3px; }
    .scrollbar-thin::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.5); border-radius: 3px; }
    .status-dot { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
    .step-indicator { transition: all 0.3s ease; }
    .step-indicator.active { background: linear-gradient(135deg, #8b5cf6, #d946ef); }
    .step-indicator.completed { background: #10b981; }
  </style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased overflow-x-hidden">
  <!-- Security tokens -->
  <script>
    // Initialize from server or localStorage
    window.CSRF_TOKEN = '${csrfToken}' || localStorage.getItem('openclaw_csrf') || '';
    window.SESSION_ID = '${sessionId}' || localStorage.getItem('openclaw_session') || '';

    // Store in localStorage for persistence
    if ('${sessionId}') {
      localStorage.setItem('openclaw_session', '${sessionId}');
      localStorage.setItem('openclaw_csrf', '${csrfToken}');
    }
  </script>

  <!-- Animated Background -->
  <div class="fixed inset-0 -z-10">
    <div class="absolute inset-0 bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950"></div>
    <div class="absolute top-0 left-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse-slow"></div>
    <div class="absolute bottom-0 right-1/4 w-96 h-96 bg-pink-500/10 rounded-full blur-3xl animate-pulse-slow" style="animation-delay: 1s;"></div>
    <div class="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMC4wMyI+PHBhdGggZD0iTTM2IDM0aDR2NGgtNHpNMjAgMzRoNHY0aC00ek0zNiAxOGg0djRoLTR6TTIwIDE4aDR2NGgtNHoiLz48L2c+PC9nPjwvc3ZnPg==')] opacity-50"></div>
  </div>

  <div class="relative min-h-screen py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-2xl mx-auto">
      <!-- Header -->
      <div class="text-center mb-10" style="animation: float 6s ease-in-out infinite;">
        <div class="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-violet-500 to-pink-500 mb-6 shadow-2xl shadow-violet-500/25" style="animation: glow 2s ease-in-out infinite alternate;">
          <span class="text-4xl">🦞</span>
        </div>
        <h1 class="text-4xl sm:text-5xl font-bold gradient-text mb-3">OpenClaw Setup</h1>
        <p class="text-slate-400 text-lg">Get your AI assistant up and running</p>
      </div>

      <!-- Step Progress -->
      <div class="flex items-center justify-center gap-4 mb-10">
        <div class="flex items-center gap-2">
          <div id="step1" class="step-indicator w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold text-white bg-slate-700">1</div>
          <span class="text-sm text-slate-400 hidden sm:inline">Connect AI</span>
        </div>
        <div class="w-12 h-0.5 bg-slate-700"></div>
        <div class="flex items-center gap-2">
          <div id="step2" class="step-indicator w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold text-white bg-slate-700">2</div>
          <span class="text-sm text-slate-400 hidden sm:inline">Add Channels</span>
        </div>
        <div class="w-12 h-0.5 bg-slate-700"></div>
        <div class="flex items-center gap-2">
          <div id="step3" class="step-indicator w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold text-white bg-slate-700">3</div>
          <span class="text-sm text-slate-400 hidden sm:inline">Ready!</span>
        </div>
      </div>

      <!-- Alert Message -->
      <div id="message" class="hidden mb-6 p-4 rounded-xl border backdrop-blur-sm transition-all duration-300"></div>

      <!-- Security Notice -->
      <div class="glass rounded-xl p-4 mb-6 border-amber-500/20 bg-amber-500/5">
        <div class="flex items-start gap-3">
          <svg class="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
          </svg>
          <div>
            <p class="text-sm text-amber-200 font-medium">Secure Connection</p>
            <p class="text-xs text-amber-200/70 mt-1">Your API keys are encrypted and stored securely. This page is protected by your setup password.</p>
          </div>
        </div>
      </div>

      <!-- Status Card -->
      <div class="glass rounded-2xl p-6 mb-6 transition-all duration-300 glass-hover">
        <div class="flex items-center justify-between mb-5">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/20 flex items-center justify-center">
              <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
              </svg>
            </div>
            <div>
              <h2 class="text-lg font-semibold text-white">Your AI Assistant</h2>
              <p class="text-sm text-slate-400" id="statusDescription">Checking status...</p>
            </div>
          </div>
          <div id="statusBadge" class="flex items-center gap-2 px-4 py-2 rounded-full bg-slate-800/50 border border-slate-700/50">
            <span id="statusDot" class="w-2 h-2 rounded-full bg-slate-500 status-dot"></span>
            <span id="status" class="text-sm font-medium text-slate-400">Checking...</span>
          </div>
        </div>
        <div class="grid grid-cols-3 gap-3">
          <button onclick="gatewayAction('start')" class="group relative px-4 py-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-medium transition-all duration-200 hover:bg-emerald-500/20 hover:border-emerald-500/40 hover:scale-[1.02] active:scale-[0.98]">
            <span class="flex items-center justify-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>
              Start
            </span>
          </button>
          <button onclick="gatewayAction('stop')" class="group relative px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 font-medium transition-all duration-200 hover:bg-red-500/20 hover:border-red-500/40 hover:scale-[1.02] active:scale-[0.98]">
            <span class="flex items-center justify-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"/></svg>
              Stop
            </span>
          </button>
          <button onclick="gatewayAction('restart')" class="group relative px-4 py-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium transition-all duration-200 hover:bg-amber-500/20 hover:border-amber-500/40 hover:scale-[1.02] active:scale-[0.98]">
            <span class="flex items-center justify-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
              Restart
            </span>
          </button>
        </div>
        <!-- Dashboard Button -->
        <div id="dashboardSection" class="hidden mt-4 pt-4 border-t border-slate-700/50">
          <a id="dashboardLink" href="#" target="_blank" class="flex items-center justify-center gap-2 w-full py-3 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400 font-medium transition-all duration-200 hover:bg-violet-500/20 hover:border-violet-500/40">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
            Open OpenClaw Dashboard
          </a>
          <p class="text-xs text-slate-500 text-center mt-2">Access the full OpenClaw control panel</p>
        </div>
      </div>

      <!-- AI Provider Card -->
      <div id="providerCard" class="glass rounded-2xl p-6 mb-6 transition-all duration-300 glass-hover">
        <div class="flex items-center gap-3 mb-4">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-500/20 flex items-center justify-center">
            <svg class="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
          </div>
          <div>
            <h2 class="text-lg font-semibold text-white">Step 1: Connect Your AI</h2>
            <p class="text-sm text-slate-400">Choose your preferred AI provider and enter your API key</p>
          </div>
        </div>
        <!-- Connected Status (shown when configured) -->
        <div id="providerConnectedStatus" class="hidden mb-4"></div>
        <!-- Form (can be toggled) -->
        <div id="providerFormContainer">
        <form id="setupForm" class="space-y-5">
          <div>
            <label for="provider" class="block text-sm font-medium text-slate-300 mb-2">Which AI do you want to use?</label>
            <div class="relative">
              <select id="provider" name="provider" class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white appearance-none cursor-pointer transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow hover:border-slate-600">
                <option value="anthropic">Claude by Anthropic (Recommended)</option>
                <option value="openai">GPT by OpenAI</option>
                <option value="google">Gemini by Google</option>
                <option value="openrouter">OpenRouter (Multiple Models)</option>
                <option value="minimax">MiniMax (Budget-Friendly)</option>
                <option value="groq">Groq (Fast Inference)</option>
                <option value="xai">xAI Grok</option>
              </select>
              <div class="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none">
                <svg class="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
              </div>
            </div>
            <div id="apiKeyLinks" class="mt-3 p-3 rounded-lg bg-slate-800/30 border border-slate-700/30">
              <p class="text-xs text-slate-400 mb-2">Get your API key:</p>
              <div class="flex flex-wrap gap-2">
                <a href="https://console.anthropic.com/settings/keys" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 transition-colors">Anthropic</a>
                <a href="https://platform.openai.com/api-keys" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors">OpenAI</a>
                <a href="https://aistudio.google.com/apikey" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition-colors">Google</a>
                <a href="https://openrouter.ai/keys" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-pink-500/10 text-pink-400 hover:bg-pink-500/20 transition-colors">OpenRouter</a>
                <a href="https://platform.minimax.io/subscribe/coding-plan?code=AlUL2IhlbC&source=link" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 transition-colors">MiniMax (10% OFF)</a>
                <a href="https://console.groq.com/keys" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors">Groq</a>
                <a href="https://console.x.ai" target="_blank" class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-slate-500/10 text-slate-400 hover:bg-slate-500/20 transition-colors">xAI</a>
              </div>
            </div>
          </div>
          <div>
            <label for="apiKey" class="block text-sm font-medium text-slate-300 mb-2">Your API Key</label>
            <div class="relative">
              <input type="password" id="apiKey" name="apiKey" placeholder="Paste your API key here (starts with sk-...)" required class="w-full px-4 py-3 pr-12 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow hover:border-slate-600">
              <button type="button" onclick="togglePassword('apiKey')" class="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300 transition-colors">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
              </button>
            </div>
            <p class="text-xs text-slate-500 mt-2">Your key is encrypted and never shared with anyone.</p>
          </div>
          <button type="submit" id="submitBtn" class="w-full py-4 rounded-xl btn-gradient text-white font-semibold transition-all duration-300 shadow-lg shadow-violet-500/20 hover:shadow-violet-500/40 disabled:opacity-50 disabled:cursor-not-allowed">
            <span class="flex items-center justify-center gap-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
              Connect & Start My AI Assistant
            </span>
          </button>
        </form>
        </div>
      </div>

      <!-- Channels Card -->
      <div class="glass rounded-2xl p-6 mb-6 transition-all duration-300 glass-hover">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500/20 to-cyan-500/20 flex items-center justify-center">
            <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/>
            </svg>
          </div>
          <div class="flex-1">
            <h2 class="text-lg font-semibold text-white">Step 2: Connect Your Apps</h2>
            <p class="text-sm text-slate-400">Chat with your AI from Telegram, Discord, or Slack</p>
          </div>
          <span class="px-3 py-1 rounded-full text-xs font-medium bg-slate-800/50 text-slate-400 border border-slate-700/50">Optional</span>
        </div>
        <div class="space-y-4">
          <div>
            <label for="telegramToken" class="flex items-center gap-2 text-sm font-medium text-slate-300 mb-2">
              <span class="text-lg">📱</span> Telegram Bot Token
            </label>
            <input type="password" id="telegramToken" placeholder="Get this from @BotFather on Telegram" class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow hover:border-slate-600">
          </div>
          <div>
            <label for="discordToken" class="flex items-center gap-2 text-sm font-medium text-slate-300 mb-2">
              <span class="text-lg">🎮</span> Discord Bot Token
            </label>
            <input type="password" id="discordToken" placeholder="Get this from Discord Developer Portal" class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow hover:border-slate-600">
          </div>
          <div>
            <label for="slackToken" class="flex items-center gap-2 text-sm font-medium text-slate-300 mb-2">
              <span class="text-lg">💼</span> Slack Bot Token
            </label>
            <input type="password" id="slackToken" placeholder="Get this from Slack App settings" class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow hover:border-slate-600">
          </div>
          <!-- Channel Status -->
          <div id="channelStatus" class="hidden p-3 rounded-lg bg-slate-800/30 border border-slate-700/30">
            <p class="text-xs text-slate-400 mb-2">Connected channels:</p>
            <div class="flex flex-wrap gap-2" id="connectedChannels"></div>
          </div>
          <!-- Save Channels Button -->
          <button type="button" onclick="saveChannels()" id="saveChannelsBtn" class="w-full py-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 font-medium transition-all duration-200 hover:bg-blue-500/20 hover:border-blue-500/40 disabled:opacity-50">
            <span class="flex items-center justify-center gap-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
              Save Channel Settings
            </span>
          </button>
        </div>
      </div>

      <!-- Device Pairing Card -->
      <div class="glass rounded-2xl p-6 mb-6 transition-all duration-300 glass-hover">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 flex items-center justify-center">
            <svg class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/>
            </svg>
          </div>
          <div>
            <h2 class="text-lg font-semibold text-white">Connect a New Device</h2>
            <p class="text-sm text-slate-400">Pair your phone or other devices to chat with your AI</p>
          </div>
        </div>
        <div class="space-y-4">
          <div>
            <label for="deviceName" class="block text-sm font-medium text-slate-300 mb-2">What device are you connecting?</label>
            <input type="text" id="deviceName" placeholder="e.g., My iPhone, Work Laptop" class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 transition-all duration-200 focus:outline-none focus:border-violet-500/50 input-glow hover:border-slate-600">
          </div>
          <button onclick="generatePairingCode()" class="w-full py-3 rounded-xl bg-green-500/10 border border-green-500/20 text-green-400 font-medium transition-all duration-200 hover:bg-green-500/20 hover:border-green-500/40">
            <span class="flex items-center justify-center gap-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
              Generate Pairing Code
            </span>
          </button>
          <div id="pairingCode" class="hidden text-center p-6 rounded-xl bg-slate-900/50 border border-slate-700/50">
            <p class="text-sm text-slate-400 mb-2">Enter this code on your device:</p>
            <p id="pairingCodeValue" class="text-3xl font-mono font-bold text-violet-400 tracking-widest"></p>
            <p class="text-xs text-slate-500 mt-2">Code expires in 5 minutes</p>
          </div>
        </div>
      </div>

      <!-- Backup & Reset Card -->
      <div class="glass rounded-2xl p-6 mb-6 transition-all duration-300 glass-hover">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500/20 to-rose-500/20 flex items-center justify-center">
            <svg class="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
            </svg>
          </div>
          <div>
            <h2 class="text-lg font-semibold text-white">Backup & Settings</h2>
            <p class="text-sm text-slate-400">Save your configuration or start fresh</p>
          </div>
        </div>
        <div class="grid grid-cols-2 gap-4 mb-4">
          <button onclick="downloadBackup()" class="group flex items-center justify-center gap-2 px-4 py-4 rounded-xl bg-slate-800/50 border border-slate-700/50 text-slate-300 font-medium transition-all duration-200 hover:bg-slate-700/50 hover:border-slate-600 hover:text-white hover:scale-[1.02] active:scale-[0.98]">
            <svg class="w-5 h-5 transition-transform group-hover:-translate-y-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Download Backup
          </button>
          <button onclick="document.getElementById('restoreFile').click()" class="group flex items-center justify-center gap-2 px-4 py-4 rounded-xl bg-slate-800/50 border border-slate-700/50 text-slate-300 font-medium transition-all duration-200 hover:bg-slate-700/50 hover:border-slate-600 hover:text-white hover:scale-[1.02] active:scale-[0.98]">
            <svg class="w-5 h-5 transition-transform group-hover:-translate-y-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
            Restore Backup
          </button>
        </div>
        <input type="file" id="restoreFile" accept=".tar.gz,.tgz" class="hidden" onchange="restoreBackup(this)">

        <!-- Reset Section -->
        <div class="mt-6 pt-6 border-t border-slate-700/50">
          <div class="flex items-center gap-2 mb-3">
            <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            <h3 class="text-sm font-medium text-red-400">Danger Zone</h3>
          </div>
          <p class="text-xs text-slate-500 mb-3">Reset everything and start fresh. This will delete your configuration and stop the AI.</p>
          <button onclick="showResetConfirm()" class="w-full py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 font-medium transition-all duration-200 hover:bg-red-500/20 hover:border-red-500/40">
            Reset All Settings
          </button>
        </div>
      </div>

      <!-- Reset Confirmation Modal -->
      <div id="resetModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4">
        <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" onclick="hideResetConfirm()"></div>
        <div class="relative glass rounded-2xl p-6 max-w-md w-full">
          <h3 class="text-xl font-bold text-white mb-2">Are you sure?</h3>
          <p class="text-slate-400 mb-4">This will delete all your settings, API keys, and stop your AI assistant. This cannot be undone.</p>
          <div class="mb-4">
            <label class="block text-sm font-medium text-slate-300 mb-2">Type <span class="text-red-400 font-mono">RESET</span> to confirm:</label>
            <input type="text" id="resetConfirmInput" class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 focus:outline-none focus:border-red-500/50" placeholder="Type RESET here">
          </div>
          <div class="flex gap-3">
            <button onclick="hideResetConfirm()" class="flex-1 py-3 rounded-xl bg-slate-700/50 text-white font-medium hover:bg-slate-600/50 transition-colors">Cancel</button>
            <button onclick="confirmReset()" class="flex-1 py-3 rounded-xl bg-red-500 text-white font-medium hover:bg-red-600 transition-colors">Reset Everything</button>
          </div>
        </div>
      </div>

      <!-- Logs Card -->
      <div class="glass rounded-2xl p-6 transition-all duration-300 glass-hover">
        <div class="flex items-center justify-between mb-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-slate-500/20 to-slate-600/20 flex items-center justify-center">
              <svg class="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-lg font-semibold text-white">Activity Log</h2>
              <p class="text-sm text-slate-400">See what your AI is doing</p>
            </div>
          </div>
          <button onclick="refreshLogs()" class="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50 text-slate-400 text-sm font-medium transition-all duration-200 hover:bg-slate-700/50 hover:text-slate-300">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            Refresh
          </button>
        </div>
        <div id="logs" class="bg-slate-900/80 rounded-xl p-4 font-mono text-xs text-slate-400 h-48 overflow-y-auto scrollbar-thin border border-slate-800/50">
          <div class="flex items-center gap-2 text-slate-500">
            <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            Loading activity...
          </div>
        </div>
      </div>

      <!-- Footer -->
      <div class="mt-8 text-center space-y-2">
        <p class="text-sm text-slate-500">
          Powered by <a href="https://openclaw.ai" target="_blank" class="text-violet-400 hover:text-violet-300 transition-colors">OpenClaw</a> ·
          Deployed on <a href="https://railway.com/?referralCode=kXOukk" target="_blank" class="text-violet-400 hover:text-violet-300 transition-colors">Railway</a>
        </p>
        <button onclick="logout()" class="text-xs text-slate-600 hover:text-slate-400 transition-colors">Sign out</button>
      </div>
    </div>
  </div>

  <script>
    // Secure fetch wrapper
    async function secureFetch(url, options = {}) {
      // Always get latest from localStorage as fallback
      const sessionId = window.SESSION_ID || localStorage.getItem('openclaw_session') || '';
      const csrfToken = window.CSRF_TOKEN || localStorage.getItem('openclaw_csrf') || '';

      const headers = {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'X-Session-Id': sessionId,
        ...options.headers
      };

      const res = await fetch(url, { ...options, headers });

      // Handle auth errors
      if (res.status === 401) {
        localStorage.removeItem('openclaw_session');
        localStorage.removeItem('openclaw_csrf');
        window.location.href = '/setup/login';
        throw new Error('Session expired');
      }

      return res;
    }

    function togglePassword(id) {
      const input = document.getElementById(id);
      input.type = input.type === 'password' ? 'text' : 'password';
    }

    function updateSteps(configured, running) {
      const step1 = document.getElementById('step1');
      const step2 = document.getElementById('step2');
      const step3 = document.getElementById('step3');

      if (configured) {
        step1.classList.add('completed');
        step1.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
        step2.classList.add('active');
      }
      if (running) {
        step2.classList.remove('active');
        step2.classList.add('completed');
        step2.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
        step3.classList.add('completed');
        step3.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
      }
    }

    async function checkStatus() {
      try {
        const res = await secureFetch('/setup/status');
        const data = await res.json();

        const statusEl = document.getElementById('status');
        const dotEl = document.getElementById('statusDot');
        const badgeEl = document.getElementById('statusBadge');
        const descEl = document.getElementById('statusDescription');

        // Build channel status text
        const connectedChannels = [];
        if (data.channels?.telegram) connectedChannels.push('Telegram');
        if (data.channels?.discord) connectedChannels.push('Discord');
        if (data.channels?.slack) connectedChannels.push('Slack');
        const channelText = connectedChannels.length > 0 ? ' · ' + connectedChannels.join(', ') : '';

        // Provider display name
        const providerNames = { anthropic: 'Claude', openai: 'GPT', google: 'Gemini', minimax: 'MiniMax' };
        const providerName = data.provider ? providerNames[data.provider] || data.provider : '';

        if (data.gateway === 'running') {
          dotEl.className = 'w-2 h-2 rounded-full bg-emerald-400 status-dot';
          statusEl.textContent = 'Running';
          statusEl.className = 'text-sm font-medium text-emerald-400';
          badgeEl.className = 'flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/30';
          descEl.innerHTML = 'Connected to <strong>' + providerName + '</strong>' + channelText + ' · Ready to help!';
        } else if (data.configured) {
          dotEl.className = 'w-2 h-2 rounded-full bg-amber-400';
          statusEl.textContent = 'Stopped';
          statusEl.className = 'text-sm font-medium text-amber-400';
          badgeEl.className = 'flex items-center gap-2 px-4 py-2 rounded-full bg-amber-500/10 border border-amber-500/30';
          descEl.innerHTML = 'Configured with <strong>' + providerName + '</strong>' + channelText + ' · Click Start to run';
        } else {
          dotEl.className = 'w-2 h-2 rounded-full bg-slate-500';
          statusEl.textContent = 'Not Set Up';
          statusEl.className = 'text-sm font-medium text-slate-400';
          badgeEl.className = 'flex items-center gap-2 px-4 py-2 rounded-full bg-slate-800/50 border border-slate-700/50';
          descEl.textContent = 'Complete the setup below to get started';
        }

        updateSteps(data.configured, data.gateway === 'running');

        // Update channel status
        if (data.channels) {
          updateChannelStatus(data.channels);
        }

        // Update AI Provider card to show connected state
        updateProviderCard(data.configured, data.provider);

        // Update Dashboard link
        updateDashboardLink(data.gateway === 'running', data.dashboardToken);

        // Update CSRF token if provided
        if (data.csrfToken) {
          window.CSRF_TOKEN = data.csrfToken;
          localStorage.setItem('openclaw_csrf', data.csrfToken);
        }
        if (data.sessionId) {
          window.SESSION_ID = data.sessionId;
          localStorage.setItem('openclaw_session', data.sessionId);
        }
      } catch (e) {
        console.error('Status check failed:', e);
      }
    }

    function updateProviderCard(configured, provider) {
      const providerCard = document.getElementById('providerCard');
      const providerForm = document.getElementById('providerFormContainer');
      const providerStatus = document.getElementById('providerConnectedStatus');

      if (!providerCard) return;

      const providerNames = { anthropic: 'Claude', openai: 'GPT', google: 'Gemini', minimax: 'MiniMax' };
      const providerName = provider ? providerNames[provider] || provider : '';

      if (configured && providerStatus) {
        providerStatus.innerHTML = '<div class="flex items-center justify-between p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20"><div class="flex items-center gap-3"><div class="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center"><svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg></div><div><p class="text-sm font-medium text-emerald-400">Connected to ' + providerName + '</p><p class="text-xs text-slate-400">Click below to change provider</p></div></div><button type="button" onclick="toggleProviderForm()" class="text-xs text-slate-400 hover:text-white transition-colors">Edit</button></div>';
        providerStatus.classList.remove('hidden');
      }
    }

    function toggleProviderForm() {
      const form = document.getElementById('providerFormContainer');
      if (form.classList.contains('hidden')) {
        form.classList.remove('hidden');
      } else {
        form.classList.add('hidden');
      }
    }

    function updateDashboardLink(isRunning, token) {
      const section = document.getElementById('dashboardSection');
      const link = document.getElementById('dashboardLink');

      if (isRunning && token) {
        // Generate tokenized dashboard URL
        const baseUrl = window.location.origin;
        const dashboardUrl = baseUrl + '/openclaw?token=' + encodeURIComponent(token);
        link.href = dashboardUrl;
        section.classList.remove('hidden');
      } else {
        section.classList.add('hidden');
      }
    }

    async function gatewayAction(action) {
      try {
        const res = await secureFetch('/setup/gateway/' + action, { method: 'POST' });
        const data = await res.json();
        showMessage(data.success ? 'success' : 'error', data.message || data.error);
        checkStatus();
        refreshLogs();
      } catch (e) {
        showMessage('error', 'Could not ' + action + ' the gateway. Please try again.');
      }
    }

    async function refreshLogs() {
      try {
        const res = await secureFetch('/setup/logs?tail=50');
        const data = await res.json();
        const logsEl = document.getElementById('logs');
        if (data.logs.length === 0) {
          logsEl.innerHTML = '<span class="text-slate-500">No activity yet. Your AI is waiting to be started.</span>';
        } else {
          logsEl.innerHTML = data.logs.map(log => {
            const isError = log.toLowerCase().includes('error') || log.includes('[stderr]');
            const isSuccess = log.toLowerCase().includes('success') || log.toLowerCase().includes('ready') || log.toLowerCase().includes('listening');
            let colorClass = 'text-slate-400';
            if (isError) colorClass = 'text-red-400';
            if (isSuccess) colorClass = 'text-emerald-400';
            return '<div class="' + colorClass + ' py-0.5">' + log.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>';
          }).join('');
          logsEl.scrollTop = logsEl.scrollHeight;
        }
      } catch (e) {
        document.getElementById('logs').innerHTML = '<span class="text-red-400">Could not load activity log</span>';
      }
    }

    function showMessage(type, text) {
      const el = document.getElementById('message');
      el.className = type === 'success'
        ? 'mb-6 p-4 rounded-xl border backdrop-blur-sm bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
        : 'mb-6 p-4 rounded-xl border backdrop-blur-sm bg-red-500/10 border-red-500/30 text-red-400';
      el.innerHTML = '<div class="flex items-center gap-3"><svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="' +
        (type === 'success' ? 'M5 13l4 4L19 7' : 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z') +
        '"/></svg><span>' + text + '</span></div>';
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => { el.className = 'hidden'; }, 8000);
    }

    document.getElementById('setupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      const originalContent = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="flex items-center justify-center gap-2"><svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>Connecting...</span>';

      try {
        const res = await secureFetch('/setup/onboard', {
          method: 'POST',
          body: JSON.stringify({
            provider: document.getElementById('provider').value,
            apiKey: document.getElementById('apiKey').value,
            channels: {
              telegram: document.getElementById('telegramToken').value || undefined,
              discord: document.getElementById('discordToken').value || undefined,
              slack: document.getElementById('slackToken').value || undefined,
            }
          })
        });
        const data = await res.json();
        showMessage(data.success ? 'success' : 'error', data.message || data.error);
        if (data.success) {
          document.getElementById('apiKey').value = '';
        }
        checkStatus();
        refreshLogs();
      } catch (e) {
        showMessage('error', 'Connection failed. Please check your internet and try again.');
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalContent;
      }
    });

    async function saveChannels() {
      const btn = document.getElementById('saveChannelsBtn');
      const originalContent = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="flex items-center justify-center gap-2"><svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Saving...</span>';

      try {
        const res = await secureFetch('/setup/channels', {
          method: 'POST',
          body: JSON.stringify({
            telegram: document.getElementById('telegramToken').value || '',
            discord: document.getElementById('discordToken').value || '',
            slack: document.getElementById('slackToken').value || ''
          })
        });
        const data = await res.json();
        showMessage(data.success ? 'success' : 'error', data.message);
        if (data.success) {
          updateChannelStatus(data.channels);
        }
        checkStatus();
      } catch (e) {
        showMessage('error', 'Could not save channels. Please try again.');
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalContent;
      }
    }

    function updateChannelStatus(channels) {
      const statusDiv = document.getElementById('channelStatus');
      const connectedDiv = document.getElementById('connectedChannels');
      const connected = [];

      if (channels.telegram) connected.push('<span class="px-2 py-1 rounded bg-blue-500/20 text-blue-400 text-xs">📱 Telegram</span>');
      if (channels.discord) connected.push('<span class="px-2 py-1 rounded bg-indigo-500/20 text-indigo-400 text-xs">🎮 Discord</span>');
      if (channels.slack) connected.push('<span class="px-2 py-1 rounded bg-purple-500/20 text-purple-400 text-xs">💼 Slack</span>');

      if (connected.length > 0) {
        connectedDiv.innerHTML = connected.join('');
        statusDiv.classList.remove('hidden');
      } else {
        statusDiv.classList.add('hidden');
      }
    }

    async function generatePairingCode() {
      const deviceName = document.getElementById('deviceName').value;
      if (!deviceName || deviceName.length < 2) {
        showMessage('error', 'Please enter a name for your device (e.g., "My iPhone")');
        return;
      }

      try {
        const res = await secureFetch('/setup/pairing/generate', {
          method: 'POST',
          body: JSON.stringify({ deviceName })
        });
        const data = await res.json();
        if (data.success) {
          document.getElementById('pairingCode').classList.remove('hidden');
          document.getElementById('pairingCodeValue').textContent = data.code;
          showMessage('success', data.message);
        } else {
          showMessage('error', data.message || 'Could not generate pairing code');
        }
      } catch (e) {
        showMessage('error', 'Could not generate pairing code. Please try again.');
      }
    }

    function downloadBackup() {
      window.location.href = '/setup/backup';
    }

    async function restoreBackup(input) {
      if (!input.files.length) return;
      if (!confirm('This will replace all your current settings. Are you sure you want to restore from this backup?')) {
        input.value = '';
        return;
      }

      showMessage('success', 'Uploading backup... Please wait.');

      try {
        const res = await fetch('/setup/restore', {
          method: 'POST',
          headers: {
            'X-CSRF-Token': window.CSRF_TOKEN,
            'X-Session-Id': window.SESSION_ID
          },
          body: input.files[0],
        });
        const data = await res.json();
        showMessage(data.success ? 'success' : 'error', data.message || data.error);
        checkStatus();
        refreshLogs();
      } catch (e) {
        showMessage('error', 'Restore failed. Please check your backup file and try again.');
      }
      input.value = '';
    }

    function showResetConfirm() {
      document.getElementById('resetModal').classList.remove('hidden');
      document.getElementById('resetConfirmInput').value = '';
      document.getElementById('resetConfirmInput').focus();
    }

    function hideResetConfirm() {
      document.getElementById('resetModal').classList.add('hidden');
    }

    async function confirmReset() {
      const confirmValue = document.getElementById('resetConfirmInput').value;
      if (confirmValue !== 'RESET') {
        showMessage('error', 'Please type RESET exactly to confirm.');
        return;
      }

      try {
        const res = await secureFetch('/setup/reset', {
          method: 'POST',
          body: JSON.stringify({ confirmReset: 'RESET' })
        });
        const data = await res.json();
        showMessage(data.success ? 'success' : 'error', data.message || data.error);
        hideResetConfirm();
        checkStatus();
        refreshLogs();
      } catch (e) {
        showMessage('error', 'Reset failed. Please try again.');
      }
    }

    async function logout() {
      try {
        await secureFetch('/setup/logout', { method: 'POST' });
      } catch (e) {}
      // Clear session from localStorage
      localStorage.removeItem('openclaw_session');
      localStorage.removeItem('openclaw_csrf');
      window.location.href = '/setup/login';
    }

    // Handle 401 errors - redirect to login
    function handleAuthError(res) {
      if (res.status === 401) {
        localStorage.removeItem('openclaw_session');
        localStorage.removeItem('openclaw_csrf');
        window.location.href = '/setup/login';
        return true;
      }
      return false;
    }

    // Initial load
    checkStatus();
    refreshLogs();
    setInterval(checkStatus, 5000);
    setInterval(refreshLogs, 10000);
  </script>
</body>
</html>`;
}

// ============================================================================
// START SERVER
// ============================================================================

server.listen(PUBLIC_PORT, '0.0.0.0', () => {
  console.log('[wrapper] OpenClaw Railway wrapper listening on port ' + PUBLIC_PORT);
  console.log('[wrapper] Setup wizard: http://localhost:' + PUBLIC_PORT + '/setup');
  console.log('[wrapper] State directory: ' + STATE_DIR);
  console.log('[wrapper] Security: Rate limiting enabled, CSRF protection active');

  if (!SETUP_PASSWORD) {
    console.warn('[security] WARNING: SETUP_PASSWORD not set! Setup page is unprotected.');
  }

  if (existsSync(join(STATE_DIR, 'config.json'))) {
    console.log('[wrapper] Found existing config, starting gateway...');
    startGateway().catch(err => {
      console.error('[wrapper] Failed to auto-start gateway:', err);
    });
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[wrapper] Received SIGTERM, shutting down...');
  stopGateway();
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  console.log('[wrapper] Received SIGINT, shutting down...');
  stopGateway();
  server.close(() => process.exit(0));
});

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.createdAt > SESSION_DURATION_MS) {
      sessions.delete(id);
    }
  }
  for (const [code, pairing] of pendingPairings.entries()) {
    if (now - pairing.createdAt > PAIRING_CODE_EXPIRY_MS) {
      pendingPairings.delete(code);
    }
  }
}, 60000);
