# ClawdBot (OpenClaw) Railway Template

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.com/deploy/hogNz1?referralCode=kXOukk&utm_medium=integration&utm_source=template&utm_campaign=generic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D22-brightgreen)](https://nodejs.org/)

One-click deployment template for [OpenClaw](https://openclaw.ai/) on [Railway](https://railway.com/?referralCode=kXOukk). Deploy your own AI assistant with a beautiful web-based setup wizard - no command line required.

> **New to Railway?** [Sign up here](https://railway.com/?referralCode=kXOukk) and get $5 in free credits to get started!

## What is OpenClaw?

OpenClaw is an open-source personal AI assistant that can:
- Manage your emails and calendar
- Automate repetitive tasks
- Browse the web and extract information
- Connect to 50+ integrations (Gmail, GitHub, Spotify, etc.)
- Chat with you via Telegram, Discord, Slack, or WhatsApp

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Browser                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐    │
│  │ Login Page  │ ──▶ │ Setup Page  │ ──▶ │ OpenClaw UI     │    │
│  │ (Password)  │     │ (Configure) │     │ (Chat & Tasks)  │    │
│  └─────────────┘     └─────────────┘     └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Railway Server (:8080)                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Wrapper Server                          │  │
│  │  • Password-protected login page                           │  │
│  │  • Setup wizard with step-by-step configuration           │  │
│  │  • Rate limiting & CSRF protection                        │  │
│  │  • Proxies requests to OpenClaw Gateway                   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              OpenClaw Gateway (localhost:18789)            │  │
│  │  • Runs your AI assistant                                  │  │
│  │  • Processes chat messages                                 │  │
│  │  • Executes automations                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Volume: /data                            │  │
│  │  ├── .openclaw/  (config, tokens, state)                  │  │
│  │  └── workspace/  (files, memory, skills)                  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Security
- **Password-protected setup** - Clean login page (not browser popup)
- **Rate limiting** - Blocks IPs after 5 failed attempts for 15 minutes
- **CSRF protection** - Prevents cross-site request forgery
- **Session management** - Secure 24-hour sessions with auto-cleanup
- **Secure headers** - HSTS, X-Frame-Options, CSP, XSS protection

### User Experience
- **Step-by-step wizard** - Visual progress through setup
- **Device pairing** - Connect phones/devices with 6-character codes
- **Backup & restore** - Export/import your configuration
- **Real-time logs** - See what your AI is doing
- **Beautiful UI** - Tailwind CSS with dark mode, glassmorphism

### Infrastructure
- **Persistent storage** - State survives redeploys
- **Auto-restart** - Gateway automatically restarts on failure
- **Health checks** - Railway monitors your service
- **One-click deploy** - No command line required

## Quick Deploy

1. **Click the Deploy button** above
2. **Add one variable** - Set `SETUP_PASSWORD` to a strong password
3. **Click Deploy** - Wait 3-5 minutes for build
4. **Open your app** - Go to `https://your-app.railway.app/setup`
5. **Log in** - Enter the password you set
6. **Configure AI** - Select provider and paste your API key
7. **Done!** - Your AI assistant is running

> **Note:** The persistent volume (`/data`) and other settings are **automatically configured** from `railway.toml`. You only need to set `SETUP_PASSWORD`.

## Railway Template Setup

When creating the template in Railway:

| Setting | Value |
|---------|-------|
| **Source** | Your GitHub repo |
| **Branch** | `main` |
| **Environment Variables** | Add `SETUP_PASSWORD` (required) |
| **Volume** | Auto-configured at `/data` |
| **Networking** | Public HTTP (auto-configured) |
| **Health Check** | `/setup/healthz` (auto-configured) |

Everything else is pre-configured in `railway.toml`:
```toml
[build]
builder = "dockerfile"

[deploy]
healthcheckPath = "/setup/healthz"
healthcheckTimeout = 300
restartPolicyType = "on_failure"

[[mounts]]
mount = "/data"

[variables]
PORT = "8080"
OPENCLAW_STATE_DIR = "/data/.openclaw"
OPENCLAW_WORKSPACE_DIR = "/data/workspace"
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SETUP_PASSWORD` | **Yes** | Password to access the setup wizard |
| `OPENCLAW_STATE_DIR` | No | Auto-configured: `/data/.openclaw` |
| `OPENCLAW_WORKSPACE_DIR` | No | Auto-configured: `/data/workspace` |
| `OPENCLAW_GATEWAY_TOKEN` | No | Gateway auth token (auto-generated) |
| `OPENCLAW_GIT_REF` | No | Git ref to build OpenClaw from (default: `main`) |

## Supported AI Providers

| Provider | Get API Key | Notes |
|----------|-------------|-------|
| **Anthropic** (Claude) | [console.anthropic.com](https://console.anthropic.com/settings/keys) | Recommended, best quality |
| **OpenAI** (GPT) | [platform.openai.com](https://platform.openai.com/api-keys) | Wide compatibility |
| **Google** (Gemini) | [aistudio.google.com](https://aistudio.google.com/apikey) | Free tier available |
| **MiniMax** | [10% OFF with this link](https://platform.minimax.io/subscribe/coding-plan?code=AlUL2IhlbC&source=link) | Budget-friendly option |

## Supported Chat Channels

- **Telegram** - Get token from [@BotFather](https://t.me/botfather)
- **Discord** - Create bot at [Discord Developer Portal](https://discord.com/developers/applications)
- **Slack** - Create app at [Slack API](https://api.slack.com/apps)
- **WhatsApp** - Requires additional setup via OpenClaw

## Local Development

```bash
# Clone the repository
git clone https://github.com/zadahmed/clawdbot-railway-template
cd clawdbot-railway-template

# Build the Docker image
docker build -t clawdbot-railway .

# Run locally
docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e SETUP_PASSWORD=test \
  -e OPENCLAW_STATE_DIR=/data/.openclaw \
  -e OPENCLAW_WORKSPACE_DIR=/data/workspace \
  -v $(pwd)/.tmpdata:/data \
  clawdbot-railway

# Open http://localhost:8080/setup
```

## API Endpoints

### Public (No Auth)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/setup/healthz` | GET | Health check |
| `/setup/login` | GET | Login page |
| `/setup/login` | POST | Authenticate |

### Protected (Requires Auth)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/setup` | GET | Setup wizard |
| `/setup/status` | GET | Gateway status |
| `/setup/onboard` | POST | Configure AI provider |
| `/setup/reset` | POST | Reset all settings |
| `/setup/gateway/start` | POST | Start gateway |
| `/setup/gateway/stop` | POST | Stop gateway |
| `/setup/gateway/restart` | POST | Restart gateway |
| `/setup/pairing/generate` | POST | Generate device pairing code |
| `/setup/pairing/approve` | POST | Approve device pairing |
| `/setup/logs` | GET | View gateway logs |
| `/setup/backup` | GET | Download backup |
| `/setup/restore` | POST | Restore from backup |
| `/setup/logout` | POST | End session |

## Project Structure

```
clawdbot-railway-template/
├── src/
│   └── server.js       # Express wrapper server (1400+ lines)
├── scripts/
│   └── smoke.js        # Smoke tests
├── Dockerfile          # Multi-stage Docker build
├── package.json        # Node.js dependencies
├── railway.toml        # Railway configuration
├── .env.example        # Environment template
└── README.md           # This file
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Troubleshooting

### "Gateway not ready" error
- Make sure you've completed the setup wizard
- Check if your API key is valid
- Look at the logs in the setup page

### "Gateway closed (1006)" or "token_mismatch" during onboard
- The setup wizard runs onboard **without** starting the gateway first, then starts the gateway afterward. This avoids the probe connecting to a gateway that is restarting (config writes) and seeing a token mismatch. The flow is: configure auth → run onboard → re-apply token in config → start gateway.

### Login not working
- Verify your `SETUP_PASSWORD` environment variable
- Clear browser cache and cookies
- Wait 15 minutes if you've been locked out

### Gateway won't start
- Ensure you have a valid API key configured
- Check Railway logs for errors
- Try restarting the service

### Dashboard shows "pairing required" or "unauthorized"
- Always open the dashboard using the **"Open OpenClaw Dashboard"** link on the setup page (`/setup`). That link includes the auth token in the URL (`/openclaw?token=...`).
- If you bookmarked or typed the URL without the token, go back to `/setup` and click the dashboard link again so the token is included.

## Resources

- [OpenClaw Documentation](https://docs.openclaw.ai)
- [OpenClaw GitHub](https://github.com/openclaw/openclaw)
- [Railway Documentation](https://docs.railway.com)
- [Get Started with Railway](https://railway.com/?referralCode=kXOukk) - $5 free credits

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

- [OpenClaw](https://openclaw.ai) - The AI that actually does things
- [Railway](https://railway.com) - Deploy in seconds
- Based on work by [@vignesh07](https://github.com/vignesh07)

---

Made with love for the open-source community
