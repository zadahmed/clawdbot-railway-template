# ClawdBot Railway Template

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/clawdbot)

One-click deployment template for [OpenClaw](https://openclaw.ai/) on Railway. This template packages OpenClaw with a web-based setup wizard so you can deploy and configure without running any commands.

## Features

- **Setup Wizard** at `/setup` - Configure AI providers and chat channels via web UI
- **Password Protected** - Secure setup with `SETUP_PASSWORD` environment variable
- **Persistent Storage** - State survives redeploys via Railway Volume
- **Backup/Restore** - Export and import your configuration
- **Auto-restart** - Gateway automatically restarts on failure

## Quick Deploy

1. Click the **Deploy on Railway** button above
2. Set the required environment variable:
   - `SETUP_PASSWORD` - Password to access the setup wizard
3. Deploy and wait for the build to complete
4. Visit `https://your-app.railway.app/setup` to configure your AI provider

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SETUP_PASSWORD` | **Yes** | Password to access `/setup` wizard |
| `OPENCLAW_STATE_DIR` | No | State directory (default: `/data/.openclaw`) |
| `OPENCLAW_WORKSPACE_DIR` | No | Workspace directory (default: `/data/workspace`) |
| `OPENCLAW_GATEWAY_TOKEN` | No | Gateway auth token (auto-generated if not set) |
| `OPENCLAW_GIT_REF` | No | Git ref to build OpenClaw from (default: `main`) |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Railway                         │
│  ┌───────────────────────────────────────────┐  │
│  │           Wrapper Server (:8080)          │  │
│  │  ┌─────────────┐    ┌─────────────────┐   │  │
│  │  │ /setup/*    │    │ Proxy to Gateway│   │  │
│  │  │ (Auth + UI) │    │ (all other req) │   │  │
│  │  └─────────────┘    └─────────────────┘   │  │
│  │                            │              │  │
│  │                            ▼              │  │
│  │              ┌─────────────────────┐      │  │
│  │              │ OpenClaw Gateway    │      │  │
│  │              │ (127.0.0.1:18789)   │      │  │
│  │              └─────────────────────┘      │  │
│  └───────────────────────────────────────────┘  │
│                        │                         │
│  ┌─────────────────────┴─────────────────────┐  │
│  │            Volume: /data                   │  │
│  │  ├── .openclaw/  (state, config, token)   │  │
│  │  └── workspace/  (files, memory)          │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Local Development

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/clawdbot-railway-template.git
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

# Visit http://localhost:8080/setup
```

## Setup Wizard Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/setup` | GET | Setup wizard UI |
| `/setup/healthz` | GET | Health check (no auth) |
| `/setup/status` | GET | Gateway status |
| `/setup/onboard` | POST | Configure and start |
| `/setup/gateway/start` | POST | Start gateway |
| `/setup/gateway/stop` | POST | Stop gateway |
| `/setup/gateway/restart` | POST | Restart gateway |
| `/setup/logs` | GET | View gateway logs |
| `/setup/backup` | GET | Download backup |
| `/setup/restore` | POST | Upload backup |

## Supported AI Providers

- **Anthropic** (Claude)
- **OpenAI** (GPT)
- **Google** (Gemini)

## Supported Chat Channels

- Telegram
- Discord
- Slack
- WhatsApp (requires additional setup)

## Resources

- [OpenClaw Documentation](https://docs.openclaw.ai)
- [OpenClaw GitHub](https://github.com/openclaw/openclaw)
- [Railway Documentation](https://docs.railway.com)

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Based on the [official OpenClaw Railway template](https://github.com/vignesh07/clawdbot-railway-template) by [@vignesh07](https://github.com/vignesh07).
