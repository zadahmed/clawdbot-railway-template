# ClawdBot Railway Template

Deploy [OpenClaw](https://openclaw.ai/) - The AI that actually does things - on Railway with one click.

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/clawdbot)

## What is OpenClaw?

OpenClaw (formerly ClawdBot) is an open-source personal AI assistant that automates tasks like:
- Email management
- Calendar handling
- Flight check-ins
- Browser automation
- And 50+ integrations

## Features

- **Multi-Platform Chat**: WhatsApp, Telegram, Discord, Slack, Signal, iMessage
- **Persistent Memory**: Maintains context across sessions
- **Browser Automation**: Navigate websites, fill forms, extract data
- **Extensible**: Community skills library + self-writing capability

## Environment Variables

Configure the following variables in your Railway project:

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes* | Your Anthropic API key for Claude |
| `OPENAI_API_KEY` | Yes* | Your OpenAI API key (alternative to Anthropic) |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot token for Telegram integration |
| `DISCORD_BOT_TOKEN` | No | Discord bot token for Discord integration |
| `SLACK_BOT_TOKEN` | No | Slack bot token for Slack integration |
| `WHATSAPP_SESSION` | No | WhatsApp session data |
| `DATABASE_URL` | No | Database connection string (auto-configured if using Railway Postgres) |
| `REDIS_URL` | No | Redis connection string (auto-configured if using Railway Redis) |
| `PORT` | No | Server port (default: 3000) |

*At least one AI provider API key is required.

## Quick Deploy

1. Click the "Deploy on Railway" button above
2. Configure your environment variables
3. Deploy!

## Adding Services

For full functionality, consider adding these Railway services:

- **PostgreSQL**: For persistent memory storage
- **Redis**: For session caching and message queues

## Resources

- [OpenClaw Documentation](https://docs.openclaw.ai)
- [OpenClaw GitHub](https://github.com/openclaw/openclaw)
- [Skill Hub](https://clawhub.com)
- [Discord Community](https://discord.com/invite/clawd)

## License

This template is provided as-is. OpenClaw is licensed under its own terms - see the [OpenClaw repository](https://github.com/openclaw/openclaw) for details.
