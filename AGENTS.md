# Agent Memory

- Do not run the Tawny-SOC Next.js web app locally in Docker.
- For local development, run Postgres with Docker Compose and run the web app with `pnpm dev`.
- Use `docker compose up -d db` for the local database only.
- The Docker `app` service is only for explicit container/deployment checks and must be started with an explicit profile when needed.
- Homelab deploy target is Portainer host `192.168.1.19` only (`~/apps/tawny-soc`, `docker-compose.homelab.yml`, LAN port **3014**).
- Coolify is production and **off-limits** — never create, deploy, update, or delete Coolify resources for this project unless the user explicitly asks.
- Port **3001** on the homelab host is Tawny EDR web, not Tawny-SOC.
- Homelab handbook is nginx on **3010** at `~/homelab-docs/site/index.html` — update it when ports/stacks change.
