# Agent Memory

- Do not run the Tawny-SOC Next.js web app locally in Docker.
- For local development, run Postgres with Docker Compose and run the web app with `pnpm dev`.
- Use `docker compose up -d db` for the local database only.
- The Docker `app` service is only for explicit container/deployment checks and must be started with an explicit profile when needed.
