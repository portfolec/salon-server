# salon-server

Backend API for the «Стильный Акцент» salon website. A small Express server that
talks directly to a PostgreSQL database (hosted on Timeweb Cloud) and exposes
REST endpoints consumed by the frontend (see the `salon` repo).

## Why this exists

The frontend is a client-side React SPA — browsers cannot open raw TCP
connections to Postgres, so this server sits in between: it holds the DB
credentials and exposes plain JSON/HTTP endpoints instead.

## Setup

```bash
npm install
cp .env.example .env   # fill in DATABASE_URL
npm start
```

The server listens on `PORT` (default `8787`).

## Environment variables

| Variable | Description |
|---|---|
| `PORT` | Port to listen on (default `8787`) |
| `DATABASE_URL` | Postgres connection string, e.g. `postgresql://user:pass@host:5432/dbname`. Percent-encode special characters in the password. |

## Deploying on Timeweb Cloud Apps

1. Create a new Node.js app, point it at this repository.
2. Set the `DATABASE_URL` environment variable in the app settings (do **not**
   commit real credentials to `.env`).
3. Build command: `npm install`. Start command: `npm start`.
4. Once deployed, point the frontend's `VITE_API_URL` env var at this app's
   public URL.

## API

All endpoints are prefixed with `/api`: `services`, `masters`, `masters/:id/schedule`,
`masters/:id/days-off`, `masters/:id/service-days`, `bookings`, `content`,
`vacancies`, `availability/days`, `availability/slots`, `health`.
