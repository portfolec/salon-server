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
| `S3_ENDPOINT` | Timeweb S3 endpoint, default `https://s3.twcstorage.ru` |
| `S3_REGION` | Default `ru-1` |
| `S3_BUCKET` | Bucket name for uploaded master photos (must be a **public** bucket) |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | Timeweb S3 storage credentials |

## File uploads (master photos)

`POST /api/upload` (multipart field `photo`) is used by the admin panel to
upload master photos. It uploads to Timeweb's S3-compatible object storage
when `S3_BUCKET`/`S3_ACCESS_KEY`/`S3_SECRET_KEY` are set — **do this in
production**, since App Platform's own filesystem is ephemeral/read-only and
files written there don't survive a redeploy or restart.

If the S3 vars are not set, it falls back to writing to local disk
(`UPLOADS_DIR`, or `server/uploads`, or the OS temp dir) — fine for local
development only.

To create the bucket: Timeweb Cloud panel → «Хранилище S3» → «Создать бакет»,
type **Публичный**. Grab the Access Key / Secret Key from the same page.

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
