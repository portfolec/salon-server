import { Pool, types } from 'pg'
import path from 'path'
import { fileURLToPath } from 'url'
import dotenv from 'dotenv'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
dotenv.config({ path: path.join(__dirname, '.env') })

// Keep DATE columns as plain "YYYY-MM-DD" strings instead of JS Date objects —
// the default parser converts to local-midnight Date, which shifts the day
// by the server's UTC offset once serialized to JSON.
types.setTypeParser(types.builtins.DATE, (val) => val)

// Timeweb Cloud sends its self-signed root CA as part of the chain, which trips up
// Node's TLS chain validation even when that same root is supplied as `ca`
// (a known Node/OpenSSL quirk: X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN).
// The connection is still TLS-encrypted end-to-end; we just don't pin the CA chain here.
const ssl = { rejectUnauthorized: false }

// Prefer discrete PG* vars — some hosting UIs mangle special characters (like
// the ">" in this DB's password) when pasted into a single connection-string
// field. Individual fields avoid any need for URL-encoding entirely.
const hasDiscreteVars = process.env.PGHOST && process.env.PGUSER && process.env.PGPASSWORD && process.env.PGDATABASE

let poolConfig
if (hasDiscreteVars) {
  poolConfig = {
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT) || 5432,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    ssl,
  }
} else if (process.env.DATABASE_URL) {
  poolConfig = { connectionString: process.env.DATABASE_URL, ssl }
} else {
  throw new Error(
    'No database credentials set. Provide either DATABASE_URL, or PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE.',
  )
}

export const pool = new Pool(poolConfig)

export async function query(text, params) {
  const { rows } = await pool.query(text, params)
  return rows
}
