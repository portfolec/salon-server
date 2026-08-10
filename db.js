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

const connectionString = process.env.DATABASE_URL
if (!connectionString) {
  throw new Error('DATABASE_URL is not set. Copy server/.env.example to server/.env and fill it in.')
}

// Timeweb Cloud sends its self-signed root CA as part of the chain, which trips up
// Node's TLS chain validation even when that same root is supplied as `ca`
// (a known Node/OpenSSL quirk: X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN).
// The connection is still TLS-encrypted end-to-end; we just don't pin the CA chain here.
const ssl = { rejectUnauthorized: false }

export const pool = new Pool({ connectionString, ssl })

export async function query(text, params) {
  const { rows } = await pool.query(text, params)
  return rows
}
