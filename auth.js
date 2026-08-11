import crypto from 'crypto'
import bcrypt from 'bcryptjs'
import { query } from './db.js'

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

export function hashPassword(password) {
  return bcrypt.hashSync(password, 10)
}

export function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash)
}

/** Maps a permission key (used by the frontend) to its DB column. */
export const PERMISSION_COLUMNS = {
  bookings: 'can_bookings',
  masters: 'can_masters',
  schedule: 'can_schedule',
  services: 'can_services',
  vacancies: 'can_vacancies',
  content: 'can_content',
  notifications: 'can_notifications',
}

/** Strips the password hash and reshapes DB columns into a client-friendly user object. */
export function toPublicUser(row) {
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    active: row.active,
    createdAt: row.created_at,
    permissions: Object.fromEntries(
      Object.entries(PERMISSION_COLUMNS).map(([key, col]) => [key, !!row[col]]),
    ),
  }
}

export async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS)
  await query('INSERT INTO admin_sessions (token, user_id, expires_at) VALUES ($1,$2,$3)', [token, userId, expiresAt])
  return token
}

export async function deleteSession(token) {
  await query('DELETE FROM admin_sessions WHERE token = $1', [token])
}

export async function getSessionUser(token) {
  if (!token) return null
  const rows = await query(
    `SELECT u.* FROM admin_sessions s
     JOIN admin_users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > now() AND u.active = true`,
    [token],
  )
  return rows[0] ?? null
}

/** Reads and validates the Bearer token, attaching req.adminUser (raw DB row) + req.adminToken. */
export function requireAuth(req, res, next) {
  const header = req.headers.authorization ?? ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' })
  getSessionUser(token)
    .then(user => {
      if (!user) return res.status(401).json({ error: 'Сессия истекла, войдите снова' })
      req.adminUser = user
      req.adminToken = token
      next()
    })
    .catch(next)
}

/**
 * Returns middleware requiring the caller to be authenticated AND have at least
 * one of the given permissions (or be an 'owner', who bypasses all checks).
 */
export function requirePermission(...perms) {
  return [
    requireAuth,
    (req, res, next) => {
      const user = req.adminUser
      if (user.role === 'owner') return next()
      const ok = perms.some(p => user[PERMISSION_COLUMNS[p]])
      if (!ok) return res.status(403).json({ error: 'Недостаточно прав для этого действия' })
      next()
    },
  ]
}

/** Requires an authenticated 'owner' account (user management). */
export const requireOwner = [
  requireAuth,
  (req, res, next) => {
    if (req.adminUser.role !== 'owner') return res.status(403).json({ error: 'Требуются права владельца' })
    next()
  },
]
