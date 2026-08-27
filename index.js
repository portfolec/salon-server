import express from 'express'
import cors from 'cors'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import os from 'os'
import crypto from 'crypto'
import { fileURLToPath } from 'url'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
import { pool, query } from './db.js'
import {
  hashPassword, verifyPassword, toPublicUser,
  createSession, deleteSession, getSessionUser,
  requireAuth, requirePermission, requireOwner, requireMaster, optionalAuth,
} from './auth.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const app = express()
app.use(cors())
app.use(express.json())

const PORT = process.env.PORT || 8787

// ─── FILE UPLOADS (master photos etc.) ──────────────────────────────────────
//
// Preferred: Timeweb S3 object storage (persists across redeploys — App
// Platform's own filesystem is ephemeral and often read-only for the app user).
// Falls back to local disk for local development when S3 env vars aren't set.

const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif'])
const EXT_BY_MIME = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif', 'image/avif': '.avif' }

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'https://s3.twcstorage.ru'
const S3_REGION = process.env.S3_REGION || 'ru-1'
const S3_BUCKET = process.env.S3_BUCKET
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY
const S3_SECRET_KEY = process.env.S3_SECRET_KEY
const s3Configured = !!(S3_BUCKET && S3_ACCESS_KEY && S3_SECRET_KEY)

const s3Client = s3Configured
  ? new S3Client({
      region: S3_REGION,
      endpoint: S3_ENDPOINT,
      credentials: { accessKeyId: S3_ACCESS_KEY, secretAccessKey: S3_SECRET_KEY },
    })
  : null

function makeFilename(originalname, mimetype) {
  const ext = path.extname(originalname || '').toLowerCase() || EXT_BY_MIME[mimetype] || '.jpg'
  return `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`
}

// Local-disk fallback dir (only used when S3 isn't configured).
// Some hosting platforms run the app from a read-only directory as a non-root
// user, so writing next to the source code can fail with EACCES — try a few
// candidates and fall back to the OS temp dir (NOT persisted across restarts).
function resolveUploadsDir() {
  const candidates = [
    process.env.UPLOADS_DIR,
    path.join(__dirname, 'uploads'),
    path.join(os.tmpdir(), 'salon-uploads'),
  ].filter(Boolean)

  for (const dir of candidates) {
    try {
      fs.mkdirSync(dir, { recursive: true })
      fs.accessSync(dir, fs.constants.W_OK)
      return dir
    } catch {
      // try next candidate
    }
  }
  console.error('[uploads] No writable directory found, photo uploads will be disabled')
  return null
}

const UPLOADS_DIR = s3Configured ? null : resolveUploadsDir()
if (UPLOADS_DIR) app.use('/uploads', express.static(UPLOADS_DIR))

const upload = multer({
  storage: s3Configured
    ? multer.memoryStorage()
    : multer.diskStorage({
        destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
        filename: (_req, file, cb) => cb(null, makeFilename(file.originalname, file.mimetype)),
      }),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_IMAGE_TYPES.has(file.mimetype)) return cb(new Error('Недопустимый тип файла'))
    cb(null, true)
  },
})

app.post('/api/upload', requireAuth, (req, res) => {
  if (!s3Configured && !UPLOADS_DIR) {
    return res.status(503).json({ error: 'Загрузка файлов недоступна на сервере' })
  }
  upload.single('photo')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message })
    if (!req.file) return res.status(400).json({ error: 'Файл не получен' })

    if (!s3Configured) {
      return res.json({ url: `/uploads/${req.file.filename}` })
    }

    const key = makeFilename(req.file.originalname, req.file.mimetype)
    try {
      await s3Client.send(new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: key,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
      }))
      res.json({ url: `${S3_ENDPOINT}/${S3_BUCKET}/${key}` })
    } catch (e) {
      console.error('[uploads] S3 upload failed:', e)
      res.status(502).json({ error: 'Не удалось загрузить файл в хранилище' })
    }
  })
})

// `asyncHandler` is a function declaration further down this file — hoisted,
// so it's already callable up here.

// ─── AUTH ────────────────────────────────────────────────────────────────────

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body ?? {}
  if (!username || !password) return res.status(400).json({ error: 'Введите логин и пароль' })

  const rows = await query('SELECT * FROM admin_users WHERE username = $1', [username])
  const user = rows[0]
  if (!user || !user.active || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' })
  }
  const token = await createSession(user.id)
  res.json({ token, user: toPublicUser(user) })
}))

app.post('/api/auth/logout', requireAuth, asyncHandler(async (req, res) => {
  await deleteSession(req.adminToken)
  res.json({ ok: true })
}))

app.get('/api/auth/me', requireAuth, asyncHandler(async (req, res) => {
  res.json({ user: toPublicUser(req.adminUser) })
}))

// ─── ADMIN USERS (owner-only staff account management) ─────────────────────

app.get('/api/admin-users', requireOwner, asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM admin_users ORDER BY created_at')
  res.json(rows.map(toPublicUser))
}))

app.post('/api/admin-users', requireOwner, asyncHandler(async (req, res) => {
  const { username, password, role, permissions = {}, masterId } = req.body ?? {}
  if (!username?.trim() || !password) return res.status(400).json({ error: 'Логин и пароль обязательны' })
  if (password.length < 6) return res.status(400).json({ error: 'Пароль должен быть не короче 6 символов' })

  const existing = await query('SELECT id FROM admin_users WHERE username = $1', [username.trim()])
  if (existing.length) return res.status(409).json({ error: 'Такой логин уже существует' })

  const finalRole = role === 'owner' ? 'owner' : role === 'master' ? 'master' : 'staff'
  if (finalRole === 'master' && !isUuid(masterId)) {
    return res.status(400).json({ error: 'Выберите мастера для этого аккаунта' })
  }
  const isMaster = finalRole === 'master'

  const rows = await query(
    `INSERT INTO admin_users
       (username, password_hash, role, master_id, can_bookings, can_masters, can_schedule, can_services, can_vacancies, can_testimonials, can_content, can_notifications, active)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true) RETURNING *`,
    [
      username.trim(), hashPassword(password), finalRole, isMaster ? masterId : null,
      !isMaster && !!permissions.bookings, !isMaster && !!permissions.masters, !isMaster && !!permissions.schedule,
      !isMaster && !!permissions.services, !isMaster && !!permissions.vacancies, !isMaster && !!permissions.testimonials,
      !isMaster && !!permissions.content, !isMaster && !!permissions.notifications,
    ],
  )
  res.json(toPublicUser(rows[0]))
}))

app.put('/api/admin-users/:id', requireOwner, asyncHandler(async (req, res) => {
  const { id } = req.params
  const { password, role, permissions, active, masterId } = req.body ?? {}

  if (id === req.adminUser.id && active === false) {
    return res.status(400).json({ error: 'Нельзя отключить собственный аккаунт' })
  }
  if (id === req.adminUser.id && role && role !== 'owner') {
    return res.status(400).json({ error: 'Нельзя понизить собственные права' })
  }

  const finalRole = role === 'owner' ? 'owner' : role === 'staff' ? 'staff' : role === 'master' ? 'master' : undefined
  if (finalRole === 'master' && !isUuid(masterId)) {
    return res.status(400).json({ error: 'Выберите мастера для этого аккаунта' })
  }
  const isMaster = finalRole === 'master'
  const perm = permissions ?? {}
  await query(
    `UPDATE admin_users SET
       role = COALESCE($1, role),
       master_id = CASE WHEN $1 = 'master' THEN $12 WHEN $1 IN ('owner','staff') THEN NULL ELSE master_id END,
       active = COALESCE($2, active),
       can_bookings = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($3, can_bookings) END,
       can_masters = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($4, can_masters) END,
       can_schedule = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($5, can_schedule) END,
       can_services = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($6, can_services) END,
       can_vacancies = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($7, can_vacancies) END,
       can_testimonials = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($8, can_testimonials) END,
       can_content = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($9, can_content) END,
       can_notifications = CASE WHEN $1 = 'master' THEN false ELSE COALESCE($10, can_notifications) END
     WHERE id = $11`,
    [
      finalRole, typeof active === 'boolean' ? active : null,
      permissions ? !!perm.bookings : null,
      permissions ? !!perm.masters : null,
      permissions ? !!perm.schedule : null,
      permissions ? !!perm.services : null,
      permissions ? !!perm.vacancies : null,
      permissions ? !!perm.testimonials : null,
      permissions ? !!perm.content : null,
      permissions ? !!perm.notifications : null,
      id,
      isMaster ? masterId : null,
    ],
  )
  if (password) {
    if (password.length < 6) return res.status(400).json({ error: 'Пароль должен быть не короче 6 символов' })
    await query('UPDATE admin_users SET password_hash = $1 WHERE id = $2', [hashPassword(password), id])
  }
  const rows = await query('SELECT * FROM admin_users WHERE id = $1', [id])
  if (!rows.length) return res.status(404).json({ error: 'Пользователь не найден' })
  res.json(toPublicUser(rows[0]))
}))

app.delete('/api/admin-users/:id', requireOwner, asyncHandler(async (req, res) => {
  const { id } = req.params
  if (id === req.adminUser.id) return res.status(400).json({ error: 'Нельзя удалить собственный аккаунт' })
  const owners = await query("SELECT count(*)::int AS n FROM admin_users WHERE role = 'owner' AND active = true")
  const target = await query('SELECT role FROM admin_users WHERE id = $1', [id])
  if (target[0]?.role === 'owner' && owners[0].n <= 1) {
    return res.status(400).json({ error: 'Должен остаться хотя бы один владелец' })
  }
  await query('DELETE FROM admin_users WHERE id = $1', [id])
  res.status(204).end()
}))

// ─── helpers ────────────────────────────────────────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
function isUuid(v) { return typeof v === 'string' && UUID_RE.test(v) }

/** Hides the middle of a phone number for master accounts (e.g. "+7 999 ••• •• 67"). */
function maskPhone(phone) {
  const digits = (phone ?? '').replace(/\D/g, '')
  if (digits.length < 7) return '••••••'
  const country = digits.slice(0, digits.length - 10)
  const rest = digits.slice(-10)
  const op = rest.slice(0, 3)
  const last2 = rest.slice(-2)
  return `+${country ? country + ' ' : ''}${op} ••• •• ${last2}`
}

function toMinutes(t) {
  const [h, m] = String(t).slice(0, 5).split(':').map(Number)
  return h * 60 + (m ?? 0)
}
function minutesToTime(m) {
  return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`
}

/** Existing appointment occupies [start, start + duration) — only forward from its start. */
function bookingOccupiesSlot(slotMin, booking) {
  const start = toMinutes(booking.time)
  const end = start + (Number(booking.duration_minutes) || 60)
  return slotMin >= start && slotMin < end
}

function startConflictsWithBookings(slotMin, bookings) {
  return bookings.some(b => bookingOccupiesSlot(slotMin, b))
}

function pad2(n) {
  return String(n).padStart(2, '0')
}

function monthBounds(year, month0) {
  const last = new Date(year, month0 + 1, 0).getDate()
  return {
    start: `${year}-${pad2(month0 + 1)}-01`,
    end: `${year}-${pad2(month0 + 1)}-${pad2(last)}`,
    last,
  }
}

function dateDow(dateStr) {
  const [y, m, d] = String(dateStr).slice(0, 10).split('-').map(Number)
  const js = new Date(y, m - 1, d).getDay()
  return js === 0 ? 6 : js - 1
}

function groupWorkDays(rows) {
  const map = {}
  for (const r of rows) {
    const date = r.date
    if (!map[date]) map[date] = []
    map[date].push({
      startTime: String(r.start_time).slice(0, 5),
      endTime: String(r.end_time).slice(0, 5),
    })
  }
  return Object.entries(map)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, intervals]) => ({ date, intervals }))
}

function fitsInIntervals(startMin, endMin, intervals) {
  return intervals.some(iv => {
    const a = toMinutes(iv.start_time ?? iv.startTime)
    const b = toMinutes(iv.end_time ?? iv.endTime)
    return startMin >= a && endMin <= b
  })
}

function weekdayAllowed(days, dow) {
  return !days || days.size === 0 || days.has(dow)
}

function phoneDigits(phone) {
  let d = String(phone ?? '').replace(/\D/g, '')
  if (d.length === 11 && d[0] === '8') d = '7' + d.slice(1)
  if (d.length === 10) d = '7' + d
  return d
}

let clientProfilesReady = false
async function ensureClientProfiles() {
  if (clientProfilesReady) return
  await query(`
    CREATE TABLE IF NOT EXISTS client_profiles (
      phone_digits TEXT PRIMARY KEY,
      notes TEXT NOT NULL DEFAULT '',
      birthday DATE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`)
  await query(`ALTER TABLE client_profiles ADD COLUMN IF NOT EXISTS birthday DATE`)
  clientProfilesReady = true
}

function isoDateOnly(value) {
  const s = String(value ?? '').trim().slice(0, 10)
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ''
}

function normalizeIntervals(raw) {
  const list = []
  for (const iv of raw) {
    const startTime = String(iv.startTime ?? iv.start_time ?? '').slice(0, 5)
    const endTime = String(iv.endTime ?? iv.end_time ?? '').slice(0, 5)
    if (!startTime || !endTime || toMinutes(endTime) <= toMinutes(startTime)) continue
    list.push({ startTime, endTime })
  }
  list.sort((a, b) => toMinutes(a.startTime) - toMinutes(b.startTime))
  for (let i = 1; i < list.length; i++) {
    if (toMinutes(list[i].startTime) < toMinutes(list[i - 1].endTime)) return null
  }
  return list
}

let workTablesReady = false
async function ensureWorkTables() {
  if (workTablesReady) return
  await query(`
    CREATE TABLE IF NOT EXISTS master_work_intervals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      master_id UUID NOT NULL REFERENCES masters(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      start_time TIME NOT NULL,
      end_time TIME NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0
    )`)
  await query(`CREATE INDEX IF NOT EXISTS idx_master_work_intervals_master_date
    ON master_work_intervals (master_id, date)`)
  await query(`
    CREATE TABLE IF NOT EXISTS master_work_months (
      master_id UUID NOT NULL REFERENCES masters(id) ON DELETE CASCADE,
      year INTEGER NOT NULL,
      month INTEGER NOT NULL,
      PRIMARY KEY (master_id, year, month)
    )`)
  workTablesReady = true
}

async function markWorkMonth(masterId, year, month0) {
  await query(
    `INSERT INTO master_work_months (master_id, year, month) VALUES ($1,$2,$3)
     ON CONFLICT (master_id, year, month) DO NOTHING`,
    [masterId, year, month0],
  )
}

async function seedMonthFromWeekly(masterId, year, month0) {
  await ensureWorkTables()
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    const marked = await client.query(
      `INSERT INTO master_work_months (master_id, year, month) VALUES ($1,$2,$3)
       ON CONFLICT (master_id, year, month) DO NOTHING RETURNING 1`,
      [masterId, year, month0],
    )
    if (!marked.rowCount) {
      await client.query('COMMIT')
      return
    }

    const { start, end, last } = monthBounds(year, month0)
    const weekly = await client.query(
      'SELECT day_of_week, start_time, end_time FROM master_schedule WHERE master_id = $1 AND active = true',
      [masterId],
    )
    const offs = await client.query(
      'SELECT date FROM master_days_off WHERE master_id = $1 AND date >= $2 AND date <= $3',
      [masterId, start, end],
    )
    const offSet = new Set(offs.rows.map(d => d.date))
    const byDow = Object.fromEntries(weekly.rows.map(s => [s.day_of_week, s]))

    for (let d = 1; d <= last; d++) {
      const dateStr = `${year}-${pad2(month0 + 1)}-${pad2(d)}`
      if (offSet.has(dateStr)) continue
      const tmpl = byDow[dateDow(dateStr)]
      if (!tmpl) continue
      await client.query(
        `INSERT INTO master_work_intervals (master_id, date, start_time, end_time, sort_order)
         VALUES ($1,$2,$3,$4,0)`,
        [masterId, dateStr, tmpl.start_time, tmpl.end_time],
      )
    }
    await client.query('COMMIT')
  } catch (e) {
    await client.query('ROLLBACK')
    throw e
  } finally {
    client.release()
  }
}

async function loadWorkIntervals(masterIds, date) {
  if (!masterIds.length) return []
  await ensureWorkTables()
  const [y, m] = String(date).slice(0, 7).split('-').map(Number)
  for (const mid of masterIds) await seedMonthFromWeekly(mid, y, m - 1)
  return query(
    'SELECT master_id, date, start_time, end_time FROM master_work_intervals WHERE master_id = ANY($1) AND date = $2 ORDER BY sort_order, start_time',
    [masterIds, date],
  )
}

function asyncHandler(fn) {
  return (req, res, next) => fn(req, res, next).catch(next)
}

// ─── SERVICES ────────────────────────────────────────────────────────────────

function rowToService(r, variants = []) {
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    priceFrom: r.price_from,
    duration: r.duration,
    durationMinutes: r.duration_minutes ?? 60,
    active: r.active,
    sortOrder: r.sort_order ?? 0,
    variants: variants.map(v => ({
      id: v.id,
      name: v.name,
      priceFrom: v.price_from ?? undefined,
      durationMinutes: v.duration_minutes ?? undefined,
    })),
  }
}

async function saveVariants(serviceId, variants) {
  await query('DELETE FROM service_variants WHERE service_id = $1', [serviceId])
  if (!variants?.length) return
  for (let i = 0; i < variants.length; i++) {
    const v = variants[i]
    if (!v.name?.trim()) continue
    await query(
      `INSERT INTO service_variants (service_id, name, price_from, duration_minutes, sort_order)
       VALUES ($1,$2,$3,$4,$5)`,
      [serviceId, v.name.trim(), v.priceFrom ?? null, v.durationMinutes ?? null, i],
    )
  }
}

app.get('/api/services', asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM services WHERE active = true ORDER BY sort_order')
  const variantRows = await query(
    'SELECT * FROM service_variants WHERE service_id = ANY($1) ORDER BY sort_order',
    [rows.map(r => r.id)],
  )
  const byService = {}
  for (const v of variantRows) {
    if (!byService[v.service_id]) byService[v.service_id] = []
    byService[v.service_id].push(v)
  }
  res.json(rows.map(r => rowToService(r, byService[r.id] ?? [])))
}))

app.post('/api/services', ...requirePermission('services'), asyncHandler(async (req, res) => {
  const s = req.body
  const rows = await query(
    `INSERT INTO services (name, description, price_from, duration, duration_minutes, active, sort_order)
     VALUES ($1,$2,$3,$4,$5,true,$6) RETURNING *`,
    [s.name, s.description, s.priceFrom, s.duration, s.durationMinutes ?? 60, s.sortOrder ?? 0],
  )
  const created = rows[0]
  await saveVariants(created.id, s.variants)
  const variantRows = await query('SELECT * FROM service_variants WHERE service_id = $1 ORDER BY sort_order', [created.id])
  res.json(rowToService(created, variantRows))
}))

app.put('/api/services/:id', ...requirePermission('services'), asyncHandler(async (req, res) => {
  const s = req.body
  await query(
    `UPDATE services SET name=$1, description=$2, price_from=$3, duration=$4, duration_minutes=$5 WHERE id=$6`,
    [s.name, s.description, s.priceFrom, s.duration, s.durationMinutes ?? 60, req.params.id],
  )
  await saveVariants(req.params.id, s.variants)
  res.json({ ok: true })
}))

app.delete('/api/services/:id', ...requirePermission('services'), asyncHandler(async (req, res) => {
  await query('UPDATE services SET active = false WHERE id = $1', [req.params.id])
  res.json({ ok: true })
}))

// ─── MASTERS ─────────────────────────────────────────────────────────────────

function rowToMaster(r, serviceIds = [], disabledVariantIds = []) {
  return {
    id: r.id,
    name: r.name,
    role: r.role,
    experience: r.experience,
    photo: r.photo_url,
    services: serviceIds,
    disabledVariantIds,
  }
}

async function saveDisabledVariants(masterId, disabledVariantIds) {
  await query('DELETE FROM master_disabled_variants WHERE master_id = $1', [masterId])
  if (!disabledVariantIds?.length) return
  const values = disabledVariantIds.map((_, i) => `($1, $${i + 2})`).join(',')
  await query(`INSERT INTO master_disabled_variants (master_id, variant_id) VALUES ${values}`, [masterId, ...disabledVariantIds])
}

app.get('/api/masters', asyncHandler(async (req, res) => {
  const masters = await query('SELECT * FROM masters WHERE active = true ORDER BY sort_order')
  const links = await query('SELECT master_id, service_id FROM master_services')
  const disabled = await query('SELECT master_id, variant_id FROM master_disabled_variants')
  const byMaster = {}
  for (const l of links) {
    if (!byMaster[l.master_id]) byMaster[l.master_id] = []
    byMaster[l.master_id].push(l.service_id)
  }
  const disabledByMaster = {}
  for (const d of disabled) {
    if (!disabledByMaster[d.master_id]) disabledByMaster[d.master_id] = []
    disabledByMaster[d.master_id].push(d.variant_id)
  }
  res.json(masters.map(m => rowToMaster(m, byMaster[m.id] ?? [], disabledByMaster[m.id] ?? [])))
}))

app.post('/api/masters', ...requirePermission('masters'), asyncHandler(async (req, res) => {
  const { master: m, serviceIds } = req.body
  const rows = await query(
    `INSERT INTO masters (name, role, experience, photo_url, active) VALUES ($1,$2,$3,$4,true) RETURNING *`,
    [m.name, m.role, m.experience, m.photo],
  )
  const created = rows[0]
  if (serviceIds?.length) {
    const values = serviceIds.map((_, i) => `($1, $${i + 2})`).join(',')
    await query(`INSERT INTO master_services (master_id, service_id) VALUES ${values}`, [created.id, ...serviceIds])
  }
  await saveDisabledVariants(created.id, m.disabledVariantIds)
  res.json(rowToMaster(created, serviceIds ?? [], m.disabledVariantIds ?? []))
}))

app.put('/api/masters/:id', ...requirePermission('masters'), asyncHandler(async (req, res) => {
  const { master: m, serviceIds } = req.body
  const id = req.params.id
  await query(
    `UPDATE masters SET name=$1, role=$2, experience=$3, photo_url=$4 WHERE id=$5`,
    [m.name, m.role, m.experience, m.photo, id],
  )
  await query('DELETE FROM master_services WHERE master_id = $1', [id])
  if (serviceIds?.length) {
    const values = serviceIds.map((_, i) => `($1, $${i + 2})`).join(',')
    await query(`INSERT INTO master_services (master_id, service_id) VALUES ${values}`, [id, ...serviceIds])
  }
  await saveDisabledVariants(id, m.disabledVariantIds)
  res.json({ ok: true })
}))

app.delete('/api/masters/:id', ...requirePermission('masters'), asyncHandler(async (req, res) => {
  await query('UPDATE masters SET active = false WHERE id = $1', [req.params.id])
  res.json({ ok: true })
}))

// ─── SCHEDULE ────────────────────────────────────────────────────────────────

app.get('/api/masters/:id/schedule', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM master_schedule WHERE master_id = $1 ORDER BY day_of_week', [req.params.id])
  res.json(rows.map(r => ({
    dayOfWeek: r.day_of_week,
    startTime: r.start_time.slice(0, 5),
    endTime: r.end_time.slice(0, 5),
    active: r.active,
  })))
}))

app.put('/api/masters/:id/schedule', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const id = req.params.id
  const days = req.body.days ?? []
  await query('DELETE FROM master_schedule WHERE master_id = $1', [id])
  const active = days.filter(d => d.active)
  for (const d of active) {
    await query(
      `INSERT INTO master_schedule (master_id, day_of_week, start_time, end_time, active) VALUES ($1,$2,$3,$4,true)`,
      [id, d.dayOfWeek, d.startTime, d.endTime],
    )
  }
  res.json({ ok: true })
}))

app.get('/api/masters/:id/work-days', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const id = req.params.id
  const year = Number(req.query.year)
  const month0 = Number(req.query.month)
  if (!Number.isInteger(year) || !Number.isInteger(month0) || month0 < 0 || month0 > 11) {
    return res.status(400).json({ error: 'Нужны year и month' })
  }
  await seedMonthFromWeekly(id, year, month0)
  const { start, end } = monthBounds(year, month0)
  const rows = await query(
    `SELECT date, start_time, end_time FROM master_work_intervals
     WHERE master_id = $1 AND date >= $2 AND date <= $3
     ORDER BY date, sort_order, start_time`,
    [id, start, end],
  )
  res.json(groupWorkDays(rows))
}))

app.put('/api/masters/:id/work-days/:date', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const { id, date } = req.params
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Некорректная дата' })
  const intervals = normalizeIntervals(Array.isArray(req.body.intervals) ? req.body.intervals : [])
  if (intervals === null) return res.status(400).json({ error: 'Интервалы пересекаются' })
  await ensureWorkTables()
  const [y, m] = date.split('-').map(Number)
  await markWorkMonth(id, y, m - 1)
  await query('DELETE FROM master_work_intervals WHERE master_id = $1 AND date = $2', [id, date])
  let order = 0
  for (const iv of intervals) {
    await query(
      `INSERT INTO master_work_intervals (master_id, date, start_time, end_time, sort_order)
       VALUES ($1,$2,$3,$4,$5)`,
      [id, date, iv.startTime, iv.endTime, order++],
    )
  }
  const rows = await query(
    `SELECT date, start_time, end_time FROM master_work_intervals WHERE master_id = $1 AND date = $2 ORDER BY sort_order, start_time`,
    [id, date],
  )
  res.json(groupWorkDays(rows)[0] ?? { date, intervals: [] })
}))

// ─── DAYS OFF ────────────────────────────────────────────────────────────────

app.get('/api/masters/:id/days-off', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM master_days_off WHERE master_id = $1 ORDER BY date', [req.params.id])
  res.json(rows.map(r => ({ id: r.id, date: r.date, reason: r.reason })))
}))

app.post('/api/masters/:id/days-off', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const { date, reason = '' } = req.body
  const rows = await query(
    `INSERT INTO master_days_off (master_id, date, reason) VALUES ($1,$2,$3) RETURNING *`,
    [req.params.id, date, reason],
  )
  res.json({ id: rows[0].id, date: rows[0].date, reason: rows[0].reason })
}))

app.delete('/api/days-off/:id', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  await query('DELETE FROM master_days_off WHERE id = $1', [req.params.id])
  res.json({ ok: true })
}))

// ─── SERVICE DAYS ────────────────────────────────────────────────────────────

app.get('/api/masters/:id/service-days', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const rows = await query('SELECT service_id, day_of_week FROM master_service_days WHERE master_id = $1', [req.params.id])
  const result = {}
  for (const r of rows) {
    if (!result[r.service_id]) result[r.service_id] = []
    result[r.service_id].push(r.day_of_week)
  }
  res.json(result)
}))

app.put('/api/masters/:id/service-days/:serviceId', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const { id, serviceId } = req.params
  const days = req.body.days ?? []
  await query('DELETE FROM master_service_days WHERE master_id = $1 AND service_id = $2', [id, serviceId])
  for (const dow of days) {
    await query(
      `INSERT INTO master_service_days (master_id, service_id, day_of_week) VALUES ($1,$2,$3)`,
      [id, serviceId, dow],
    )
  }
  res.json({ ok: true })
}))

// ─── VARIANT DAYS (per-variant day restrictions) ────────────────────────────

app.get('/api/masters/:id/variant-days', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const rows = await query('SELECT variant_id, day_of_week FROM master_variant_days WHERE master_id = $1', [req.params.id])
  const result = {}
  for (const r of rows) {
    if (!result[r.variant_id]) result[r.variant_id] = []
    result[r.variant_id].push(r.day_of_week)
  }
  res.json(result)
}))

app.put('/api/masters/:id/variant-days/:variantId', ...requirePermission('schedule'), asyncHandler(async (req, res) => {
  const { id, variantId } = req.params
  const days = req.body.days ?? []
  await query('DELETE FROM master_variant_days WHERE master_id = $1 AND variant_id = $2', [id, variantId])
  for (const dow of days) {
    await query(
      `INSERT INTO master_variant_days (master_id, variant_id, day_of_week) VALUES ($1,$2,$3)`,
      [id, variantId, dow],
    )
  }
  res.json({ ok: true })
}))

// ─── BOOKINGS ────────────────────────────────────────────────────────────────

function rowToBooking(r) {
  return {
    id: r.id,
    createdAt: r.created_at,
    service: r.service_name,
    serviceId: r.service_id,
    variantName: r.variant_name || null,
    master: r.master_name ?? null,
    masterId: r.master_id ?? null,
    date: r.date,
    time: r.time.slice(0, 5),
    name: r.client_name,
    phone: r.client_phone,
    comment: r.comment,
    status: r.status,
    source: r.source ?? 'website',
  }
}

app.get('/api/bookings', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM bookings ORDER BY created_at DESC')
  res.json(rows.map(rowToBooking))
}))

const VALID_BOOKING_STATUSES = ['new', 'confirmed', 'done', 'cancelled']

/**
 * Picks which specific master will actually take a booking, and makes sure they're
 * really free at that date+time — this is what guarantees a "любой мастер" booking
 * (or a race between two clients) never ends up with nobody actually available.
 *
 * Returns:
 *   - { id, name } of the master to assign
 *   - 'no_candidates' if the service has no masters configured at all (legacy/unassigned booking allowed)
 *   - null if masters exist for the service but none of them is free for this exact slot
 */
async function resolveBookingMaster({ masterId, serviceId, variantId, date, time, durationMin }) {
  const masterIds = masterId
    ? [masterId]
    : (await query(
        `SELECT ms.master_id FROM master_services ms
         JOIN masters m ON m.id = ms.master_id
         WHERE ms.service_id = $1 AND m.active = true`,
        [serviceId],
      )).map(r => r.master_id)
  if (!masterIds.length) return 'no_candidates'

  const startMin = toMinutes(time)
  const endMin = startMin + durationMin
  const dow = dateDow(date)

  const [workRows, existingBookings, serviceDaysRows, variantDaysRows, mastersRows, disabledVariantRows] = await Promise.all([
    loadWorkIntervals(masterIds, date),
    query("SELECT master_id, time, duration_minutes FROM bookings WHERE master_id = ANY($1) AND date = $2 AND status != 'cancelled'", [masterIds, date]),
    query('SELECT master_id, day_of_week FROM master_service_days WHERE master_id = ANY($1) AND service_id = $2', [masterIds, serviceId]),
    variantId
      ? query('SELECT master_id, day_of_week FROM master_variant_days WHERE master_id = ANY($1) AND variant_id = $2', [masterIds, variantId])
      : Promise.resolve([]),
    query('SELECT id, name FROM masters WHERE id = ANY($1)', [masterIds]),
    variantId
      ? query('SELECT master_id FROM master_disabled_variants WHERE master_id = ANY($1) AND variant_id = $2', [masterIds, variantId])
      : Promise.resolve([]),
  ])

  const nameById = Object.fromEntries(mastersRows.map(m => [m.id, m.name]))
  const disabledSet = new Set(disabledVariantRows.map(r => r.master_id))
  const intervalsByMaster = {}
  workRows.forEach(r => {
    if (!intervalsByMaster[r.master_id]) intervalsByMaster[r.master_id] = []
    intervalsByMaster[r.master_id].push(r)
  })
  const serviceDayMap = {}
  serviceDaysRows.forEach(r => {
    if (!serviceDayMap[r.master_id]) serviceDayMap[r.master_id] = new Set()
    serviceDayMap[r.master_id].add(r.day_of_week)
  })
  const variantDayMap = {}
  variantDaysRows.forEach(r => {
    if (!variantDayMap[r.master_id]) variantDayMap[r.master_id] = new Set()
    variantDayMap[r.master_id].add(r.day_of_week)
  })

  for (const mid of masterIds) {
    if (disabledSet.has(mid)) continue
    if (!weekdayAllowed(serviceDayMap[mid], dow)) continue
    if (!weekdayAllowed(variantDayMap[mid], dow)) continue

    const intervals = intervalsByMaster[mid] ?? []
    if (!fitsInIntervals(startMin, endMin, intervals)) continue

    const masterBookings = existingBookings.filter(bk => bk.master_id === mid)
    if (startConflictsWithBookings(startMin, masterBookings)) continue

    return { id: mid, name: nameById[mid] ?? '' }
  }
  return null
}

app.post('/api/bookings', optionalAuth, asyncHandler(async (req, res) => {
  const b = req.body
  // Only a logged-in admin may set an initial status other than "new" (e.g. manually
  // adding an already-confirmed booking from the panel). Public website submissions always start as "new".
  const status = req.adminUser && VALID_BOOKING_STATUSES.includes(b.status) ? b.status : 'new'

  const validServiceId = isUuid(b.serviceId) ? b.serviceId : null
  const validMasterId = isUuid(b.masterId) ? b.masterId : null

  // Look up the real duration (and matching variant id) instead of trusting the client.
  let variantId = null
  let durationMin = 60
  if (validServiceId) {
    const svcRows = await query('SELECT duration_minutes FROM services WHERE id = $1', [validServiceId])
    if (svcRows[0]) durationMin = svcRows[0].duration_minutes ?? 60
    if (b.variantName) {
      const varRows = await query('SELECT id, duration_minutes FROM service_variants WHERE service_id = $1 AND name = $2', [validServiceId, b.variantName])
      if (varRows[0]) {
        variantId = varRows[0].id
        if (varRows[0].duration_minutes) durationMin = varRows[0].duration_minutes
      }
    }
  }

  // Assign (and validate) a real master, so "любой мастер" bookings always pin down
  // someone who is actually free, and explicit picks can't silently double-book a slot.
  let assignedMasterId = validMasterId
  let assignedMasterName = validMasterId ? (b.master || '') : ''
  if (validServiceId && b.date && b.time) {
    const resolved = await resolveBookingMaster({
      masterId: validMasterId,
      serviceId: validServiceId,
      variantId,
      date: b.date,
      time: b.time,
      durationMin,
    })
    if (resolved === 'no_candidates') {
      // No masters configured for this service at all — keep the legacy unassigned booking.
    } else if (!resolved) {
      return res.status(409).json({ error: 'Извините, на выбранное время уже нет свободных мастеров. Пожалуйста, выберите другое время.' })
    } else {
      assignedMasterId = resolved.id
      assignedMasterName = resolved.name
    }
  }

  const rows = await query(
    `INSERT INTO bookings (service_id, service_name, variant_name, master_id, master_name, date, time, duration_minutes, client_name, client_phone, comment, status, source)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [validServiceId, b.service, b.variantName ?? '', assignedMasterId, assignedMasterName, b.date, b.time, durationMin, b.name, b.phone, b.comment ?? '', status, b.source ?? 'website'],
  )
  res.json(rowToBooking(rows[0]))
}))

app.patch('/api/bookings/:id/status', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  await query('UPDATE bookings SET status = $1 WHERE id = $2', [req.body.status, req.params.id])
  res.json({ ok: true })
}))

app.patch('/api/bookings/:id/master', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  const { masterId } = req.body
  if (masterId && !isUuid(masterId)) return res.status(400).json({ error: 'Некорректный мастер' })
  const bookingRows = await query('SELECT date, time, duration_minutes FROM bookings WHERE id = $1', [req.params.id])
  if (!bookingRows[0]) return res.status(404).json({ error: 'Запись не найдена' })
  const { date, time } = bookingRows[0]

  let masterName = ''
  if (masterId) {
    const masterRows = await query('SELECT name FROM masters WHERE id = $1', [masterId])
    if (!masterRows[0]) return res.status(404).json({ error: 'Мастер не найден' })
    masterName = masterRows[0].name

    const startMin = toMinutes(time.slice(0, 5))
    const others = await query(
      `SELECT time, duration_minutes FROM bookings WHERE master_id = $1 AND date = $2 AND id != $3 AND status != 'cancelled'`,
      [masterId, date, req.params.id],
    )
    if (startConflictsWithBookings(startMin, others)) {
      return res.status(409).json({ error: 'У этого мастера уже есть запись на это время.' })
    }
  }

  await query('UPDATE bookings SET master_id = $1, master_name = $2 WHERE id = $3', [masterId || null, masterName, req.params.id])
  res.json({ masterId: masterId || null, masterName })
}))

app.delete('/api/bookings/:id', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  await query('DELETE FROM bookings WHERE id = $1', [req.params.id])
  res.status(204).end()
}))

// ─── CLIENT DIRECTORY ────────────────────────────────────────────────────────

app.get('/api/clients', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  await ensureClientProfiles()
  const [bookings, profiles] = await Promise.all([
    query('SELECT client_name, client_phone, date, time, master_name FROM bookings'),
    query('SELECT phone_digits, notes, birthday::text AS birthday FROM client_profiles'),
  ])
  const profileByPhone = Object.fromEntries(profiles.map(p => [p.phone_digits, p]))
  const byKey = {}
  for (const r of bookings) {
    const digits = phoneDigits(r.client_phone)
    const key = digits || `name:${String(r.client_name).trim().toLowerCase()}`
    const stamp = `${String(r.date).slice(0, 10)}T${String(r.time).slice(0, 5)}`
    const prev = byKey[key]
    if (!prev || stamp > prev.lastStamp) {
      const profile = profileByPhone[digits] || {}
      byKey[key] = {
        phoneDigits: digits,
        name: String(r.client_name ?? '').trim(),
        phone: String(r.client_phone ?? '').trim(),
        lastDate: String(r.date).slice(0, 10),
        lastTime: String(r.time).slice(0, 5),
        lastStamp: stamp,
        master: r.master_name || '',
        notes: profile.notes ?? '',
        birthday: isoDateOnly(profile.birthday),
      }
    }
  }
  const list = Object.values(byKey)
    .map(({ lastStamp, ...rest }) => rest)
    .sort((a, b) => a.name.localeCompare(b.name, 'ru', { sensitivity: 'base' }))
  res.json(list)
}))

app.put('/api/clients/notes', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  await ensureClientProfiles()
  const digits = phoneDigits(req.body.phoneDigits ?? req.body.phone)
  if (!digits) return res.status(400).json({ error: 'Нужен телефон клиента' })
  const notes = String(req.body.notes ?? '')
  await query(
    `INSERT INTO client_profiles (phone_digits, notes, updated_at) VALUES ($1,$2,now())
     ON CONFLICT (phone_digits) DO UPDATE SET notes = $2, updated_at = now()`,
    [digits, notes],
  )
  res.json({ ok: true, phoneDigits: digits, notes })
}))

app.put('/api/clients/birthday', ...requirePermission('bookings'), asyncHandler(async (req, res) => {
  await ensureClientProfiles()
  const digits = phoneDigits(req.body.phoneDigits ?? req.body.phone)
  if (!digits) return res.status(400).json({ error: 'Нужен телефон клиента' })
  const birthday = isoDateOnly(req.body.birthday) || null
  await query(
    `INSERT INTO client_profiles (phone_digits, notes, birthday, updated_at) VALUES ($1,'',$2,now())
     ON CONFLICT (phone_digits) DO UPDATE SET birthday = $2, updated_at = now()`,
    [digits, birthday],
  )
  res.json({ ok: true, phoneDigits: digits, birthday: birthday ?? '' })
}))

// ─── MASTER PERSONAL CABINET (self-service, scoped to the caller's own master_id) ──

app.get('/api/my/bookings', ...requireMaster, asyncHandler(async (req, res) => {
  const rows = await query(
    'SELECT * FROM bookings WHERE master_id = $1 ORDER BY date DESC, time DESC',
    [req.adminUser.master_id],
  )
  res.json(rows.map(r => ({ ...rowToBooking(r), phone: maskPhone(r.client_phone) })))
}))

app.get('/api/my/work-days', ...requireMaster, asyncHandler(async (req, res) => {
  const id = req.adminUser.master_id
  const year = Number(req.query.year)
  const month0 = Number(req.query.month)
  if (!Number.isInteger(year) || !Number.isInteger(month0) || month0 < 0 || month0 > 11) {
    return res.status(400).json({ error: 'Нужны year и month' })
  }
  await seedMonthFromWeekly(id, year, month0)
  const { start, end } = monthBounds(year, month0)
  const rows = await query(
    `SELECT date, start_time, end_time FROM master_work_intervals
     WHERE master_id = $1 AND date >= $2 AND date <= $3
     ORDER BY date, sort_order, start_time`,
    [id, start, end],
  )
  res.json(groupWorkDays(rows))
}))

app.get('/api/my/schedule', ...requireMaster, asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM master_schedule WHERE master_id = $1 ORDER BY day_of_week', [req.adminUser.master_id])
  res.json(rows.map(r => ({
    dayOfWeek: r.day_of_week,
    startTime: r.start_time.slice(0, 5),
    endTime: r.end_time.slice(0, 5),
    active: r.active,
  })))
}))

app.get('/api/my/days-off', ...requireMaster, asyncHandler(async (req, res) => {
  const rows = await query(
    'SELECT * FROM master_days_off WHERE master_id = $1 AND date >= CURRENT_DATE ORDER BY date',
    [req.adminUser.master_id],
  )
  res.json(rows.map(r => ({ id: r.id, date: r.date, reason: r.reason })))
}))

// ─── CONTENT ─────────────────────────────────────────────────────────────────

app.get('/api/content', asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM site_content')
  const map = {}
  rows.forEach(r => { map[r.key] = r.value })
  res.json(map)
}))

app.put('/api/content', ...requirePermission('content', 'notifications'), asyncHandler(async (req, res) => {
  const c = req.body
  for (const [key, value] of Object.entries(c)) {
    await query(
      `INSERT INTO site_content (key, value, updated_at) VALUES ($1,$2,NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [key, value ?? ''],
    )
  }
  res.json({ ok: true })
}))

// ─── VACANCIES ───────────────────────────────────────────────────────────────

function rowToVacancy(r) {
  return { id: r.id, title: r.title, description: r.description, requirements: r.requirements }
}

app.get('/api/vacancies', asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM vacancies WHERE active = true ORDER BY sort_order')
  res.json(rows.map(rowToVacancy))
}))

app.post('/api/vacancies', ...requirePermission('vacancies'), asyncHandler(async (req, res) => {
  const v = req.body
  const rows = await query(
    `INSERT INTO vacancies (title, description, requirements, active, sort_order) VALUES ($1,$2,$3,true,0) RETURNING *`,
    [v.title, v.description, v.requirements],
  )
  res.json(rowToVacancy(rows[0]))
}))

app.put('/api/vacancies/:id', ...requirePermission('vacancies'), asyncHandler(async (req, res) => {
  const v = req.body
  await query('UPDATE vacancies SET title=$1, description=$2, requirements=$3 WHERE id=$4', [v.title, v.description, v.requirements, req.params.id])
  res.json({ ok: true })
}))

app.delete('/api/vacancies/:id', ...requirePermission('vacancies'), asyncHandler(async (req, res) => {
  await query('UPDATE vacancies SET active = false WHERE id = $1', [req.params.id])
  res.json({ ok: true })
}))

// ─── TESTIMONIALS ────────────────────────────────────────────────────────────

function rowToTestimonial(r) {
  return { id: r.id, name: r.name, role: r.role, text: r.text }
}

app.get('/api/testimonials', asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM testimonials WHERE active = true ORDER BY sort_order')
  res.json(rows.map(rowToTestimonial))
}))

app.post('/api/testimonials', ...requirePermission('testimonials'), asyncHandler(async (req, res) => {
  const t = req.body
  const rows = await query(
    `INSERT INTO testimonials (name, role, text, active, sort_order) VALUES ($1,$2,$3,true,0) RETURNING *`,
    [t.name, t.role, t.text],
  )
  res.json(rowToTestimonial(rows[0]))
}))

app.put('/api/testimonials/:id', ...requirePermission('testimonials'), asyncHandler(async (req, res) => {
  const t = req.body
  await query('UPDATE testimonials SET name=$1, role=$2, text=$3 WHERE id=$4', [t.name, t.role, t.text, req.params.id])
  res.json({ ok: true })
}))

app.delete('/api/testimonials/:id', ...requirePermission('testimonials'), asyncHandler(async (req, res) => {
  await query('UPDATE testimonials SET active = false WHERE id = $1', [req.params.id])
  res.json({ ok: true })
}))

// ─── AVAILABILITY ─────────────────────────────────────────────────────────────

async function resolveMasterIds(masterId, serviceId) {
  if (masterId) return [masterId]
  const rows = await query(
    `SELECT ms.master_id FROM master_services ms
     JOIN masters m ON m.id = ms.master_id
     WHERE ms.service_id = $1 AND m.active = true`,
    [serviceId],
  )
  return rows.map(r => r.master_id)
}

app.get('/api/availability/days', asyncHandler(async (req, res) => {
  const { masterId, serviceId, variantId, year, month } = req.query
  const y = Number(year), mo = Number(month)
  if (!isUuid(serviceId) || (masterId && !isUuid(masterId)) || (variantId && !isUuid(variantId))) return res.json([])
  const masterIds = await resolveMasterIds(masterId || null, serviceId)
  if (!masterIds.length) return res.json([])

  await ensureWorkTables()
  for (const mid of masterIds) await seedMonthFromWeekly(mid, y, mo)
  const { start, end } = monthBounds(y, mo)

  const [workRows, serviceDaysRows, variantDaysRows] = await Promise.all([
    query(
      `SELECT master_id, date FROM master_work_intervals
       WHERE master_id = ANY($1) AND date >= $2 AND date <= $3`,
      [masterIds, start, end],
    ),
    query('SELECT master_id, day_of_week FROM master_service_days WHERE master_id = ANY($1) AND service_id = $2', [masterIds, serviceId]),
    variantId
      ? query('SELECT master_id, day_of_week FROM master_variant_days WHERE master_id = ANY($1) AND variant_id = $2', [masterIds, variantId])
      : Promise.resolve([]),
  ])

  const workDates = {}
  workRows.forEach(r => {
    if (!workDates[r.master_id]) workDates[r.master_id] = new Set()
    workDates[r.master_id].add(r.date)
  })
  const serviceDayMap = {}
  serviceDaysRows.forEach(r => {
    if (!serviceDayMap[r.master_id]) serviceDayMap[r.master_id] = new Set()
    serviceDayMap[r.master_id].add(r.day_of_week)
  })
  const variantDayMap = {}
  variantDaysRows.forEach(r => {
    if (!variantDayMap[r.master_id]) variantDayMap[r.master_id] = new Set()
    variantDayMap[r.master_id].add(r.day_of_week)
  })

  const today = new Date(); today.setHours(0, 0, 0, 0)
  const daysInMonth = new Date(y, mo + 1, 0).getDate()
  const result = []

  for (let d = 1; d <= daysInMonth; d++) {
    const date = new Date(y, mo, d)
    if (date < today) continue
    const dow = date.getDay() === 0 ? 6 : date.getDay() - 1
    const dateStr = `${y}-${pad2(mo + 1)}-${pad2(d)}`

    const anyAvail = masterIds.some(mid => {
      if (!(workDates[mid]?.has(dateStr))) return false
      if (!weekdayAllowed(serviceDayMap[mid], dow)) return false
      if (!weekdayAllowed(variantDayMap[mid], dow)) return false
      return true
    })
    if (anyAvail) result.push(d)
  }
  res.json(result)
}))

app.get('/api/availability/slots', asyncHandler(async (req, res) => {
  const { masterId, serviceId, variantId, date, durationMinutes } = req.query
  if (!isUuid(serviceId) || (masterId && !isUuid(masterId)) || (variantId && !isUuid(variantId))) return res.json([])
  const durationMin = Number(durationMinutes) || 60
  const masterIds = await resolveMasterIds(masterId || null, serviceId)
  if (!masterIds.length) return res.json([])
  const dow = dateDow(date)

  const [workRows, existingBookings, serviceDaysRows, variantDaysRows, disabledVariantRows] = await Promise.all([
    loadWorkIntervals(masterIds, date),
    query("SELECT master_id, time, duration_minutes FROM bookings WHERE master_id = ANY($1) AND date = $2 AND status != 'cancelled'", [masterIds, date]),
    query('SELECT master_id, day_of_week FROM master_service_days WHERE master_id = ANY($1) AND service_id = $2', [masterIds, serviceId]),
    variantId
      ? query('SELECT master_id, day_of_week FROM master_variant_days WHERE master_id = ANY($1) AND variant_id = $2', [masterIds, variantId])
      : Promise.resolve([]),
    variantId
      ? query('SELECT master_id FROM master_disabled_variants WHERE master_id = ANY($1) AND variant_id = $2', [masterIds, variantId])
      : Promise.resolve([]),
  ])

  const serviceDayMap = {}
  serviceDaysRows.forEach(r => {
    if (!serviceDayMap[r.master_id]) serviceDayMap[r.master_id] = new Set()
    serviceDayMap[r.master_id].add(r.day_of_week)
  })
  const variantDayMap = {}
  variantDaysRows.forEach(r => {
    if (!variantDayMap[r.master_id]) variantDayMap[r.master_id] = new Set()
    variantDayMap[r.master_id].add(r.day_of_week)
  })
  const disabledSet = new Set(disabledVariantRows.map(r => r.master_id))
  const allowedMasters = masterIds.filter(mid => {
    if (disabledSet.has(mid)) return false
    if (!weekdayAllowed(serviceDayMap[mid], dow)) return false
    if (!weekdayAllowed(variantDayMap[mid], dow)) return false
    return true
  })

  const slotMap = {}
  for (const mid of allowedMasters) {
    const intervals = workRows.filter(r => r.master_id === mid)
    const masterBookings = existingBookings.filter(b => b.master_id === mid)
    for (const iv of intervals) {
      const startMin = toMinutes(iv.start_time)
      const endMin = toMinutes(iv.end_time)
      for (let t = startMin; t + durationMin <= endMin; t += 30) {
        const slotKey = minutesToTime(t)
        if (slotMap[slotKey] === true) continue
        const blocked = startConflictsWithBookings(t, masterBookings)
        if (!blocked) slotMap[slotKey] = true
        else if (slotMap[slotKey] === undefined) slotMap[slotKey] = false
      }
    }
  }

  const result = Object.entries(slotMap)
    .sort(([a], [b]) => toMinutes(a) - toMinutes(b))
    .map(([time, available]) => ({ time, available }))
  res.json(result)
}))

// ─── HEALTH ──────────────────────────────────────────────────────────────────

app.get('/api/health', asyncHandler(async (req, res) => {
  await query('SELECT 1')
  res.json({ ok: true })
}))

app.use((err, req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: err.message ?? String(err) })
})

app.listen(PORT, () => {
  console.log(`API server listening on http://localhost:${PORT}`)
})

process.on('SIGTERM', () => pool.end())
