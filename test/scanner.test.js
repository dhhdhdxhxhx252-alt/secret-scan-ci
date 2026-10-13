import test from 'node:test'
import assert from 'node:assert/strict'
import { scanText, scanPathName } from '../src/scanner.js'

function jwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = Buffer.from('signature-bytes-not-a-secret').toString('base64url')
  return `${header}.${body}.${sig}`
}

test('service_role ключ Supabase — критично', () => {
  const secret = `sb_secret_${'Ab3x'.repeat(8)}`
  const hits = scanText(`const k = "${secret}"`, { file: 'a.js' })
  const hit = hits.find((h) => h.rule === 'supabase-service-key')
  assert.ok(hit, 'должен найти sb_secret')
  assert.equal(hit.severity, 'critical')
})

test('anon-ключ не помечается критическим', () => {
  const hits = scanText(`const key = '${jwt({ role: 'anon', iss: 'supabase' })}'`, { file: 'a.js' })
  const hit = hits.find((h) => h.rule === 'jwt')
  assert.ok(hit)
  assert.equal(hit.severity, 'medium')
  assert.match(hit.title, /anon/)
})

test('service_role в JWT — критично', () => {
  const hits = scanText(`const token = '${jwt({ role: 'service_role' })}'`, { file: 'a.js' })
  const hit = hits.find((h) => h.rule === 'jwt')
  assert.equal(hit.severity, 'critical')
})

test('PEM закрытого ключа находится', () => {
  const hits = scanText('-----BEGIN PRIVATE KEY-----\nMIIEvQ==', { file: 'id.pem' }) // secret-scan:allow
  assert.ok(hits.some((h) => h.rule === 'private-key' && h.severity === 'critical'))
})

const CRED_RULES = new Set(['credential-assignment', 'env-assignment'])
const creds = (hits) => hits.filter((h) => CRED_RULES.has(h.rule))

test('заглушки не считаются секретами', () => {
  const lines = ['API_KEY=changeme', 'password = "your-key-here"', 'secret: "xxxxxxxxxx"', 'token=<from env>', 'MY_TOKEN=your_token_here']
  for (const line of lines) {
    const hits = creds(scanText(line, { file: 'config.js' }))
    assert.equal(hits.length, 0, `не должен флаговать: ${line}`)
  }
})

test('реальный ключ в присвоении находится', () => {
  const hits = creds(scanText('const apiKey = "Zx9Kq7Lm2Wp4Rt8Yu6Ia0Sd3Fg7Hb1Nc"', { file: 'src/client.js' })) // secret-scan:allow
  assert.equal(hits.length, 1)
  assert.equal(hits[0].severity, 'high')
  assert.equal(hits[0].length, 32)
})

test('строка формата .env находится', () => {
  const hits = creds(scanText('SUPABASE_SECRET_KEY=s3cretValue9xQ7Lm2Wp4Rt', { file: '.env.local' }))
  assert.equal(hits.length, 1)
  assert.equal(hits[0].rule, 'env-assignment')
})

test('код в minified бандле не считается секретом', () => {
  const line = 'e.weak_password.reasons.reduce((a,t)=>a&&typeof t==`string`,!0)&&(t.data.weak_password.length>8)'
  assert.equal(creds(scanText(line, { file: 'assets/index-abc.js' })).length, 0)
})

test('путь к кейстору и .env ловятся по имени файла', () => {
  assert.equal(scanPathName('keystore/release.jks')[0].rule, 'keystore-file')
  assert.equal(scanPathName('.env')[0].rule, 'env-file')
  assert.equal(scanPathName('config/.env.example').length, 0)
})

test('служебные адреса почты игнорируются', () => {
  assert.equal(scanText('from: noreply@acme.dev', { file: 'a.txt' }).filter((h) => h.rule === 'pii-email').length, 0)
  assert.equal(scanText('owner = "someone@gmail.com"', { file: 'a.txt' }).filter((h) => h.rule === 'pii-email').length, 1) // secret-scan:allow
})

test('маркер secret-scan:allow глушит строку', () => {  const hits = scanText('const apiKey = "Zx9Kq7Lm2Wp4Rt8Yu6Ia0Sd3Fg7Hb1Nc"', { file: 'fixture.js' }) // secret-scan:allow
  assert.equal(hits.length, 1)
  const allowed = scanText('const apiKey = "Zx9Kq7Lm2Wp4Rt8Yu6Ia0Sd3Fg7Hb1Nc" // secret-scan:allow', { file: 'fixture.js' })
  assert.equal(allowed.length, 0)
})

test('у почты нет отпечатка: её можно подобрать по хешу', () => {
  const hit = scanText('owner = "someone@corp.io"', { file: 'a.txt' }).find((h) => h.rule === 'pii-email') // secret-scan:allow
  assert.equal(hit.hash, '')
  assert.equal(hit.length, 0)
  assert.ok(hit.line > 0)
})

test('значение секрета никогда не попадает в вывод', () => {
  const secret = `sb_secret_${'Tr9zQ2'.repeat(6)}`
  const hits = scanText(`const k = "${secret}"`, { file: 'leak.js' })
  const serialized = JSON.stringify(hits)
  assert.ok(!serialized.includes(secret), 'хеш-отчёт не должен содержать сам ключ')
  assert.ok(serialized.includes(hits[0].hash))
})
