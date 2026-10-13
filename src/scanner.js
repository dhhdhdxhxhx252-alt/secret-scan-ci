import { createHash } from 'node:crypto'

export const SEVERITIES = ['note', 'medium', 'high', 'critical']

// Значения никогда не возвращаются наружу: только класс, позиция, длина и хеш.
const PLACEHOLDER = /^(changeme|change_me|your[_-]?|xxx+|dummy|sample|example|placeholder|test|none|null|undefined|todo|n\/a|<.*>|\$\{.*\}|%s|\*\*\*)$/i

function isPlaceholder(value) {
  if (PLACEHOLDER.test(value)) return true
  // "your-key-here", "my_token" и подобные — текст из туториала, а не секрет.
  if (/^(?:your|my|the|some|fake|real|new|old)[_-]/i.test(value)) return true
  // Повтор одного символа или слишком однотонный набор — это не секрет.
  const unique = new Set(value.replace(/[^A-Za-z0-9]/g, '')).size
  return unique <= 3
}

function shannonEntropy(value) {
  const chars = {}
  for (const c of value) chars[c] = (chars[c] || 0) + 1
  const total = value.length
  let entropy = 0
  for (const c in chars) {
    const p = chars[c] / total
    entropy -= p * Math.log2(p)
  }
  return entropy
}

function decodeJwtRole(token) {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    return payload.role ?? null
  } catch {
    return null
  }
}

function fingerprint(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 12)
}

const GENERIC_RULES = new Set(['credential-assignment', 'env-assignment'])

function skipCredential(value) {
  if (isPlaceholder(value)) return true
  // `{location.pathname}`, `=>`, массив или вызов функции — это код, а не ключ.
  if (/^[{([~]/.test(value) || value.includes('=>') || value.includes('${')) return true
  return value.length < 8 || entropyOf(value) < 3.2
}

const RULES = [
  {
    id: 'private-key',
    severity: 'critical',
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/,
    title: 'pem private key',
  },
  {
    id: 'supabase-service-key',
    severity: 'critical',
    pattern: /\bsb_secret_[A-Za-z0-9_\-]{20,}/,
    title: 'supabase service_role key',
  },
  {
    id: 'github-token',
    severity: 'critical',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/,
    title: 'github token',
  },
  {
    id: 'aws-access-key',
    severity: 'critical',
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    title: 'aws access key id',
  },
  {
    id: 'slack-token',
    severity: 'critical',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
    title: 'slack token',
  },
  {
    id: 'jwt',
    severity: 'critical',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
    title: (value) => {
      const role = decodeJwtRole(value)
      if (role === 'service_role') return 'jwt with service_role claims'
      if (role === 'anon') return 'supabase anon key (public by design)'
      return `jwt${role ? ` with role ${role}` : ''}`
    },
    // anon-ключ публикуется в клиенте намеренно — не критично.
    downgrade: (value) => {
      const role = decodeJwtRole(value)
      if (role === 'anon') return 'medium'
      if (role === 'authenticated') return 'medium'
      return null
    },
  },
  {
    id: 'supabase-project-ref',
    severity: 'note',
    pattern: /\bhttps:\/\/[a-z0-9]{15,25}\.supabase\.co\b/i,
    title: 'supabase project url',
  },
  {
    id: 'credential-assignment',
    severity: 'high',
    // Присваивание в кавычках. Без кавычек minified JS даёт ложные срабатывания на фрагментах кода.
    pattern:
      /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|client[_-]?secret|pass(?:word|wd)?|private[_-]?key)\s*[:=]\s*(["'`])([^"'`\s]{8,})\1/i,
    capture: 2,
    title: 'hard-coded credential',
    skip: skipCredential,
  },
  {
    id: 'env-assignment',
    severity: 'high',
    // Формат .env: FOO_API_KEY=..., без кавычек и пробелов вокруг знака равенства.
    pattern:
      /^\s*(?:export\s+)?[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASS(?:WORD|WD)?|CREDENTIAL|AUTH)[A-Za-z0-9_]*\s*=\s*(\S{8,})\s*$/i,
    capture: 1,
    title: 'credential in env-style line',
    skip: skipCredential,
  },
  {
    id: 'pii-email',
    severity: 'medium',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
    title: 'e-mail address in source',
    // Email — низкая энтропия: по хешу его можно подобрать, поэтому отпечатка нет.
    noFingerprint: true,
    skip: (value) => /^(noreply|no-reply|example|root|postmaster|abuse)@/i.test(value) || /@(?:example|domain|yourdomain)\.(com|org|net)$/i.test(value),
  },
]

function entropyOf(value) {
  return shannonEntropy(value)
}

export function scanText(text, { file, maxLineLength = 20000 } = {}) {
  const findings = []
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]
    if (line.length > maxLineLength) continue
    // Строка с маркером не проверяется: тесты и фикстуры сами содержат выдуманные ключи.
    if (line.includes('secret-scan:allow')) continue
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0
      const match = rule.pattern.exec(line)
      if (!match) continue
      const value = rule.capture ? match[rule.capture] : match[0]
      if (!value) continue
      if (rule.skip && rule.skip(value)) continue
      const severity = (rule.downgrade && rule.downgrade(value)) || rule.severity
      findings.push({
        rule: rule.id,
        severity,
        title: typeof rule.title === 'function' ? rule.title(value) : rule.title,
        file,
        line: i + 1,
        length: rule.noFingerprint ? 0 : value.length,
        hash: rule.noFingerprint ? '' : fingerprint(value),
      })
    }
  }
  return dedupe(findings)
}

// Одно и то же значение может попасть под узкое правило (jwt) и под общее (env-assignment).
// Узкие правила идут в RULES первыми, поэтому оставляем первое, а общее вытесняем, если оно оказалось раньше.
function dedupe(findings) {
  const byKey = new Map()
  const out = []
  for (const f of findings) {
    if (!f.hash) {
      out.push(f)
      continue
    }
    const key = `${f.file}:${f.line}:${f.hash}`
    const prev = byKey.get(key)
    if (!prev) {
      byKey.set(key, f)
      out.push(f)
    } else if (GENERIC_RULES.has(prev.rule) && !GENERIC_RULES.has(f.rule)) {
      out[out.indexOf(prev)] = f
      byKey.set(key, f)
    }
  }
  return out
}

const ARTIFACT_RULES = [
  { id: 'keystore-file', severity: 'critical', title: 'signing keystore', test: (p) => /\.(jks|keystore|p12|pfx)$/i.test(p) },
  { id: 'env-file', severity: 'high', title: '.env file in the tree', test: (p) => /(^|[\\/])\.env(\.[A-Za-z0-9_-]+)?$/i.test(p) && !/\.env\.example$/i.test(p) },
  { id: 'ssh-key-file', severity: 'critical', title: 'ssh private key file', test: (p) => /[\\/]id_(?:rsa|ecdsa|ed25519|dsa)$/i.test(p) },
]

export function scanPathName(path) {
  for (const rule of ARTIFACT_RULES) {
    if (rule.test(path)) {
      return [{ rule: rule.id, severity: rule.severity, title: rule.title, file: path, line: 0, length: 0, hash: '' }]
    }
  }
  return []
}

export const DEFAULT_IGNORES = [
  /(^|[\\/])\.git([\\/]|$)/,
  /(^|[\\/])node_modules([\\/]|$)/,
  /(^|[\\/])\.venv([\\/]|$)/,
  /(^|[\\/])__pycache__([\\/]|$)/,
  /(^|[\\/])\.gradle([\\/]|$)/,
  // В лок-файлах email автора и url с токеном — штатный шум, не утечка.
  /(?:^|[\\/])(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock)$/i,
]
