#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { join, relative } from 'node:path'
import { scanText, scanPathName, DEFAULT_IGNORES, SEVERITIES } from './scanner.js'

const USAGE = `secret-scan — сканер дерева и сборки на утечки ключей (значения не печатаются)

usage: secret-scan [path...] [options]

  --json               вывод списком объектов
  --fail-on <level>    минимальная серьёзность для кода 1 (по умолчанию high)
  --ignore <pattern>   дополнительный regex для исключения путей (повторяемо)
  --max-size <bytes>   пропускать файлы больше этого размера (по умолчанию 8388608)
  --help               эта справка
`

function parseArgs(argv) {
  const paths = []
  const ignores = []
  const options = { json: false, failOn: 'high', maxSize: 8 * 1024 * 1024, help: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--json') options.json = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else if (arg === '--fail-on') options.failOn = argv[++i] ?? options.failOn
    else if (arg === '--ignore') ignores.push(new RegExp(argv[++i] ?? '', 'i'))
    else if (arg === '--max-size') options.maxSize = Number(argv[++i]) || options.maxSize
    else if (arg.startsWith('-')) throw new Error(`неизвестный флаг: ${arg}`)
    else paths.push(arg)
  }
  return { paths: paths.length ? paths : ['.'], ignores, options }
}

function* walk(root, ignores) {
  let entries
  try {
    entries = readdirSync(root, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const full = join(root, entry.name)
    const normalized = full.replace(/\\/g, '/')
    if (ignores.some((re) => re.test(normalized))) continue
    if (entry.isSymbolicLink()) continue
    if (entry.isDirectory()) {
      yield* walk(full, ignores)
    } else if (entry.isFile()) {
      yield normalized
    }
  }
}

function readText(file, maxSize) {
  try {
    const size = statSync(file).size
    if (size > maxSize) return null
    const buffer = readFileSync(file)
    // Бинарный файл: NUL в первых 8 КБ — не читаем как текст.
    if (buffer.subarray(0, 8192).includes(0)) return null
    return buffer.toString('utf8')
  } catch {
    return null
  }
}

export function run(argv) {
  let parsed
  try {
    parsed = parseArgs(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${USAGE}`)
    return { code: 2 }
  }
  const { paths, ignores, options } = parsed
  if (options.help) {
    process.stdout.write(USAGE)
    return { code: 0 }
  }

  const extraIgnores = [...DEFAULT_IGNORES, ...ignores]
  const findings = []
  let scanned = 0
  for (const root of paths) {
    for (const file of walk(root, extraIgnores)) {
      const artifact = scanPathName(file)
      if (artifact.length) {
        findings.push(...artifact.map((f) => ({ ...f, file: relative('.', file).replace(/\\/g, '/') })))
      }
      const text = readText(file, options.maxSize)
      if (text === null) continue
      scanned += 1
      const hits = scanText(text, { file: relative('.', file).replace(/\\/g, '/') })
      findings.push(...hits)
    }
  }

  const rank = (severity) => SEVERITIES.indexOf(severity)
  const blocking = findings.filter((f) => rank(f.severity) >= rank(options.failOn))

  if (options.json) {
    process.stdout.write(`${JSON.stringify({ scanned, findings, blocking: blocking.length }, null, 2)}\n`)
  } else if (!findings.length) {
    process.stdout.write(`проверено файлов: ${scanned} — ничего похожего на секреты не найдено\n`)
  } else {
    const order = { critical: 0, high: 1, medium: 2, note: 3 }
    for (const f of [...findings].sort((a, b) => (order[a.severity] - order[b.severity]) || a.file.localeCompare(b.file))) {
      const where = f.line ? `${f.file}:${f.line}` : f.file
      const shape = f.length ? `, длина ${f.length}, sha256/${f.hash}` : ''
      process.stdout.write(`${f.severity.toUpperCase().padEnd(8)} ${where}  ${f.rule}  (${f.title}${shape})\n`)
    }
    const counts = findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1
      return acc
    }, {})
    process.stdout.write(
      `\nпроверено файлов: ${scanned}  |  находок: ${findings.length}  (${Object.entries(counts)
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ')})\n`
    )
  }
  return { code: blocking.length ? 1 : 0, findings, scanned }
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url

if (isMain) {
  process.exitCode = run(process.argv.slice(2)).code
}
