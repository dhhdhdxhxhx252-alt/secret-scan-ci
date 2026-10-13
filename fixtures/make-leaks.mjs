// Генерирует fixtures/leaks/ — выдуманные «утечки» для проверки правил.
// Каталог не коммитится: если держать целые токены в репозитории, GitHub Secret Scanning
// видит их в дереве и блокирует пуш. Здесь значения собираются из частей.
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const out = join(dirname(fileURLToPath(import.meta.url)), 'leaks')
mkdirSync(out, { recursive: true })

const cat = (...pieces) => pieces.join('')

const githubToken = cat('gh', 'p', '_') + cat('A1b2', 'C3d4', 'E5f6', 'G7h8', 'I9j0', 'K1l2', 'M3n4', 'O6p8')
const awsKey = cat('AKI', 'A') + cat('FAKE', 'KEYT', 'EST1', '234A')
const supabaseKey = cat('sb', '_', 'secret', '_') + cat('F1k3', 'N3Vm', '1nV4', 'lUeF', '0rT3', 's7T9')
const pemHead = cat('-----BEGIN ', 'RSA PRIVATE KEY', '-----')
const pemTail = cat('-----END ', 'RSA PRIVATE KEY', '-----')
const jwtHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
const jwtBody = Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url')
const bearer = `${jwtHeader}.${jwtBody}.${cat('aB3c', 'D4eF', 'G5hI', 'J6kL')}`

writeFileSync(
  join(out, 'leaky-config.js'),
  [
    'export const leaked = {',
    `  github: '${githubToken}',`,
    `  aws: '${awsKey}',`,
    `  supabase: '${supabaseKey}',`,
    '}',
    `const authorization = "Bearer ${bearer}"`,
    '',
  ].join('\n')
)

writeFileSync(
  join(out, 'leaky.pem'),
  [
    pemHead,
    'bXlGYWtlS2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYmNkZWY=',
    'ZmFrZW1hdGVyaWFsZm9ydGVzdHNvbmx5MDAyMjMzNDQ1NQ==',
    pemTail,
    '',
  ].join('\n')
)

writeFileSync(
  join(out, 'prod.env'),
  [
    `DEPLOY_ACCESS_TOKEN=${cat('R7nQ2x', 'W5vB8m', 'K3jL6h', 'G9fD1s')}`,
    `NOTIFY_SECRET=${cat('Z3yX6w', 'V9uT2r', 'Q5pM8k', 'N1bV4c')}`,
    '',
  ].join('\n')
)

writeFileSync(join(out, 'release.keystore'), 'not-a-real-keystore-for-tests-only\n')
writeFileSync(join(out, 'id_ed25519'), 'fake ssh key material for tests only\n')

console.log(`fixtures/leaks/ готов: ${out}`)
