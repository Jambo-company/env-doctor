import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const ts = require('typescript')
const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function loadTsModule(relativePath) {
  const fullPath = path.join(rootDir, relativePath)
  const source = fs.readFileSync(fullPath, 'utf8')
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
      esModuleInterop: true,
    },
  })
  const mod = { exports: {} }
  const fn = new Function('module', 'exports', 'require', '__filename', '__dirname', outputText)
  fn(mod, mod.exports, require, fullPath, path.dirname(fullPath))
  return mod.exports
}

test('AWS Secret Access Key pattern requires AWS/secret context and skips bare 40-char hashes', () => {
  const { SECRET_PATTERNS } = loadTsModule('src/patterns.ts')
  const awsPattern = SECRET_PATTERNS.find((p) => p.name === 'AWS Secret Access Key')
  assert.ok(awsPattern)

  awsPattern.regex.lastIndex = 0
  const commitLine = 'const gitSha = "607dd14c3a1b2c3d4e5f60718293a4b5c6d7e8f9";'
  assert.equal(awsPattern.regex.exec(commitLine), null)

  awsPattern.regex.lastIndex = 0
  const validLine = 'const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";'
  const matched = awsPattern.regex.exec(validLine)
  assert.ok(matched)
  assert.equal(matched[1], 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
})

test('applySafeSecretExtraction validates identifiers, targets only matched line, and avoids $& expansion', () => {
  const { applySafeSecretExtraction, formatDotenvLine, isValidEnvVarName } = loadTsModule('src/remediation.ts')

  assert.equal(isValidEnvVarName('VALID_SECRET_1'), true)
  assert.equal(isValidEnvVarName('1BAD'), false)
  assert.equal(isValidEnvVarName('BAD;NAME'), false)

  const src = [
    '// secret "abc$&12345" comment',
    'const key = "abc$&12345";',
    'const other = "abc$&12345";',
  ].join('\n')

  const updated = applySafeSecretExtraction(src, 2, 'abc$&12345', 'MY_API_KEY')
  assert.equal(
    updated,
    [
      '// secret "abc$&12345" comment',
      'const key = process.env.MY_API_KEY;',
      'const other = "abc$&12345";',
    ].join('\n'),
  )

  assert.throws(() => applySafeSecretExtraction(src, 2, 'abc$&12345', 'bad-name'), /Invalid environment variable/)
  assert.throws(() => applySafeSecretExtraction('const x = abc;', 1, 'abc', 'MY_KEY'), /not quoted/)

  assert.equal(formatDotenvLine('MY_KEY', 'a"b\\c\nd'), '\nMY_KEY="a\\"b\\\\c\\nd"\n')
})

test('CLI source uses execFileSync arrays instead of shell-interpolated execSync', () => {
  const cliSource = fs.readFileSync(path.join(rootDir, 'src/index.ts'), 'utf8')
  assert.match(cliSource, /execFileSync/)
  assert.doesNotMatch(cliSource, /\bexecSync\b/)
  assert.equal(typeof os.tmpdir(), 'string')
})
