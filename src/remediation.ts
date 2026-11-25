const ENV_VAR_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/

export function isValidEnvVarName(value: string): boolean {
  return ENV_VAR_NAME_PATTERN.test(value)
}

export function formatDotenvLine(varName: string, secretValue: string): string {
  if (!isValidEnvVarName(varName)) {
    throw new Error(`Invalid environment variable name: ${varName}`)
  }
  const escaped = secretValue
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
  return `\n${varName}="${escaped}"\n`
}

export function applySafeSecretExtraction(
  sourceCode: string,
  lineNumber: number,
  matchText: string,
  varName: string,
): string {
  if (!isValidEnvVarName(varName)) {
    throw new Error(`Invalid environment variable name: ${varName}`)
  }
  if (!matchText) {
    throw new Error('Cannot extract an empty secret match.')
  }

  const lines = sourceCode.split('\n')
  if (!Number.isInteger(lineNumber) || lineNumber < 1 || lineNumber > lines.length) {
    throw new Error(`Line number ${lineNumber} is out of bounds.`)
  }

  const targetLine = lines[lineNumber - 1]
  const replacement = `process.env.${varName}`
  for (const quote of ["'", '"', '`']) {
    const quoted = `${quote}${matchText}${quote}`
    const index = targetLine.indexOf(quoted)
    if (index !== -1) {
      lines[lineNumber - 1] =
        targetLine.slice(0, index) +
        replacement +
        targetLine.slice(index + quoted.length)
      return lines.join('\n')
    }
  }

  throw new Error('Refusing auto-extraction because the secret literal was not quoted on the target line.')
}
