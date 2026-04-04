export interface EntropyToken {
  token: string
  entropy: number
  kind: 'hex' | 'base64' | 'mixed'
}

export function findHighEntropyTokens(text: string): EntropyToken[] {
  const results: EntropyToken[] = []
  
  // Base64 strings (length >= 24)
  const b64Regex = /(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
  let match
  while ((match = b64Regex.exec(text)) !== null) {
    const token = match[0]
    if (token.length > 100) continue // Too long to be a normal secret
    
    const e = shannonEntropy(token)
    if (e > 4.5) {
      results.push({ token, entropy: e, kind: 'base64' })
    }
  }

  // Hex strings (length >= 32)
  const hexRegex = /\b[0-9a-fA-F]{32,64}\b/g
  while ((match = hexRegex.exec(text)) !== null) {
    const token = match[0]
    const e = shannonEntropy(token)
    if (e > 3.0) { // Hex has lower max entropy (3.17 bits)
      results.push({ token, entropy: e, kind: 'hex' })
    }
  }

  return results
}

function shannonEntropy(str: string): number {
  const len = str.length
  const frequencies = new Map<string, number>()
  for (let i = 0; i < len; i++) {
    const char = str[i]
    frequencies.set(char, (frequencies.get(char) || 0) + 1)
  }

  let entropy = 0
  for (const count of frequencies.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}
