export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface SecretPattern {
  name: string
  regex: RegExp
  severity: Severity
  description: string
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // ── AWS ─────────────────────────────────────────────────
  {
    name: 'AWS Access Key ID',
    regex: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g,
    severity: 'critical',
    description: 'AWS IAM access key',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /(?<![A-Za-z0-9/+=])(?:[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    description: 'AWS secret key (40 chars, base64-like)',
  },
  {
    name: 'AWS Session Token',
    regex: /(?:aws.?session.?token|AWS_SESSION_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})/gi,
    severity: 'critical',
    description: 'AWS temporary session token',
  },

  // ── Stripe ──────────────────────────────────────────────
  {
    name: 'Stripe Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    description: 'Stripe live secret key',
  },

  // ── GitHub ──────────────────────────────────────────────
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub personal access token (classic)',
  },
  {
    name: 'GitHub Fine-grained Token',
    regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    severity: 'critical',
    description: 'GitHub fine-grained personal access token',
  },

  // ── Google ──────────────────────────────────────────────
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
    description: 'Google Cloud / Firebase API key',
  },
  {
    name: 'Google OAuth Client Secret',
    regex: /GOCSPX-[a-zA-Z0-9\-_]{28}/g,
    severity: 'critical',
    description: 'Google OAuth 2.0 client secret',
  },

  // ── Slack ───────────────────────────────────────────────
  {
    name: 'Slack Bot / User / App Token',
    regex: /xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z\-]{10,}/g,
    severity: 'critical',
    description: 'Slack API token',
  },

  // ── Database / Connection Strings ───────────────────────
  {
    name: 'Database Connection String',
    regex: /(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^\s'"`,;{}]+:[^\s'"`,;{}]+@[^\s'"`,;{}]+/g,
    severity: 'critical',
    description: 'Database URL with credentials',
  },

  // ── Generic assignment patterns ─────────────────────────
  {
    name: 'Generic Password Assignment',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'high',
    description: 'Password assigned in source code',
  },
  {
    name: 'Generic Secret Assignment',
    regex: /(?:secret|secret_key|secretkey)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'high',
    description: 'Secret value assigned in source code',
  },
  {
    name: 'Generic Token Assignment',
    regex: /(?:api_?token|auth_?token|access_?token)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'high',
    description: 'Token assigned in source code',
  },
  {
    name: 'Generic API Key Assignment',
    regex: /(?:api_?key|apikey)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'high',
    description: 'API key assigned in source code',
  },

  // ── .env file detection ─────────────────────────────────
  {
    name: '.env File with Secrets',
    regex: /^(?:DATABASE_URL|SECRET_KEY|API_KEY|AUTH_SECRET|ENCRYPTION_KEY|PRIVATE_KEY|AWS_SECRET)\s*=\s*["']?([^\s"']+)/gm,
    severity: 'critical',
    description: 'Sensitive env var assignment (likely a .env file)',
  },
]

export const IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  'coverage',
  '.vercel',
  '.turbo',
  '.cache',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  'vendor',
  'target',
  '.gradle',
])

export const IGNORE_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.avi', '.mov', '.webm',
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.lock', '.map',
])

export const IGNORE_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'README.md', // Usually safe and contains documentation examples
])

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}
