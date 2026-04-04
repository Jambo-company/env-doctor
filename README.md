# 🩺 @jambo.team/env-doctor

A lightning-fast, zero-dependency secrets scanner and automated remediation engine for modern development teams.

**env-doctor** proactively scans your source code for hardcoded secrets, cryptographic keys, and high-entropy passwords. When vulnerabilities are detected, our interactive **Remediation Wizard** surgically extracts the string, replaces it with `process.env.*`, and auto-vaults it into the Cloud.

This tool is part of the [RunEnv](https://runenv.dev) DevSecOps ecosystem.

## 🚀 Features
- **Zero Dependencies**: Uses native JavaScript modules. Extremely lightweight.
- **Blazing Fast**: Native regex execution and Shannon entropy analysis ensures sub-millisecond execution.
- **Automated Refactoring**: Identifies leaks and natively splices `process.env.VAR_NAME` directly into your code.
- **CI/CD Native**: Seamlessly plugs into GitHub Actions, automatically blocking Pull Requests and surfacing file annotations in the PR code review interface.

## 💻 Local Usage

You don't need to install anything! Run it directly via `npx` in any codebase:

```bash
npx @jambo.team/env-doctor@latest
```

It will execute a full risk analysis on your repository and grade your hygiene. If your grade is below an `A+`, it will launch the interactive remediation wizard to vault the leaked secrets.

### Optional Flags
```bash
# Scan a specific directory
npx @jambo.team/env-doctor@latest -d src/

# Disable Shannon Entropy (massively boosts speed for huge codebases)
npx @jambo.team/env-doctor@latest --no-entropy
```

## 🛡️ GitHub Actions Setup

You can fully automate this scanner in your CI/CD pipelines to ensure developers never merge a leaked API key to production.

Create a `.github/workflows/scan.yml` file in your repository:

```yaml
name: "Security: Secret Scanner"

on:
  pull_request:
    branches: [ "main", "develop" ]

jobs:
  scan:
    name: "Audit Source Code"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: RunEnv Secret Scanner
        uses: Jambo-company/env-doctor@main
```

When run in CI, if a secret is hardcoded, `env-doctor` will fatally crash the build and annotate exactly where the leak occurred inside the GitHub PR UI.

## License

MIT License
