#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import prompts from 'prompts';
import { execFileSync } from 'child_process';
import { SECRET_PATTERNS, IGNORE_DIRS, IGNORE_EXTS, IGNORE_FILES, SEVERITY_ORDER, type Severity } from './patterns';
import { findHighEntropyTokens } from './entropy';
import { applySafeSecretExtraction, formatDotenvLine, isValidEnvVarName } from './remediation';

function runRunenv(args: string[]): void {
  const npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  execFileSync(npxBin, ['runenv', ...args], { stdio: 'inherit' });
}

const program = new Command();

interface ScanIssue {
  file: string;
  line: number;
  name: string;
  severity: Severity;
  description: string;
  matchText: string;
  source: 'pattern' | 'entropy';
}

function shouldIgnoreFile(filePath: string): boolean {
  // basic check
  if (filePath.includes('/.git/')) return true;
  return false;
}

function scanFile(filePath: string, contents: string, entropy: boolean): ScanIssue[] {
  const results: ScanIssue[] = [];
  const lines = contents.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i];
    const trimmed = lineContent.trimStart();
    if (
      trimmed.startsWith('//') || 
      trimmed.startsWith('#') || 
      trimmed.startsWith('*') || 
      trimmed.startsWith('<!--') ||
      trimmed.startsWith('import ') ||
      trimmed.startsWith('export *')
    ) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(lineContent);
      if (match) {
        results.push({
          file: filePath,
          line: i + 1,
          name: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          matchText: match[1] || match[0],
          source: 'pattern',
        });
      }
    }

    if (entropy) {
      const entropyMatches = findHighEntropyTokens(lineContent);
      for (const em of entropyMatches) {
        const alreadyCaught = results.some(r => r.line === i + 1 && (r.matchText.includes(em.token) || em.token.includes(r.matchText)));
        if (alreadyCaught) continue;
        results.push({
          file: filePath,
          line: i + 1,
          name: `High Entropy ${em.kind.toUpperCase()} String`,
          severity: 'medium',
          description: `Entropy: ${em.entropy.toFixed(2)} bits/char`,
          matchText: em.token,
          source: 'entropy',
        });
      }
    }
  }

  return results;
}

function walkDir(dir: string, callback: (fp: string) => void) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir);

  for (const file of entries) {
    if (IGNORE_DIRS.has(file) || IGNORE_FILES.has(file)) continue;
    const filepath = path.join(dir, file);
    try {
      const stat = fs.statSync(filepath);
      if (stat.isDirectory()) {
        walkDir(filepath, callback);
      } else if (stat.isFile()) {
        const ext = path.extname(filepath).toLowerCase();
        if (IGNORE_EXTS.has(ext)) continue;
        if (stat.size > 1_000_000) continue; 
        const relativePath = path.relative(process.cwd(), filepath);
        if (shouldIgnoreFile(relativePath)) continue;
        callback(filepath);
      }
    } catch { continue; }
  }
}

function maskValue(value: string): string {
  if (value.length <= 8) return '****';
  return value.substring(0, 4) + '****' + value.substring(value.length - 4);
}

function calculateGrade(issues: ScanIssue[]): string {
  const critical = issues.filter(i => i.severity === 'critical').length;
  const high = issues.filter(i => i.severity === 'high').length;
  const medium = issues.filter(i => i.severity === 'medium').length;

  if (critical >= 3 || high >= 5) return 'F';
  if (critical >= 1 || high >= 2) return 'D';
  if (high >= 1 || medium >= 3) return 'C';
  if (medium >= 1) return 'B';
  return 'A+';
}

function getGradeColor(grade: string): chalk.Chalk {
  switch (grade) {
    case 'A+': return chalk.green.bold;
    case 'B': return chalk.yellow.bold;
    case 'C': return chalk.magenta.bold;
    case 'D': return chalk.redBright.bold;
    case 'F': default: return chalk.bgRed.white.bold;
  }
}

const SEVERITY_COLORS: Record<Severity, chalk.Chalk> = {
  critical: chalk.red,
  high: chalk.yellow,
  medium: chalk.cyan,
  low: chalk.dim,
}

program
  .name('env-doctor')
  .description('Audit your directory for secret hygiene leaks.')
  .option('-d, --dir <path>', 'Directory to scan', '.')
  .option('--no-entropy', 'Disable Shannon entropy scanning')
  .action(async (options) => {
    console.log(chalk.bold.cyan('\n🩺 env-doctor: Launching Hygiene Scanner...\n'));
    
    const rootDir = path.resolve(process.cwd(), options.dir);
    const filesToScan: string[] = [];
    walkDir(rootDir, (fp) => filesToScan.push(fp));

    const issues: ScanIssue[] = [];
    for (const filePath of filesToScan) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const rel = path.relative(process.cwd(), filePath);
        issues.push(...scanFile(rel, content, options.entropy !== false));
      } catch {}
    }

    const byLine = new Map<string, ScanIssue[]>();
    for (const issue of issues) {
      const key = `${issue.file}:${issue.line}`;
      const existing = byLine.get(key) || [];
      let shouldAdd = true;

      for (let i = 0; i < existing.length; i++) {
        const e = existing[i];
        if (e.matchText.includes(issue.matchText) || issue.matchText.includes(e.matchText)) {
          // If they overlap, keep the strictly smaller match text (the pure secret, instead of the assignment string)
          if (issue.matchText.length < e.matchText.length) {
            existing[i] = issue;
          }
          shouldAdd = false;
          break;
        }
      }
      
      if (shouldAdd) existing.push(issue);
      byLine.set(key, existing);
    }

    issues.length = 0;
    for (const fileIssues of byLine.values()) {
      issues.push(...fileIssues);
    }

    if (issues.length === 0) {
      console.log(chalk.green(`✅ Scanned ${filesToScan.length} files. Zero secrets leaked. Hygiene Score: A+`));
      process.exit(0);
    }

    issues.sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      if (sevDiff !== 0) return sevDiff
      return a.file.localeCompare(b.file) || a.line - b.line
    });

    const byFile = new Map<string, ScanIssue[]>()
    for (const issue of issues) {
      const existing = byFile.get(issue.file) || []
      existing.push(issue)
      byFile.set(issue.file, existing)
    }

    for (const [file, fileIssues] of byFile) {
      if (!process.env.CI) console.log(chalk.bold.underline(`📂 ${file}`));
      for (const issue of fileIssues) {
        const masked = maskValue(issue.matchText);
        if (process.env.CI) {
          console.log(`::error file=${issue.file},line=${issue.line}::[Hardcoded Secret] ${issue.name} leaked: ${masked}`);
        } else {
          const color = SEVERITY_COLORS[issue.severity];
          console.log(`    ${color('●')} [${issue.severity.toUpperCase()}] L${issue.line} — ${issue.name}`);
          console.log(`      ${chalk.dim(masked)}  (${chalk.italic(issue.description)})`);
        }
      }
      if (!process.env.CI) console.log();
    }

    const crit = issues.filter(i => i.severity === 'critical').length;
    const high = issues.filter(i => i.severity === 'high').length;
    const med  = issues.filter(i => i.severity === 'medium').length;
    const grade = calculateGrade(issues);
    const gColor = getGradeColor(grade);

    console.log(chalk.bold('\n--- Hygiene Report ---'));
    console.log(`Total Files Scanned: ${filesToScan.length}`);
    console.log(`Vulnerabilities:     ${crit} Critical, ${high} High, ${med} Medium`);
    console.log(`Project Risk Score:  ${gColor(` ${grade} `)}\n`);

    if (grade !== 'A+') {
      if (process.env.CI) {
        console.log(chalk.red.bold(`\n❌ CI Pipeline Blocked: ${crit + high + med} hardcoded secrets detected.`));
        console.log(chalk.dim(`Run 'npx env-doctor' locally to execute the automated remediation wizard.`));
        process.exit(1);
      }

      console.log(chalk.yellow('💡 Over 80% of data breaches stem from hardcoded credentials in source code.'));
      console.log(chalk.yellow('   Take 10 seconds to resolve this permanently.'));
      
      const response = await prompts({
        type: 'confirm',
        name: 'fix',
        message: chalk.bold.magenta('Would you like to securely vault these in the Cloud with RunEnv right now?'),
        initial: true
      });

      if (response.fix) {
        console.log(chalk.green('\n🚀 Bridging to RunEnv Migration Engine...'));
        let migrationReady = false;
        try {
          runRunenv(['init']);
          migrationReady = true;
        } catch (err) {
          console.log(chalk.yellow('\n⚠️ RunEnv is not fully configured for this workspace yet.'));
          console.log(chalk.cyan('Starting the automated setup wizard... 🪄\n'));
          
          try {
            console.log(chalk.bold('Authenticating with RunEnv Cloud...'));
            runRunenv(['login']);
            
            const defaultProjectName = path.basename(process.cwd());
            const projectResponse = await prompts({
              type: 'text',
              name: 'projectName',
              message: chalk.magenta('What should we name this project in the Cloud Vault?'),
              initial: defaultProjectName
            });

            const projectName = typeof projectResponse.projectName === 'string' ? projectResponse.projectName.trim() : '';
            if (projectName && !/[\r\n\0]/.test(projectName)) {
              console.log(chalk.cyan(`\nProvisioning secure boundary for: ${projectName}...`));
              runRunenv(['init', '--project', projectName]);
              migrationReady = true;
            } else {
              console.log(chalk.dim('\nSetup aborted.'));
            }
          } catch (wizardErr) {
            console.log(chalk.red('\n❌ Automated setup was incomplete. Please run these manually:'));
            console.log(chalk.bold('   1. npx runenv login'));
            console.log(chalk.bold('   2. npx runenv init --project <your-project-name>\n'));
          }
        }

        if (migrationReady) {
          // PHASE 1.5: Source Extraction Wizard
          const sourceIssues = issues.filter(i => !path.basename(i.file).startsWith('.env'));
          
          if (sourceIssues.length > 0) {
            console.log(chalk.cyan(`\n🛠️  Source Extraction Wizard`));
            console.log(chalk.dim(`We found ${sourceIssues.length} secrets hardcoded outside of .env files.`));
            
            for (const issue of sourceIssues) {
              const masked = maskValue(issue.matchText);
              console.log(chalk.yellow(`\n⚠️  Found in ${issue.file}:${issue.line}`));
              console.log(`    ${chalk.dim(masked)}`);
              
              const extractRes = await prompts({
                type: 'confirm',
                name: 'consent',
                message: chalk.magenta('Would you like env-doctor to auto-extract this to your .env file?'),
                initial: true
              });

              if (extractRes.consent) {
                const varRes = await prompts({
                  type: 'text',
                  name: 'varName',
                  message: chalk.cyan('What should we name this environment variable?'),
                  initial: 'SECRET_VAR_' + Math.floor(Math.random() * 1000)
                });

                const varName = typeof varRes.varName === 'string' ? varRes.varName.trim() : '';
                if (varName && isValidEnvVarName(varName)) {
                  try {
                    // 1. Refactor Source Code safely on the matched line within workspace root
                    const absPath = path.resolve(rootDir, issue.file);
                    if (absPath.startsWith(rootDir + path.sep) && fs.existsSync(absPath)) {
                      const sourceCode = fs.readFileSync(absPath, 'utf-8');
                      const updated = applySafeSecretExtraction(sourceCode, issue.line, issue.matchText, varName);
                      fs.writeFileSync(absPath, updated, 'utf-8');
                      console.log(chalk.green(`   ✔ Refactored ${issue.file}`));

                      // 2. Append to .env with owner-only permissions
                      const envFilePath = path.join(rootDir, '.env');
                      fs.appendFileSync(envFilePath, formatDotenvLine(varName, issue.matchText), {
                        encoding: 'utf-8',
                        mode: 0o600,
                      });
                      fs.chmodSync(envFilePath, 0o600);
                      console.log(chalk.green(`   ✔ Vaulted ${varName} into .env`));
                    }
                  } catch (err) {
                    console.log(chalk.red(`   ❌ Failed to automatically extract secret from ${issue.file}`));
                  }
                } else if (varName) {
                  console.log(chalk.red(`   ❌ Invalid environment variable name "${varName}". Use letters, digits, and underscores only.`));
                }
              }
            }
          }

          console.log(chalk.cyan(`\n⬆️ Pushing local secrets to the Cloud Vault...`));
          try {
            runRunenv(['push', '--yes']);
            
            // Backup the .env file to seal the leak
            const envPath = path.join(process.cwd(), '.env');
            if (fs.existsSync(envPath)) {
              fs.renameSync(envPath, path.join(process.cwd(), '.env.backup'));
              console.log(chalk.green(`\n✅ Backed up .env to .env.backup to prevent accidental commits.`));
            }
          } catch (pushErr) {
            console.log(chalk.yellow(`\n⚠️ Failed to automatically push secrets. Try running "npx runenv push" manually.`));
          }
        }
      } else {
        console.log(chalk.dim('\nMigration bypassed. Please manually rotate the leaked credentials ASAP.'));
      }
    }
  });

program.parse(process.argv);
