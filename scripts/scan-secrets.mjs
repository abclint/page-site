#!/usr/bin/env node
// 安全扫描门禁：在发布前拦截站点内容中的敏感信息泄露。
//
// 为什么存在：GitHub Pages 是公开站点，HTML/JS/CSS/JSON 里误带的私钥、API Key、
//   内网 IP、邮箱会被搜索引擎公开索引且难以撤回。本脚本作为 CI 门禁，发布前扫描，
//   对高危泄露（私钥/密钥/令牌）阻断发布，对低危项（IP/邮箱）告警但放行。
//
// 用法：
//   node scripts/scan-secrets.mjs <file>...   显式扫描指定文件（用于 fixture 自测）
//   node scripts/scan-secrets.mjs             无参数 → 自动取「改动的站点内容文件」
//
// 退出码：检出高危 → 1（阻断）；仅低危或无命中 → 0（放行，低危打印 warning）。
//
// 设计约束（勿违反，违反等于削弱门禁）：
//   - 命中内容一律脱敏后输出（前4后4，中间打码），严禁把完整密钥打进公开 CI 日志。
//   - 自动模式只扫「待发布的站点内容」，因此排除 scripts/ 与 .github/（工具与测试目录，
//     永不发布）。这是“正确界定扫描范围”，不是“加白名单绕过真实泄露”——
//     真要发布的站点文件一个都不会被排除。

import { readFileSync, existsSync, statSync } from 'node:fs';
import { execSync } from 'node:child_process';

// ── 规则表 ────────────────────────────────────────────────────────────────
// severity: 'high' → 命中即阻断（退出 1）；'low' → 仅 warning（退出 0）。
const RULES = [
  { id: 'PRIVATE_KEY_BLOCK', severity: 'high', desc: '私钥块',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'AWS_ACCESS_KEY_ID', severity: 'high', desc: 'AWS Access Key ID',
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'GITHUB_TOKEN', severity: 'high', desc: 'GitHub Token',
    re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: 'SLACK_TOKEN', severity: 'high', desc: 'Slack Token',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'GOOGLE_API_KEY', severity: 'high', desc: 'Google API Key',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'GENERIC_SECRET_ASSIGN', severity: 'high', desc: '通用密钥/令牌赋值',
    re: /(?:api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_-]{16,}["']?/gi },
  { id: 'JWT', severity: 'high', desc: 'JWT',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: 'IPV4', severity: 'low', desc: 'IPv4 地址',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { id: 'IPV6', severity: 'low', desc: 'IPv6 地址',
    re: /\b(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}\b/g },
  { id: 'EMAIL', severity: 'low', desc: '邮箱地址',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
];

// 低危误报抑制：本机回环/通配地址泄露价值为零，不必告警。
const IPV4_IGNORE = new Set(['127.0.0.1', '0.0.0.0', '255.255.255.255']);

// 只扫这些扩展名（含 HTML 内联 <script>，因为按整文件逐行扫，内联脚本天然覆盖）。
const SITE_EXT = /\.(?:html?|js|mjs|css|json)$/i;
// 非站点内容：工具与测试目录，永不发布，自动模式下排除。
const NON_SITE = /(?:^|\/)(?:\.github|scripts|node_modules)\//;

// ── git 辅助 ─────────────────────────────────────────────────────────────
function sh(cmd) { return execSync(cmd, { encoding: 'utf8' }); }
function gitLines(cmd) {
  try { return sh(cmd).split('\n').map(s => s.trim()).filter(Boolean); }
  catch { return []; }
}
function gitOk(cmd) {
  try { execSync(cmd, { stdio: 'ignore' }); return true; } catch { return false; }
}

// 自动模式：解析「本次改动的文件」。
// 优先用 CI 注入的 SCAN_BASE..SCAN_HEAD；退化路径覆盖首次提交与本地工作区。
function changedFiles() {
  const base = (process.env.SCAN_BASE || '').trim();
  const head = (process.env.SCAN_HEAD || 'HEAD').trim();
  const allZero = /^0+$/;

  if (base && !allZero.test(base) && gitOk(`git cat-file -e ${base}^{commit}`)) {
    console.log(`[scan] 模式=git-diff  base=${base.slice(0, 8)}  head=${head.slice(0, 8)}`);
    return gitLines(`git diff --name-only ${base} ${head}`);
  }
  if (gitOk('git rev-parse --verify HEAD')) {
    if (gitOk('git rev-parse --verify HEAD~1')) {
      console.log('[scan] 模式=git-diff(HEAD~1..HEAD)  无有效 SCAN_BASE，回退到与父提交比较');
      return gitLines('git diff --name-only HEAD~1 HEAD');
    }
    console.log('[scan] 模式=首次提交  回退到全量 tracked 文件');
    return gitLines('git ls-files');
  }
  console.log('[scan] 模式=工作区  仓库无提交，扫描 tracked + 未忽略的 untracked');
  return [...gitLines('git ls-files'), ...gitLines('git ls-files --others --exclude-standard')];
}

// ── 脱敏 ─────────────────────────────────────────────────────────────────
// 命中片段一律脱敏：前4后4保留，中间固定 4 星；过短则全遮蔽。
function redact(s) {
  return s.length <= 8 ? '*'.repeat(s.length) : `${s.slice(0, 4)}****${s.slice(-4)}`;
}

// ── 主流程 ───────────────────────────────────────────────────────────────
const explicit = process.argv.slice(2);
let targets;
if (explicit.length) {
  // 显式模式（fixture 自测）：扫描指定文件，不做站点范围过滤。
  targets = explicit.filter(f => existsSync(f) && statSync(f).isFile());
  console.log(`[scan] 模式=显式文件  目标 ${targets.length} 个`);
} else {
  // 自动模式（CI 门禁）：只扫改动的、待发布的站点内容文件。
  targets = changedFiles().filter(f =>
    SITE_EXT.test(f) && !NON_SITE.test(f) && existsSync(f) && statSync(f).isFile());
  console.log(`[scan] 过滤后命中站点内容 ${targets.length} 个文件`);
}

const findings = [];
for (const file of targets) {
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  lines.forEach((text, idx) => {
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(text)) !== null) {
        const matched = m[0];
        if (rule.id === 'IPV4' && IPV4_IGNORE.has(matched)) continue;
        findings.push({ file, line: idx + 1, rule, snippet: redact(matched) });
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // 防零宽匹配死循环
      }
    }
  });
}

const high = findings.filter(f => f.rule.severity === 'high');
const low = findings.filter(f => f.rule.severity === 'low');

for (const f of findings) {
  const tag = f.rule.severity === 'high' ? '⛔ HIGH' : '⚠️  LOW';
  const out = f.rule.severity === 'high' ? console.error : console.warn;
  out(`${tag}  ${f.file}:${f.line}  [${f.rule.id}] ${f.rule.desc}  →  ${f.snippet}`);
}

console.log(`\n[scan] 完成：检查 ${targets.length} 个文件 · 高危 ${high.length} · 低危 ${low.length}`);

if (high.length) {
  console.error(`\n❌ 检出 ${high.length} 项高危泄露，阻断发布。请从源文件移除后重试（勿通过削弱规则绕过）。`);
  process.exit(1);
}
if (low.length) {
  console.warn(`\n⚠️  检出 ${low.length} 项低危项（仅告警，不阻断）。请人工确认这些 IP/邮箱是否应公开。`);
}
console.log('✅ 无高危泄露，放行发布。');
process.exit(0);
