#!/usr/bin/env node
// 把 gitleaks JSON 报告渲染成【脱敏】的 Markdown 表,供写入 $GITHUB_STEP_SUMMARY。
// gitleaks 已用 --redact 脱敏(Secret/Match 字段为 REDACTED),这里再截断兜底,绝不输出完整密钥。
import { readFileSync } from 'node:fs';

const path = process.argv[2] || '/tmp/gitleaks.json';
let rows = [];
try { rows = JSON.parse(readFileSync(path, 'utf8')); } catch { /* 无报告则输出空表 */ }

console.log('## ⛔ gitleaks 检出密钥泄露(已脱敏)\n');
console.log('| 规则 | 文件 | 行 | 片段(脱敏) |');
console.log('|---|---|---|---|');
for (const f of rows) {
  const frag = String(f.Secret || f.Match || '').slice(0, 16);
  console.log(`| ${f.RuleID} | ${f.File} | ${f.StartLine} | \`${frag}\` |`);
}
