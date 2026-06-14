#!/usr/bin/env node
// 发布前安全卫生扫描（IP 分级 / 中国 PII / 静态站点 Web 卫生）。
//
// 职责边界：密钥/凭据检测已交给 gitleaks(见 .gitleaks.toml)。本脚本只负责 gitleaks
//   不擅长的部分——IP 分级、个人隐私(PII)、以及静态站点特有的「发布卫生」问题。
//
// 用法：
//   node scripts/scan-secrets.mjs            扫描发布集(优先 _site/,否则仓库根并排除工具目录)
//   node scripts/scan-secrets.mjs <path>...  扫描指定文件/目录(用于 fixture 自测)
//
// 退出码：检出高危 → 1（阻断发布）；仅低危或无命中 → 0（放行，低危打印 warning）。
//
// 分级：
//   高危(阻断) → 内网/云元数据 IP、中国手机号、身份证号、误发布敏感文件、source map 泄露
//   低危(告警) → 公网 IP、邮箱、外链缺 SRI、target=_blank 缺 noopener、混合内容、HTML 注释敏感词

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const HIGH = 'high', LOW = 'low';

// 工具/元数据目录：永不发布；仅在「扫描仓库根」时跳过(自测显式传入路径时不跳过)。
const NON_SITE = /(?:^|\/)(?:\.git|\.github|scripts|node_modules|_site)(?:\/|$)/;
// 可读为文本做内容检查的扩展名。
const TEXT_EXT = /\.(?:html?|js|mjs|cjs|css|json|xml|svg|txt|md)$/i;
// 敏感文件名/扩展:出现在发布集即高危(误发布)。
const SENSITIVE_FILE =
  /(?:^|\/)(?:\.env(?:\.[\w.-]+)?|\.htpasswd|\.npmrc|\.netrc|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.DS_Store)$|\.(?:bak|old|orig|swp|swo|pem|key|p12|pfx|keystore|jks|sql|sqlite|db)$|~$/i;

// ── IP ──
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IPV6 = /\b(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}\b/g;
const IP_IGNORE = new Set(['127.0.0.1', '0.0.0.0', '255.255.255.255']);
function ipSeverity(ip) {
  if (ip === '169.254.169.254') return HIGH;                   // 云元数据端点(SSRF 信号)
  const o = ip.split('.').map(Number);
  if (o[0] === 10) return HIGH;                                // 10.0.0.0/8
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return HIGH;   // 172.16.0.0/12
  if (o[0] === 192 && o[1] === 168) return HIGH;               // 192.168.0.0/16
  if (o[0] === 169 && o[1] === 254) return HIGH;               // link-local
  return LOW;                                                  // 公网 IP → 低危
}

// ── 中国 PII ──
const PHONE = /(?<!\d)1[3-9]\d{9}(?!\d)/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const ID_RE = /(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g;
// 身份证 ISO 7064 MOD 11-2 校验,降误报。
function validId(id) {
  const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const codes = '10X98765432';
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * w[i];
  return codes[sum % 11] === id[17].toUpperCase();
}

// ── Web 卫生 ──
const SOURCEMAP_REF = /\/\/[#@]\s*sourceMappingURL=/;
const SCRIPT_OPEN = /<script\b[^>]*>/gi;
const ANCHOR_BLANK = /<a\b[^>]*\btarget\s*=\s*["']?_blank\b[^>]*>/gi;
const MIXED_SRC = /\bsrc\s*=\s*["']http:\/\//i;
const LINK_HTTP = /<link\b[^>]*\bhref\s*=\s*["']http:\/\//i;
const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
const COMMENT_SENSITIVE = /(password|passwd|secret|token|api[_-]?key|私钥|密码|内部|todo|fixme)/i;

const redact = s => (s.length <= 8 ? '*'.repeat(s.length) : `${s.slice(0, 4)}****${s.slice(-4)}`);

// ── 收集发布集 ──
const args = process.argv.slice(2);
const noArgs = args.length === 0;
const root = existsSync('_site') ? '_site' : '.';
const targets = noArgs ? [root] : args;
const applyExclusion = noArgs && root === '.';   // 仅扫仓库根时排除工具目录

function collect(target) {
  let st; try { st = statSync(target); } catch { return []; }
  if (st.isFile()) return [target];
  const files = [], stack = [target];
  while (stack.length) {
    const dir = stack.pop();
    let entries; try { entries = readdirSync(dir); } catch { continue; }
    for (const name of entries) {
      const p = join(dir, name);
      if (applyExclusion && NON_SITE.test('/' + p)) continue;
      let s; try { s = statSync(p); } catch { continue; }
      if (s.isDirectory()) stack.push(p);
      else if (s.isFile()) files.push(p);
    }
  }
  return files;
}

const fileSet = [...new Set(targets.flatMap(collect))];
const findings = [];
const add = (sev, file, line, rule, detail) => findings.push({ sev, file, line, rule, detail });

// 文件级:误发布敏感文件 / source map 文件
for (const f of fileSet) {
  if (SENSITIVE_FILE.test(f)) add(HIGH, f, 0, 'SENSITIVE_FILE', '疑似误发布敏感文件');
  if (/\.map$/i.test(f)) add(HIGH, f, 0, 'SOURCEMAP_FILE', 'source map 文件不应发布');
}

// 内容级
for (const f of fileSet) {
  if (!TEXT_EXT.test(f)) continue;
  let text; try { text = readFileSync(f, 'utf8'); } catch { continue; }
  text.split(/\r?\n/).forEach((ln, i) => {
    const n = i + 1; let m;
    IPV4.lastIndex = 0; while ((m = IPV4.exec(ln))) { const ip = m[0]; if (!IP_IGNORE.has(ip)) add(ipSeverity(ip), f, n, 'IPV4', redact(ip)); }
    IPV6.lastIndex = 0; while ((m = IPV6.exec(ln))) add(LOW, f, n, 'IPV6', redact(m[0]));
    PHONE.lastIndex = 0; while ((m = PHONE.exec(ln))) add(HIGH, f, n, 'CN_PHONE', redact(m[0]));
    ID_RE.lastIndex = 0; while ((m = ID_RE.exec(ln))) { if (validId(m[0])) add(HIGH, f, n, 'CN_ID_CARD', redact(m[0])); }
    EMAIL.lastIndex = 0; while ((m = EMAIL.exec(ln))) add(LOW, f, n, 'EMAIL', redact(m[0]));
    if (SOURCEMAP_REF.test(ln)) add(HIGH, f, n, 'SOURCEMAP_REF', '内联 sourceMappingURL 引用');
    SCRIPT_OPEN.lastIndex = 0; while ((m = SCRIPT_OPEN.exec(ln))) { const t = m[0]; if (/\bsrc\s*=\s*["']https?:\/\//i.test(t) && !/\bintegrity\s*=/i.test(t)) add(LOW, f, n, 'MISSING_SRI', '外链脚本缺少 SRI 完整性校验'); }
    ANCHOR_BLANK.lastIndex = 0; while ((m = ANCHOR_BLANK.exec(ln))) { if (!/\brel\s*=\s*["'][^"']*noopener/i.test(m[0])) add(LOW, f, n, 'NO_NOOPENER', 'target=_blank 缺少 rel=noopener'); }
    if (MIXED_SRC.test(ln) || LINK_HTTP.test(ln)) add(LOW, f, n, 'MIXED_CONTENT', '子资源走 http://');
  });
  // HTML 注释敏感词(全文,只报命中的词不 dump 注释体)
  let cm; HTML_COMMENT.lastIndex = 0;
  while ((cm = HTML_COMMENT.exec(text))) {
    const km = cm[1].match(COMMENT_SENSITIVE);
    if (km) { const line = text.slice(0, cm.index).split(/\r?\n/).length; add(LOW, f, line, 'HTML_COMMENT', `注释含敏感词「${km[1]}」`); }
  }
}

// ── 输出 ──
const high = findings.filter(x => x.sev === HIGH);
const low = findings.filter(x => x.sev === LOW);
for (const x of [...high, ...low]) {
  const tag = x.sev === HIGH ? '⛔ HIGH' : '⚠️  LOW';
  (x.sev === HIGH ? console.error : console.warn)(`${tag}  ${x.file}${x.line ? ':' + x.line : ''}  [${x.rule}]  ${x.detail}`);
}
console.log(`\n[hygiene] 扫描 ${fileSet.length} 个文件 · 高危 ${high.length} · 低危 ${low.length}`);
if (high.length) {
  console.error(`\n❌ 检出 ${high.length} 项高危(内网/元数据IP·中国PII·敏感文件·source map)，阻断发布。`);
  process.exit(1);
}
if (low.length) console.warn(`\n⚠️  检出 ${low.length} 项低危(公网IP/邮箱/SRI/noopener/混合内容/注释)，仅告警。`);
console.log('✅ 无高危项，放行发布。');
process.exit(0);
