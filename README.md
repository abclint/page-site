# page-site

带**安全扫描门禁**的 GitHub Pages 自动发布站点。站点：<https://abclint.github.io/page-site/>

## 流水线（`.github/workflows/deploy.yml`）

`push` 到 `main` 时：

| 阶段 | 作用 |
|---|---|
| **scan** | 用 `build-site.sh` 生成发布集 `_site/`，再跑 **gitleaks**(密钥) + **scan-secrets.mjs**(IP/PII/Web 卫生)。检出高危即失败，**不发布**。 |
| **lint** | `actionlint` + `zizmor` 自检工作流本身的语法与安全问题。 |
| **build** | `needs: [scan, lint]`，收集 `_site/` 上传为 Pages 产物，**原样保留目录层级**。 |
| **deploy** | GitHub 官方 `deploy-pages` 部署。 |

> 「扫描的」和「发布的」是同一份 `_site/`（`build-site.sh` 单一事实来源），不会出现"扫了 A 发了 B"。

## 检测分级

**密钥/凭据 → gitleaks**（`.gitleaks.toml`，继承内置规则 + 阿里云/腾讯云/京东自定义规则）。任一命中即**阻断**。

**IP / PII / Web 卫生 → scan-secrets.mjs**：

| 等级 | 行为 | 命中项 |
|---|---|---|
| **高危** | 阻断 | 内网 IP（10./172.16-31./192.168.）、云元数据 IP（169.254.169.254）、中国手机号、身份证号（带 MOD 11-2 校验）、误发布敏感文件（`.env`/`*.pem`/`*.bak`/`.DS_Store` 等）、source map 泄露 |
| **低危** | 告警 | 公网 IP、邮箱、外链缺 SRI、`target=_blank` 缺 `rel=noopener`、混合内容 `http://`、HTML 注释敏感词 |

命中**一律脱敏**（`前4****后4`）；gitleaks 用 `--redact`，job summary 也只含脱敏片段。

> ⚠️ 误报请**从源文件移除/重构**那段内容，**不要**删改扫描规则或加白名单放行——那等于拆门禁。

## 供应链加固

- 所有 GitHub Action **钉到 commit SHA**（行尾注释版本号），防 tag 被重打。
- gitleaks 用**二进制**（`v8.30.1`）而非官方 `gitleaks-action`——后者扫组织仓库需 license，二进制免 license。

## 新增页面

把 `.html` 及静态资源放进**仓库根目录任意子目录**，目录层级原样发布。
`scripts/`、`.github/`、`node_modules/`、`README.md`、`.gitignore`、`.gitleaks.toml` 不发布。

## 本地运行

```bash
# 装工具(一次)
brew install gitleaks actionlint

# 生成发布集并扫描(等价于 CI)
bash scripts/build-site.sh _site
gitleaks dir _site -c .gitleaks.toml --redact --no-banner --exit-code 1
node scripts/scan-secrets.mjs _site

# fixture 自测(scripts/__fixtures__/ 永不发布)
gitleaks dir scripts/__fixtures__/secrets -c .gitleaks.toml --redact --no-banner --exit-code 1  # 应 exit 1
node scripts/scan-secrets.mjs scripts/__fixtures__/pii/idcard.html                              # 应 exit 1
node scripts/scan-secrets.mjs scripts/__fixtures__/web/public-ip.html                           # 应 exit 0 + warning
```

## ⚙️ 一次性手动配置（必须，代码无法完成）

> 仓库 **Settings → Pages → Build and deployment → Source** 选 **“GitHub Actions”**

不设置则 Pages 不会采用本工作流的部署产物。
