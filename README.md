# page-site

一个带**安全扫描门禁**的 GitHub Pages 自动发布站点。站点地址：
<https://abclint.github.io/page-site/>

## 它做什么

每次 `push` 到 `main`，`.github/workflows/deploy.yml` 会依次执行：

1. **scan** — 扫描本次改动的站点内容（`.html/.js/.css/.json`，含 HTML 内联 `<script>`），
   检出敏感信息泄露。**检出高危项则整条流水线失败，不发布。**
2. **build** — 用 `rsync` 把站点内容收集到 `_site/`（排除 `scripts/`、`.github/` 等工具目录），
   **原样保留目录层级**。
3. **deploy** — 用 GitHub 官方 Actions（`upload-pages-artifact` + `deploy-pages`）部署。

## 扫描分级

| 等级 | 行为 | 规则 |
|---|---|---|
| **高危** | 阻断发布（退出码 1） | 私钥块、AWS Access Key、GitHub/Slack Token、Google API Key、通用密钥/令牌赋值、JWT |
| **低危** | 仅告警（退出码 0） | IPv4、IPv6、邮箱 |

命中内容**一律脱敏**输出（`前4****后4`），不会把完整密钥打进 CI 日志。

> ⚠️ 若扫描误报，**正确做法是从源文件移除/重构那段内容**，
> 不要通过删改 `scripts/scan-secrets.mjs` 的规则或加白名单来“放行”——那等于拆掉门禁。

## 新增页面

把任意 `.html` 及其静态资源放进**仓库根目录的任意子目录**即可，目录层级会原样发布。
`scripts/`、`.github/`、`node_modules/`、`README.md` 不会被发布。

## 本地运行扫描

```bash
# 扫描本次改动的站点内容（自动模式）
node scripts/scan-secrets.mjs

# 自测：显式扫描指定文件
node scripts/scan-secrets.mjs scripts/__fixtures__/leak-private-key.html   # 退出码 1（高危阻断）
node scripts/scan-secrets.mjs scripts/__fixtures__/only-ip.html            # 退出码 0（低危仅告警）
```

## ⚙️ 一次性手动配置（必须，代码无法完成）

首次发布前，在 GitHub 网页端操作一次：

> 仓库 **Settings → Pages → Build and deployment → Source** 选择 **“GitHub Actions”**

不设置则 Pages 不会采用本工作流的部署产物。
