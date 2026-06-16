#!/usr/bin/env bash
# 收集「发布集」到 _site/:把仓库内容原样复制,排除工具/测试/元数据目录。
# 单一事实来源——CI 的 scan 与 build 两个 job 都调用它,保证「扫描的」与「发布的」完全一致,
# 目录层级原样保留(rsync -a)。
set -euo pipefail

DEST="${1:-_site}"
rm -rf "$DEST"
mkdir -p "$DEST"

rsync -a \
  --exclude='.git' \
  --exclude='.github' \
  --exclude='scripts' \
  --exclude='node_modules' \
  --exclude="$DEST" \
  --exclude='.gitignore' \
  --exclude='.gitleaks.toml' \
  --exclude='README.md' \
  ./ "$DEST"/

# 注入目录树导航到 index.html
bash scripts/generate-nav.sh "$DEST"

# Pagefind 搜索索引（pagefind_extended 支持中文分词）
if command -v pagefind_extended &> /dev/null; then
  pagefind_extended --site "$DEST"
  echo "[build-site] Pagefind 索引已构建 → $DEST/pagefind/"
elif command -v pagefind &> /dev/null; then
  pagefind --site "$DEST"
  echo "[build-site] Pagefind 索引已构建 → $DEST/pagefind/"
else
  echo "[build-site] 跳过 Pagefind（未安装 pagefind 二进制，CI 中会自动安装）"
fi

echo "[build-site] 已生成发布集 → $DEST/ ($(find "$DEST" -type f | wc -l | tr -d ' ') 个文件)"
