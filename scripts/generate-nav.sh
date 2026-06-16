#!/usr/bin/env bash
# 扫描 _site/ 目录树，生成嵌套导航并注入 index.html 的 <!-- NAV_TREE --> 标记处。
# 用法: bash scripts/generate-nav.sh _site
set -euo pipefail

SITE_DIR="${1:-_site}"
INDEX_FILE="$SITE_DIR/index.html"
MARKER="<!-- NAV_TREE -->"

if [ ! -f "$INDEX_FILE" ]; then
  echo "[generate-nav] 错误: 未找到 $INDEX_FILE" >&2
  exit 1
fi

# ---- 提取页面标题 ----
get_title() {
  local file="$1"
  local t
  # macOS 默认 grep 不支持 -P，用 sed 提取 <title>...</title>
  t=$(sed -n '/<title>/{s/.*<title>\([^<]*\)<\/title>.*/\1/p;q;}' "$SITE_DIR/$file" 2>/dev/null)
  if [ -z "$t" ]; then
    t=$(basename "$file" .html)
  fi
  echo "$t"
}

# ---- 构建目录树 ----
# 数据结构：为每个 HTML 文件记录 (路径, 链接, 显示名)
# index.html 的链接指向父目录，非 index.html 指向自身
declare -a entries=()

while IFS= read -r raw; do
  file="${raw#./}"
  dir=$(dirname "$file")
  base=$(basename "$file")

  if [ "$base" = "index.html" ]; then
    link="$dir/"
    display=$(get_title "$file")
  else
    link="$file"
    display=$(get_title "$file")
  fi
  entries+=("$file|$link|$display")
done < <(cd "$SITE_DIR" && find . -name "*.html" \
  ! -path "./index.html" \
  ! -path "./pagefind/*" \
  | sort)

# ---- 将条目展开为嵌套 HTML ----
# 使用栈追踪当前开启的 <li><ul> 路径
print_tree() {
  # 当前打开到第几层目录（0 = 没有任何 <ul> 打开）
  local depth=0
  local -a stack_dirs=()

  for entry in "${entries[@]}"; do
    IFS='|' read -r file link display <<< "$entry"
    dir=$(dirname "$file")
    IFS='/' read -ra dir_parts <<< "$dir"

    # 去除 "." 根目录
    if [ "${dir_parts[0]}" = "." ]; then
      dir_parts=()
    fi

    # 计算与栈中已打开目录的共同前缀长度
    local common=0
    while [ "$common" -lt "$depth" ] && [ "$common" -lt "${#dir_parts[@]}" ]; do
      if [ "${dir_parts[$common]}" = "${stack_dirs[$common]}" ]; then
        ((common++))
      else
        break
      fi
    done

    # 关闭多余层级
    while [ "$depth" -gt "$common" ]; do
      printf '%*s</ul></li>\n' $((depth * 2)) ''
      ((depth--))
    done

    # 打开新的层级
    while [ "$depth" -lt "${#dir_parts[@]}" ]; do
      local dir_name="${dir_parts[$depth]}"
      printf '%*s<li><span class="nav-dir">%s</span>\n' $((depth * 2)) '' "$dir_name"
      printf '%*s<ul>\n' $((depth * 2)) ''
      stack_dirs[$depth]="$dir_name"
      ((depth++))
    done

    # 输出当前页面
    printf '%*s<li><a href="./%s">%s</a></li>\n' $((depth * 2)) '' "$link" "$display"
  done

  # 关闭所有剩余层级
  while [ "$depth" -gt 0 ]; do
    printf '%*s</ul></li>\n' $((depth * 2)) ''
    ((depth--))
  done
}

nav_html=$(print_tree)

# ---- 注入 index.html ----
if grep -qF "$MARKER" "$INDEX_FILE"; then
  # 将导航 HTML 写入临时文件，用 sed r 命令替换标记行
  nav_tmp=$(mktemp)
  echo "$nav_html" > "$nav_tmp"
  sed "/^[[:space:]]*$(printf '%s' "$MARKER" | sed 's/[\/&]/\\&/g')/{
    r $nav_tmp
    d
  }" "$INDEX_FILE" > "$INDEX_FILE.tmp"
  rm -f "$nav_tmp"
  mv "$INDEX_FILE.tmp" "$INDEX_FILE"
  echo "[generate-nav] 导航树已注入 ${INDEX_FILE}（${#entries[@]} 个页面）"
else
  echo "[generate-nav] 警告: 未找到 $MARKER 标记，跳过注入" >&2
fi
