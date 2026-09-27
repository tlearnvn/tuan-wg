#!/usr/bin/env bash
# Tuấn WireGuard - tự tăng phiên bản và ghi CHANGELOG từ lịch sử commit
#
# Cách dùng:
#   scripts/bump-version.sh [auto|major|minor|patch|X.Y.Z] [tùy chọn]
#
#   auto (mặc định)  tự chọn mức tăng theo Conventional Commits:
#                      feat -> minor, fix/khác -> patch, "!" hoặc BREAKING CHANGE -> major
# Tùy chọn:
#   --range A..B     chỉ xét các commit trong khoảng (mặc định: từ tag v* gần nhất tới HEAD)
#   --last           chỉ xét commit HEAD (dùng cho git hook)
#   --amend          gộp thay đổi VERSION/CHANGELOG vào commit HEAD (git commit --amend)
#   --commit         tạo commit riêng "chore(release): vX.Y.Z"
#   --tag            tạo tag vX.Y.Z
#   --dry-run        chỉ in ra, không ghi file
#
# Tác giả: Tuandethuong
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

LEVEL="auto"
RANGE=""
LAST=0
AMEND=0
COMMIT=0
TAG=0
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    auto | major | minor | patch) LEVEL="$1" ;;
    [0-9]*.[0-9]*.[0-9]*) LEVEL="set"; SETVER="$1" ;;
    --range) RANGE="$2"; shift ;;
    --last) LAST=1 ;;
    --amend) AMEND=1 ;;
    --commit) COMMIT=1 ;;
    --tag) TAG=1 ;;
    --dry-run) DRY=1 ;;
    -h | --help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Tham số không hợp lệ: $1" >&2; exit 2 ;;
  esac
  shift
done

CUR="$(tr -d ' \n\r' < VERSION 2>/dev/null || echo 0.0.0)"
if ! [[ "$CUR" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "VERSION không đúng định dạng X.Y.Z: '$CUR'" >&2
  exit 1
fi
MA="${BASH_REMATCH[1]}"; MI="${BASH_REMATCH[2]}"; PA="${BASH_REMATCH[3]}"

# ---------- thu thập commit ----------
if [ "$LAST" = 1 ]; then
  LOG="$(git log -1 --no-merges --format='%s%x1f%b%x1e' HEAD)"
elif [ -n "$RANGE" ]; then
  LOG="$(git log --no-merges --format='%s%x1f%b%x1e' "$RANGE")"
else
  LASTTAG="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
  if [ -n "$LASTTAG" ]; then
    LOG="$(git log --no-merges --format='%s%x1f%b%x1e' "$LASTTAG"..HEAD)"
  else
    LOG="$(git log --no-merges --format='%s%x1f%b%x1e' HEAD 2>/dev/null || true)"
  fi
fi

UPPER_FIRST="s/^a/A/;s/^à/À/;s/^á/Á/;s/^ạ/Ạ/;s/^ả/Ả/;s/^ã/Ã/;s/^â/Â/;s/^ầ/Ầ/;s/^ấ/Ấ/;s/^ậ/Ậ/;s/^ẩ/Ẩ/;s/^ẫ/Ẫ/;s/^ă/Ă/;s/^ằ/Ằ/;s/^ắ/Ắ/;s/^ặ/Ặ/;s/^ẳ/Ẳ/;s/^ẵ/Ẵ/;s/^b/B/;s/^c/C/;s/^d/D/;s/^đ/Đ/;s/^e/E/;s/^è/È/;s/^é/É/;s/^ẹ/Ẹ/;s/^ẻ/Ẻ/;s/^ẽ/Ẽ/;s/^ê/Ê/;s/^ề/Ề/;s/^ế/Ế/;s/^ệ/Ệ/;s/^ể/Ể/;s/^ễ/Ễ/;s/^f/F/;s/^g/G/;s/^h/H/;s/^i/I/;s/^ì/Ì/;s/^í/Í/;s/^ị/Ị/;s/^ỉ/Ỉ/;s/^ĩ/Ĩ/;s/^j/J/;s/^k/K/;s/^l/L/;s/^m/M/;s/^n/N/;s/^o/O/;s/^ò/Ò/;s/^ó/Ó/;s/^ọ/Ọ/;s/^ỏ/Ỏ/;s/^õ/Õ/;s/^ô/Ô/;s/^ồ/Ồ/;s/^ố/Ố/;s/^ộ/Ộ/;s/^ổ/Ổ/;s/^ỗ/Ỗ/;s/^ơ/Ơ/;s/^ờ/Ờ/;s/^ớ/Ớ/;s/^ợ/Ợ/;s/^ở/Ở/;s/^ỡ/Ỡ/;s/^p/P/;s/^q/Q/;s/^r/R/;s/^s/S/;s/^t/T/;s/^u/U/;s/^ù/Ù/;s/^ú/Ú/;s/^ụ/Ụ/;s/^ủ/Ủ/;s/^ũ/Ũ/;s/^ư/Ư/;s/^ừ/Ừ/;s/^ứ/Ứ/;s/^ự/Ự/;s/^ử/Ử/;s/^ữ/Ữ/;s/^v/V/;s/^w/W/;s/^x/X/;s/^y/Y/;s/^ỳ/Ỳ/;s/^ý/Ý/;s/^ỵ/Ỵ/;s/^ỷ/Ỷ/;s/^ỹ/Ỹ/;s/^z/Z/"
BREAK=(); FEAT=(); FIX=(); PERF=(); REF=(); DOCS=(); OTHER=()
HAS_BREAK=0; HAS_FEAT=0
while IFS= read -r -d $'\x1e' rec; do
  rec="${rec#$'\n'}"
  [ -z "$rec" ] && continue
  subj="${rec%%$'\x1f'*}"
  body="${rec#*$'\x1f'}"
  case "$subj" in "chore(release)"* | "Merge "*) continue ;; esac
  type="other"; scope=""; bang=""; desc="$subj"
  if [[ "$subj" =~ ^([a-zA-Z]+)(\(([^\)]+)\))?(!)?:[[:space:]]*(.+)$ ]]; then
    type="$(echo "${BASH_REMATCH[1]}" | tr 'A-Z' 'a-z')"
    scope="${BASH_REMATCH[3]}"
    bang="${BASH_REMATCH[4]}"
    desc="${BASH_REMATCH[5]}"
  fi
  # viết hoa chữ cái đầu (kể cả chữ tiếng Việt có dấu)
  desc="$(printf '%s' "$desc" | sed "$UPPER_FIRST")"
  item="- ${scope:+**$scope:** }$desc"
  if [ -n "$bang" ] || printf '%s' "$body" | grep -q "BREAKING CHANGE"; then
    HAS_BREAK=1
    BREAK+=("$item")
    continue
  fi
  case "$type" in
    feat) HAS_FEAT=1; FEAT+=("$item") ;;
    fix) FIX+=("$item") ;;
    perf) PERF+=("$item") ;;
    refactor) REF+=("$item") ;;
    docs) DOCS+=("$item") ;;
    *) OTHER+=("$item") ;;
  esac
done <<< "$LOG"

# ---------- tính phiên bản mới ----------
case "$LEVEL" in
  set) NEW="$SETVER" ;;
  major) NEW="$((MA + 1)).0.0" ;;
  minor) NEW="$MA.$((MI + 1)).0" ;;
  patch) NEW="$MA.$MI.$((PA + 1))" ;;
  auto)
    if [ "$HAS_BREAK" = 1 ]; then
      if [ "$MA" = 0 ]; then NEW="0.$((MI + 1)).0"; else NEW="$((MA + 1)).0.0"; fi
    elif [ "$HAS_FEAT" = 1 ]; then NEW="$MA.$((MI + 1)).0"
    else NEW="$MA.$MI.$((PA + 1))"; fi
    ;;
esac

# ---------- nội dung CHANGELOG ----------
DATE="$(date +%Y-%m-%d)"
SECTION="$(mktemp)"
trap 'rm -f "$SECTION" "${SECTION}.new"' EXIT
{
  echo "## [$NEW] - $DATE"
  # ghi chú viết tay trong mục "Chưa phát hành" (nếu có)
  if [ -f CHANGELOG.md ]; then
    awk '/^## \[Chưa phát hành\]/{f=1; next} /^## /{f=0} f' CHANGELOG.md | sed '/^[[:space:]]*$/d'
  fi
  emit() { # emit "Tiêu đề" mảng...
    local title="$1"; shift
    [ $# -eq 0 ] && return 0
    echo
    echo "### $title"
    printf '%s\n' "$@"
  }
  emit "💥 Thay đổi lớn (không tương thích ngược)" ${BREAK[@]+"${BREAK[@]}"}
  emit "✨ Tính năng mới" ${FEAT[@]+"${FEAT[@]}"}
  emit "🐛 Sửa lỗi" ${FIX[@]+"${FIX[@]}"}
  emit "⚡ Hiệu năng" ${PERF[@]+"${PERF[@]}"}
  emit "♻️ Cải tiến mã nguồn" ${REF[@]+"${REF[@]}"}
  emit "📝 Tài liệu" ${DOCS[@]+"${DOCS[@]}"}
  emit "🔧 Thay đổi khác" ${OTHER[@]+"${OTHER[@]}"}
} > "$SECTION"
if [ "$(wc -l < "$SECTION")" -le 1 ]; then
  printf '\n### 🔧 Thay đổi khác\n- Cập nhật mã nguồn\n' >> "$SECTION"
fi

echo "Phiên bản: $CUR -> $NEW"
if [ "$DRY" = 1 ]; then
  cat "$SECTION"
  exit 0
fi

# chèn mục mới lên trước phiên bản gần nhất, làm trống mục "Chưa phát hành"
if [ ! -f CHANGELOG.md ]; then
  printf '# Nhật ký thay đổi\n\n## [Chưa phát hành]\n\n' > CHANGELOG.md
fi
awk -v secfile="$SECTION" '
  BEGIN { while ((getline l < secfile) > 0) sec = sec l "\n" }
  /^## \[Chưa phát hành\]/ { print; print ""; unrel = 1; skip = 1; next }
  /^## / && !done {
    if (!unrel) { print "## [Chưa phát hành]"; print "" }
    printf "%s\n", sec
    done = 1; skip = 0
    print; next
  }
  skip { next }
  { print }
  END {
    if (!done) {
      if (!unrel) { print "## [Chưa phát hành]"; print "" }
      printf "%s", sec
    }
  }
' CHANGELOG.md > "${SECTION}.new"
mv "${SECTION}.new" CHANGELOG.md
echo "$NEW" > VERSION
echo "Đã cập nhật VERSION và CHANGELOG.md"

if [ "$AMEND" = 1 ]; then
  git add VERSION CHANGELOG.md
  TWG_BUMPING=1 git commit --amend --no-edit --no-verify -q
  echo "Đã gộp vào commit $(git rev-parse --short HEAD)"
elif [ "$COMMIT" = 1 ]; then
  git add VERSION CHANGELOG.md
  TWG_BUMPING=1 git commit --no-verify -q -m "chore(release): v$NEW [skip ci]"
  echo "Đã tạo commit phát hành v$NEW"
fi
if [ "$TAG" = 1 ]; then
  git tag -a "v$NEW" -m "Tuấn WireGuard v$NEW"
  echo "Đã tạo tag v$NEW"
fi
