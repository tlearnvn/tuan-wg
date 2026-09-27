#!/usr/bin/env bash
# Bật git hook tự tăng phiên bản + CHANGELOG cho repo Tuấn WireGuard
set -e
cd "$(git rev-parse --show-toplevel)"
chmod +x .githooks/* scripts/bump-version.sh
git config core.hooksPath .githooks
echo "✔ Đã bật git hook (.githooks). Mỗi commit thay đổi mã nguồn sẽ tự tăng VERSION và ghi CHANGELOG.md"
echo "  Quy ước commit: feat: ... (tính năng -> tăng minor), fix: ... (sửa lỗi -> tăng patch), feat!: ... (thay đổi lớn -> tăng major)"
