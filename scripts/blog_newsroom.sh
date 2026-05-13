#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

limit="${1:-5}"

python3 -m secopsai.cli blog news-run --limit "$limit"
echo
python3 -m secopsai.cli blog news-review list

cat <<'EOF'

Next steps:
  1. Inspect a draft:
     python3 -m secopsai.cli blog news-review show <draft-slug-or-path>

  2. Approve or reject it:
     python3 -m secopsai.cli blog news-review approve <draft-slug-or-path> --note "Reviewed sources and SecOpsAI guidance"
     python3 -m secopsai.cli blog news-review reject <draft-slug-or-path> --note "Not relevant or insufficiently sourced"

  3. Publish approved drafts and rebuild feeds:
     python3 -m secopsai.cli blog news-publish-approved --rebuild
EOF
