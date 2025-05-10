#!/usr/bin/env bash

# Path to your Chrome “History” SQLite DB on macOS
HISTORY_DB="$HOME/Library/Application Support/Google/Chrome/Profile 1/History"

if [[ ! -f "$HISTORY_DB" ]]; then
  echo "❌ Couldn’t find Chrome history at:"
  echo "   $HISTORY_DB"
  exit 1
fi

# Copy out so we don’t collide with a running Chrome
TMP_DB=$(mktemp)
cp "$HISTORY_DB" "$TMP_DB"

# Query the last 25 visits: convert Chrome’s 1601-epoch μs to normal time
sqlite3 -header -column "$TMP_DB" <<'SQL'
SELECT
  datetime((last_visit_time/1000000) - 11644473600, 'unixepoch') AS visit_time,
  url
FROM urls
ORDER BY last_visit_time DESC
LIMIT 250;
SQL

# Clean up
rm "$TMP_DB"
