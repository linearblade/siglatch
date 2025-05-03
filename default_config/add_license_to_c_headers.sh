#!/bin/bash

add_generic_license_header() {
    file="$1"

    # Skip if already tagged
    if grep -q "License: MTL-10" "$file"; then
        echo "⚠️  Already tagged: $file"
        return
    fi

    # Create a temp file and insert header
    tmpfile=$(mktemp)
    cat <<'EOF' > "$tmpfile"
/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

EOF
    cat "$file" >> "$tmpfile"
    mv "$tmpfile" "$file"
    echo "✅ Tagged: $file"
}

# Process all .c and .h files
find . -type f \( -name "*.c" -o -name "*.h" \) -print0 |
while IFS= read -r -d '' file; do
    add_generic_license_header "$file"
done
