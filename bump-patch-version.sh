#!/usr/bin/env bash
set -euo pipefail

csproj="src/PasswordManagerAccess.csproj"
changelog="CHANGELOG.md"

current=$(sed -n 's/.*<AssemblyVersion>\(.*\)<\/AssemblyVersion>.*/\1/p' "$csproj")
if [[ -z "$current" ]]; then
    echo "Error: could not find AssemblyVersion in $csproj" >&2
    exit 1
fi

IFS='.' read -r major minor patch <<< "$current"
new_patch=$((patch + 1))
new_version="$major.$minor.$new_patch"

echo "$current -> $new_version"

# Update csproj
sed -i '' "s|<AssemblyVersion>$current</AssemblyVersion>|<AssemblyVersion>$new_version</AssemblyVersion>|" "$csproj"

# Add new version entry to CHANGELOG.md after the "# Changelog" header
sed -i '' "/^# Changelog$/a\\
\\
## $new_version" "$changelog"

echo "Updated $csproj and $changelog"
