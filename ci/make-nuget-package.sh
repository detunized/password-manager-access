#!/bin/bash

# This script is needed to strip out the leading `v` from the git tag. Otherwise it just calls
# `dotnet pack`.

GIT_TAG=$1

if [[ -z $GIT_TAG ]]; then
    echo "Usage: $0 git-tag"
    echo "Example: $0 v1.2.3"
    exit 1
fi

if [[ $GIT_TAG != v* ]]; then
    echo "The git tag must start with 'v'"
    exit 1
fi

# Remove the leading 'v' from the git tag
VERSION=$(echo $GIT_TAG | cut -c 2-)

# Build the NuGet package
dotnet pack --configuration Release --include-source --include-symbols -property:Version=$VERSION
