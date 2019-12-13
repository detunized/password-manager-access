#!/bin/bash
set -e

API_KEY=$1

if [[ -z $API_KEY ]]; then
    exit 1
fi

env
dotnet nuget push --source nuget.org --api-key $API_KEY src/bin/*.nupgk
