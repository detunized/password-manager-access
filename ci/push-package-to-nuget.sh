#!/bin/bash
set -e

API_KEY=$NUGET_API_KEY

if [[ -z $API_KEY ]]; then
    echo "Environemtn variable NUGET_API_KEY must be set"
    exit 1
fi

env
dotnet nuget push --source nuget.org --api-key $API_KEY --skip-duplicate src/bin/Release/*.nupkg
