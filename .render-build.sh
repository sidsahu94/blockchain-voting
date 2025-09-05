#!/usr/bin/env bash
set -x

rm -rf node_modules
rm -f package-lock.json

npm install sqlite3 --build-from-source
npm install
