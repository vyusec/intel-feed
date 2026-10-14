#!/bin/sh
set -eu
cd /work
node /usr/local/bin/npm-lock.cjs
npm ci --offline --no-audit --no-fund --ignore-scripts=false
# Import the installed package rather than every bundled file.
node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync("package.json")); for(const name of Object.keys(p.dependencies||{})) require(name)'
