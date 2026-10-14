// SPDX-License-Identifier: Apache-2.0
// Trusted offline lock preparation, executed inside the gVisor sandbox.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {execFileSync} = require('child_process');

const rootArchive = path.join('/input', process.env.ZOLI_ARTIFACT);
const archives = [rootArchive, ...fs.readdirSync('/input/deps').filter(n => n.endsWith('.tgz')).sort().map(n => path.join('/input/deps', n))];
const packages = Object.create(null);
const versions = Object.create(null);
let rootName;
for (const archive of archives) {
  const manifest = JSON.parse(execFileSync('tar', ['-xOf', archive, 'package/package.json'], {maxBuffer: 1024 * 1024}).toString());
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/.test(manifest.name) || typeof manifest.version !== 'string') throw Error('Invalid archive package identity');
  if (versions[manifest.name] && versions[manifest.name] !== manifest.version) throw Error('Conflicting dependency versions cannot be reproduced in the flat sandbox layout');
  versions[manifest.name] = manifest.version;
  if (!rootName) rootName = manifest.name;
  packages['node_modules/' + manifest.name] = {
    version: manifest.version,
    resolved: 'file:' + archive,
    integrity: 'sha512-' + crypto.createHash('sha512').update(fs.readFileSync(archive)).digest('base64'),
    dependencies: manifest.dependencies || {},
    optionalDependencies: manifest.optionalDependencies || {},
    hasInstallScript: true
  };
}
const dependencies = Object.create(null);
dependencies[rootName] = 'file:' + rootArchive;
const workspace = {name: 'zoli-analysis', version: '1.0.0', dependencies};
packages[''] = workspace;
fs.writeFileSync('/work/package.json', JSON.stringify(workspace));
fs.writeFileSync('/work/package-lock.json', JSON.stringify({name: workspace.name, version: workspace.version, lockfileVersion: 3, requires: true, packages}));
