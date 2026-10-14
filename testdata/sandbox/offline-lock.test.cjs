const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('deploy/sandbox/npm-lock.cjs', 'utf8');
function prepare(manifests) {
  const outputs = {};
  const archives = ['/input/package.tgz', ...manifests.slice(1).map((_, i) => '/input/deps/' + i + '.tgz')];
  const mockFS = {
    readdirSync: () => archives.slice(1).map(p => require('node:path').basename(p)),
    readFileSync: p => Buffer.from('inert archive ' + p),
    writeFileSync: (p, b) => {outputs[p] = JSON.parse(b);}
  };
  vm.runInNewContext(source, {
    process: {env: {ZOLI_ARTIFACT: 'package.tgz'}},
    require: name => name === 'fs' ? mockFS : name === 'child_process' ? {
      execFileSync: (program, args) => {
        assert.equal(program, 'tar');
        return Buffer.from(JSON.stringify(manifests[archives.indexOf(args[1])]));
      }
    } : require(name)
  });
  return outputs;
}
test('offline lock pins verified local archives and preserves dependency constraints', () => {
  const out = prepare([{name:'root-package',version:'1.0.0',dependencies:{dep:'^2.0.0'}},{name:'dep',version:'2.1.0'}]);
  assert.equal(out['/work/package.json'].dependencies['root-package'], 'file:/input/package.tgz');
  const lock = out['/work/package-lock.json'];
  assert.equal(lock.packages['node_modules/root-package'].dependencies.dep, '^2.0.0');
  assert.equal(lock.packages['node_modules/dep'].resolved, 'file:/input/deps/0.tgz');
  assert.match(lock.packages['node_modules/dep'].integrity, /^sha512-/);
});
test('conflicting versions fail instead of silently changing the runtime layout', () => {
  assert.throws(() => prepare([{name:'root-package',version:'1.0.0'},{name:'dep',version:'1.0.0'},{name:'dep',version:'2.0.0'}]), /Conflicting dependency versions/);
});
test('invalid archive identities cannot escape the package layout', () => {
  assert.throws(() => prepare([{name:'../outside',version:'1.0.0'}]), /Invalid archive package identity/);
});
