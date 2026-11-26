'use strict';

// The Windows Credential Manager bridge (lib/credential-manager.ps1) and
// its store (lib/keyring.cjs WindowsCredentialStore) round-trip a synthetic
// key through a uniquely named generic credential, then delete it. Only
// the test's own target is ever written or removed. Skipped off Windows.

const assert = require('assert');
const cryptoLib = require('../lib/crypto.cjs');
const { WindowsCredentialStore } = require('../lib/keyring.cjs');

async function main() {
  if (process.platform !== 'win32') {
    console.log('SKIP credential-manager (Windows only)');
    return;
  }

  const store = new WindowsCredentialStore({
    service: `zcode-keyring-test-${process.pid}-${Date.now()}`,
  });
  const account = 'probe';
  const keyString = Buffer.alloc(32, 7).toString('base64url');

  assert.strictEqual(store.available(), true, 'the bridge answers a read of a missing target');
  assert.strictEqual(store.get(account), null, 'nothing stored yet');

  try {
    assert.strictEqual(store.set(account, keyString), true);
    assert.strictEqual(store.get(account), keyString, 'the key round-trips through the UTF-16LE blob');
  } finally {
    assert.strictEqual(store.delete(account), true, 'the test credential is removed');
  }
  assert.strictEqual(store.get(account), null, 'gone after delete');
  assert.strictEqual(store.delete(account), false, 'deleting a missing target is not an error');

  // the blob on the wire is what ZCode's own keyring stores: UTF-16LE
  const blob = cryptoLib.keyToKeyringBlob(keyString);
  assert.strictEqual(cryptoLib.keyFromKeyringBlob(blob).toString('base64url'), keyString);

  console.log('PASS credential-manager round-trip (synthetic key, own target only)');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
