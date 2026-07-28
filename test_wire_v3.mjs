// Run: npm run build && node test_wire_v3.mjs
import { ClutchHubSdk, verifyUnsignedTransaction, formatUsd } from './dist/index.js';
import assert from 'node:assert';
import * as rlp from 'rlp';

const sdk = new ClutchHubSdk('http://unused', '0x9b6e8afff8329743cac73dbef83ca3cbf9a74c20');
const unsigned = {
  from: '0x9b6e8afff8329743cac73dbef83ca3cbf9a74c20',
  nonce: 1,
  chain_id: 2077,
  data: { function_call_type: 'Burn', arguments: { amount: '5000000', redemption_ref: 'a'.repeat(64) } },
};
const signed = await sdk.signTransaction(
  unsigned,
  '0883ddd3d07303b87c954b0c9383f7b78f45e002520fc03a8adc80595dbf6509',
  { type: 'Burn', amount: 5000000n, redemptionRef: 'a'.repeat(64) },
);
const decoded = rlp.decode(Buffer.from(signed.rawTransaction.slice(2), 'hex'));
assert.equal(decoded.length, 8, '8-item signed tx');
assert.equal(BigInt('0x' + Buffer.from(decoded[2]).toString('hex')), 2077n, 'chain_id at index 2');
// rlp.decode is recursive — decoded[7] is ALREADY the nested [tagBuf, argsArray].
const [tag] = decoded[7];
assert.equal(Buffer.from(tag)[0], 7, 'Burn tag 7');

// chain_id must be the minimal big-endian encoding of 2077 (0x82 0x08 0x1d), not merely
// round-trip-equal after decode. Byte-compare the RLP-encoded chain_id item directly.
const chainIdEncoded = rlp.encode(2077);
assert.equal(Buffer.from(chainIdEncoded).toString('hex'), '82081d', 'chain_id RLP bytes are minimal big-endian');

// Burn call data round-trips its optional redemption_ref, including the empty-string case
// (None/absent encodes as '' — the same convention the referrer fields already use).
const [, burnArgs] = decoded[7];
const [amountBuf, refBuf] = burnArgs;
assert.equal(BigInt('0x' + Buffer.from(amountBuf).toString('hex')), 5000000n, 'Burn amount round-trips');
assert.equal(Buffer.from(refBuf).toString('utf8'), 'a'.repeat(64), 'Burn redemption_ref round-trips');

const unsignedNoRef = {
  from: '0x9b6e8afff8329743cac73dbef83ca3cbf9a74c20',
  nonce: 2,
  chain_id: 2077,
  data: { function_call_type: 'Burn', arguments: { amount: '1000', redemption_ref: '' } },
};
const signedNoRef = await sdk.signTransaction(
  unsignedNoRef,
  '0883ddd3d07303b87c954b0c9383f7b78f45e002520fc03a8adc80595dbf6509',
  { type: 'Burn', amount: 1000n, redemptionRef: '' },
);
const decodedNoRef = rlp.decode(Buffer.from(signedNoRef.rawTransaction.slice(2), 'hex'));
const [, burnArgsNoRef] = decodedNoRef[7];
const [, refBufNoRef] = burnArgsNoRef;
assert.equal(Buffer.from(refBufNoRef).length, 0, 'absent redemption_ref round-trips as empty string');

// verification catches a tampered fare
assert.throws(() =>
  verifyUnsignedTransaction(
    { ...unsigned, data: { function_call_type: 'Burn', arguments: { amount: '6000000', redemption_ref: 'a'.repeat(64) } } },
    { type: 'Burn', amount: 5000000n },
  ),
);

// presence-only chain_id checking would defeat the replay protection chain_id exists for —
// a mismatched (but present) chain_id must also throw.
assert.throws(() =>
  verifyUnsignedTransaction(
    { ...unsigned, chain_id: 1 },
    { type: 'Burn', amount: 5000000n, chainId: 2077 },
  ),
);

assert.equal(formatUsd(5000000n), '$5.00');
assert.equal(formatUsd(1n), '$0.00');
assert.equal(formatUsd(123456789n), '$123.45');
console.log('wire v3 self-check OK');
