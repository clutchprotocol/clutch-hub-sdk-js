# clutch-hub-sdk-js

TypeScript client SDK for Clutch Protocol (npm: `clutch-hub-sdk-js`). Signs transactions
client-side (secp256k1 + keccak-256 + RLP) and talks to the Hub API over GraphQL HTTP and
graphql-ws subscriptions. See the parent `D:\source\clutch\CLAUDE.md` for the workspace overview.

## Source Layout

Only four source files — the SDK is deliberately small:

- `src/sdk.ts` — everything important: `ClutchHubSdk` class, JWT auth caching, signing/hashing,
  RLP encoding (`encodeFunctionCall`), all GraphQL queries/mutations/subscriptions inline as
  template strings, faucet helper. Also exports `stripHexPrefix`, `normalizeTxHashForRlp`,
  `UnsignedTransaction`.
- `src/subscriptions.ts` — `hubGraphqlWsUrl()` (HTTP base URL → `ws(s)://…/graphql/ws`),
  `createHubSubscriptionClient()` (graphql-ws client: `lazy: false`, infinite retry, 10s keepAlive),
  shared GraphQL field-selection constants (`RIDE_REQUEST_GQL_FIELDS` etc.), `SubscriptionHandlers<T>`.
- `src/types.ts` — arg/result interfaces (`RideRequestArgs`, `AvailableActiveTrip`, `MapBounds`,
  `Signature`, `FaucetResponse`, …).
- `src/index.ts` — barrel re-exports. New public symbols must be reachable from here.

There is no test suite. `test_rlp_fix.{js,mjs}` are ad-hoc manual scripts run against `dist/` after
`npm run build` — not wired into CI.

## Transaction Lifecycle (client side)

1. **Build unsigned**: `createUnsignedRideRequest/Offer/Acceptance/Pay/Cancel/RequestCancel` call
   the corresponding Hub API mutation (after `ensureAuth`) and get back
   `{ data, from, nonce }` (`UnsignedTransaction`).
2. **Encode call data**: `encodeFunctionCall(data)` maps the function-call type to a nested array
   `[tag, args]` for RLP. Tags must match the Rust node: RideRequest=1, RideOffer=2,
   RideAcceptance=3, RidePay=4, RideCancel=5, RideRequestCancel=8 (6/7 reserved elsewhere).
3. **Hash**: RLP-encode `[from (no 0x), nonce, callDataArray]`, keccak-256 it → `rawHashHex`.
4. **Sign**: `signHash` does **not** sign the hash bytes directly — the Rust node verifies
   `Keccak256(hash_string.as_utf8_bytes())`, so the SDK keccaks the *hex string's UTF-8 bytes*,
   then `secp.signAsync`. Recovery id + 27 → `v`.
5. **Encode signed**: RLP `[from, nonce, r, s, v, hash, callDataArray]` (all hex without 0x) →
   `rawTransaction: '0x…'`.
6. **Submit**: `submitTransaction(rawTransaction)` → `sendRawTransaction` mutation → tx hash.

Signing quirks to preserve: floats (lat/lng) are encoded as IEEE-754 big-endian u64 bits via
`float64ToUint64` (BigInt); tx-hash args go through `normalizeTxHashForRlp` (strips 0x *and*
legacy JSON-string quoting); empty referrer encodes as `''`.

## Public API Surface (`ClutchHubSdk`)

- **Constructor / identity**: `new ClutchHubSdk(apiUrl, publicKey, privateKey?)`, `getPublicKey()`,
  `setPrivateKey(privateKey)`, `isAuthenticated()`. The private key (constructor arg or
  `setPrivateKey`) is required for token issuance — `generateToken` demands a signed
  proof-of-key-ownership challenge. It is kept in a module-global map keyed by publicKey
  (like the JWT cache) and never sent to the API.
- **Auth (internal)**: `ensureAuth()` builds the challenge `clutch-auth:{publicKey}:{timestamp}`
  (unix seconds), signs it via `signAuthChallenge` (Keccak-256 the message to a hex string, then
  the usual `signHashHex` convention — see Transaction Lifecycle step 4), and calls the
  `generateToken(publicKey, timestamp, signature)` mutation. The Hub API rejects timestamps more
  than ±120s from server time. JWTs are cached in a **module-global** map keyed by publicKey with
  30s expiry buffer and in-flight dedup, so multiple SDK instances share tokens; `ensureAuth`
  throws if no cached token is valid and no private key was provided. Exported helpers:
  `buildAuthChallengeMessage`, `authChallengeHashHex`, `signAuthChallenge` — these must stay
  byte-for-byte in sync with `clutch-hub-api`'s `hub/auth.rs`.
- **Unsigned tx builders**: `createUnsignedRideRequest/RideOffer/RideAcceptance/RidePay/RideCancel/RideRequestCancel`.
- **Sign & submit**: `signTransaction(unsignedTx, privateKey)` → `{ r, s, v, rawTransaction, txHash }`;
  `submitTransaction(rawTransaction)`.
- **Queries**: `listRideRequests(bounds?)`, `listRideOffers(hash)`, `listActiveTrips`,
  `listCompletedTrips`, `listRecentTrips`, `getAccountBalance(publicKey?)`.
- **Subscriptions** (each returns a dispose function): `subscribeRideRequests`,
  `subscribeRideOffers`, `subscribeActiveTrips`, `subscribeCompletedTrips`, `subscribeRecentTrips`,
  `subscribeAccountBalance`. All multiplex over **one shared graphql-ws socket per
  (hub URL, publicKey)**, refcounted in a module-global map; the last dispose closes the socket.
  Always call the returned dispose function or sockets/refcounts leak.
- **Misc**: `requestFaucet(address)` — plain `POST /faucet` (no JWT), returns
  `{ ok: false, error }` instead of throwing; `getGraphqlWsUrl()`.

## Adding a New Transaction Type

1. Add the arg interface to `src/types.ts`; export lands via `src/index.ts` automatically.
2. Add `createUnsignedXxx` in `src/sdk.ts` mirroring existing ones (inline mutation string,
   `ensureAuth`, `executeGraphQL`).
3. Add a `case` in `encodeFunctionCall` with the **same tag number and argument order as the Rust
   node's FunctionCall enum** (`clutch-node`) — a mismatch produces valid-looking txs the node
   rejects. Support both snake_case (`ride_offer_transaction_hash`) and camelCase arg keys, as the
   Hub API has returned both shapes.
4. Upstream first: node RPC → `clutch-hub-api` GraphQL mutation must exist before the SDK method
   works. Then update `clutch-hub-demo-app` and `clutch-docs`.

For a new query/subscription: add types + field constant (in `subscriptions.ts` if shared between
query and subscription), then a `listXxx` using `executeGraphQL` and/or a `subscribeXxx` using
`subscribeGraphqlListField` (list payloads) or the manual pattern in `subscribeAccountBalance`
(scalar payloads).

## Build & Release

- `npm run build` = `tsc` → `dist/` (declarations included). `prepare` also builds, which is what
  makes the `file:` install work. No lint or test scripts exist despite CONTRIBUTING.md mentioning them.
- tsconfig: ES2020 target, `module: ESNext`, `strict: true`, DOM lib included (browser-first).
- **semantic-release** on push to `main` (`.github/workflows/npm-publish.yml` + `.releaserc.json`):
  Conventional Commits required. `feat:` → minor, `fix:`/`perf:`/`refactor:` → patch,
  `feat!:` or a `BREAKING CHANGE:` footer → major; `docs:`/`chore:`/`ci:`/`test:`/`build:`/`style:`
  release nothing. Non-releasing pushes to `main` publish a `-canary.<sha>` build under the
  `canary` dist-tag. A `beta` branch does prereleases. CHANGELOG.md and package.json version are
  bot-committed (`chore(release): x.y.z [skip ci]`) — never bump the version by hand.
- The demo app consumes this repo via `"clutch-hub-sdk-js": "file:../clutch-hub-sdk-js"`; its
  `predev`/`prebuild` run `npm run build --prefix ../clutch-hub-sdk-js`. So SDK source changes
  reach the demo app on its next `npm run dev` — but if Vite is already running you may need to
  restart / clear `node_modules/.vite` to pick up the rebuilt dist.

## Gotchas

- **Browser + Node dual use**: `sdk.ts` imports `buffer` (npm polyfill) and assigns
  `window.Buffer` if missing. Don't use Node-only APIs; keep DOM usage guarded by
  `typeof window !== 'undefined'`.
- `@noble/secp256k1` v2 hex parsers reject `0x` prefixes — always run keys/hashes through
  `stripHexPrefix` before passing them to noble.
- Auth state (JWT cache, in-flight dedup, shared WS clients) is module-global, not per-instance —
  tests or multi-wallet apps share it by design.
- WS subscriptions silently continue without a JWT if `generateToken` fails — including when no
  private key was supplied for the wallet (public list subscriptions are allowed unauthenticated).
- GraphQL operations are inline strings with hand-written TS result types — there is no codegen;
  keep field constants and `types.ts` in sync with the Hub API schema manually.
