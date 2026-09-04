# clutch-hub-sdk-js

![Alpha](https://img.shields.io/badge/status-alpha-orange.svg)
![Experimental](https://img.shields.io/badge/stage-experimental-red.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=flat&logo=typescript&logoColor=white)
[![npm](https://img.shields.io/npm/v/clutch-hub-sdk-js.svg)](https://www.npmjs.com/package/clutch-hub-sdk-js)

> ⚠️ **ALPHA SOFTWARE** — APIs may change without notice.

JavaScript/TypeScript SDK for the Clutch Hub API and Clutch blockchain.

**Documentation:** https://docs.clutchprotocol.io/clutch-hub-sdk-js/overview

## Install

```bash
npm install clutch-hub-sdk-js
```

## Usage

```javascript
import { ClutchHubSdk } from 'clutch-hub-sdk-js';

// privateKey is needed for authenticated calls: generateToken requires a signed
// proof-of-key-ownership challenge (the key stays local, it is never sent).
const sdk = new ClutchHubSdk('http://localhost:3000', publicKey, privateKey);

// Create, sign, and submit a ride request
const unsigned = await sdk.createUnsignedRideRequest({
  pickup: { latitude: 35.7, longitude: 51.4 },
  dropoff: { latitude: 35.8, longitude: 51.5 },
  fare: 1000,
});
const signed = await sdk.signTransaction(unsigned, privateKey);
await sdk.submitTransaction(signed.rawTransaction);
```

## Features

- Client-side signing (private keys never sent to server)
- Full ride lifecycle: request, offer, accept, pay, cancel
- GraphQL queries and WebSocket subscriptions
- TypeScript types

## API methods

| Category | Methods |
|----------|---------|
| Auth | Auto `generateToken` via `ensureAuth()` (signed challenge; needs the private key), `setPrivateKey`, `signAuthChallenge` |
| Write | `createUnsignedRide*`, `signTransaction`, `submitTransaction` |
| Read | `listRideRequests`, `listRideOffers`, `listActiveTrips`, `getAccountBalance`, … |
| Live | `subscribeRideRequests`, `subscribeRideOffers`, `subscribeActiveTrips`, … |

Full reference: https://docs.clutchprotocol.io/clutch-hub-sdk-js/api-reference

## Security

**Never expose private keys.** Client-side signing only. See [Security](https://docs.clutchprotocol.io/reference/security).

## Releases

Uses [semantic-release](https://semantic-release.gitbook.io/) with conventional commits.

**Created and maintained by [Mehran Mazhar](https://github.com/MehranMazhar)**
