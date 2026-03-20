# clutch-hub-sdk-js

![Alpha](https://img.shields.io/badge/status-alpha-orange.svg)
![Experimental](https://img.shields.io/badge/stage-experimental-red.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=flat&logo=typescript&logoColor=white)
[![npm](https://img.shields.io/npm/v/clutch-hub-sdk-js.svg)](https://www.npmjs.com/package/clutch-hub-sdk-js)
[![npm downloads](https://img.shields.io/npm/dm/clutch-hub-sdk-js.svg)](https://www.npmjs.com/package/clutch-hub-sdk-js)

> ⚠️ **ALPHA SOFTWARE** - This project is in active development and is considered experimental. Use at your own risk. APIs may change without notice.

JavaScript SDK for interacting with the clutch-hub-api

**Created and maintained by [Mehran Mazhar](https://github.com/MehranMazhar)**

## Overview

`clutch-hub-sdk-js` is a JavaScript/TypeScript SDK for building decentralized applications (dApps) that interact with the [clutch-hub-api](https://github.com/your-org/clutch-hub-api) and the Clutch custom blockchain. This SDK helps you:
- Connect to the hub API
- Build and sign transactions client-side (keeping private keys secure)
- Submit signed transactions to the blockchain via the API
- Query chain state (e.g., get nonce, balances, etc.)

## Features
- **Client-side signing:** Never expose your private key to the server; all signing is done in the browser or mobile app.
- **Transaction helpers:** Easily build, encode, and sign custom Clutch transactions (e.g., ride requests).
- **API integration:** Fetch chain state and submit signed transactions to the hub API.
- **GraphQL subscriptions:** `subscribeRideRequests`, `subscribeRideOffers`, `subscribeActiveTrips`, and `subscribeCompletedTrips` use [`graphql-ws`](https://github.com/enisdenjo/graphql-ws) against `wss://…/graphql/ws` (see `hubGraphqlWsUrl()`). Each call opens a WebSocket, sends optional JWT from `connection_init`, and returns a **dispose** function for cleanup.
- **TypeScript support:** Type-safe interfaces for all major methods and transaction types.

## Installation
```bash
npm install clutch-hub-sdk-js
```

### Latest Version
You can also install the latest canary version for cutting-edge features:
```bash
npm install clutch-hub-sdk-js@canary
```

## Basic Usage
```js
import { ClutchHubSdk } from 'clutch-hub-sdk-js';

const sdk = new ClutchHubSdk('https://your-hub-api-url');

// 1. Fetch the next nonce for the user
const nonce = await sdk.getNextNonce(userAddress);

// 2. Build a ride request transaction
const tx = sdk.buildRideRequestTx({
  pickup: { latitude: 35.7, longitude: 51.4 },
  dropoff: { latitude: 35.8, longitude: 51.5 },
  fare: 1000
}, userAddress, nonce);

// 3. Sign the transaction (using user's private key)
const { r, s, v } = await sdk.signTx(tx, userPrivateKey);

// 4. Submit the signed transaction
const receipt = await sdk.sendTransaction({
  from: userAddress,
  nonce,
  payload: tx,
  r, s, v
});

console.log('Transaction receipt:', receipt);
```

## Security Note
**Never share or expose your private key.** The SDK is designed for client-side signing only. For best security, integrate with browser wallets, hardware wallets, or secure mobile keystores.

## Development & Releases

This project uses [semantic-release](https://semantic-release.gitbook.io/) for automated versioning and publishing.

### Commit Message Format

Use [Conventional Commits](https://conventionalcommits.org/) for automatic version bumping:

```bash
# Patch release (0.1.0 → 0.1.1)
git commit -m "fix: resolve memory leak in transaction processing"

# Minor release (0.1.0 → 0.2.0)  
git commit -m "feat: add ride cancellation functionality"

# Major release (0.1.0 → 1.0.0)
git commit -m "feat!: change API signature for ClutchHubSdk constructor"

# No release
git commit -m "docs: update README with new examples"
git commit -m "chore: update dependencies"
```

### Release Process

1. **Automatic Releases**: Merge commits to `main` with conventional commit messages
2. **Canary Releases**: Non-conventional commits create canary versions (`0.1.0-canary.abc1234`)
3. **Manual Releases**: Push git tags (`v1.0.0`) for manual version control

### Commit Message Template

Set up the commit message template:
```bash
git config commit.template .gitmessage
```

## Author & Maintainer

**Mehran Mazhar**
- GitHub: [@MehranMazhar](https://github.com/MehranMazhar)
- Website: [MehranMazhar.com](https://MehranMazhar.com)
- Email: mehran.mazhar@gmail.com

## License
MIT
