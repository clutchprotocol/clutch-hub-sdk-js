import axios, { AxiosInstance } from 'axios';
import { Buffer } from 'buffer';
import type { Client } from 'graphql-ws';
import { keccak_256 } from '@noble/hashes/sha3';
import * as rlp from 'rlp';
import * as secp from '@noble/secp256k1';
import {
  ACTIVE_TRIP_GQL_FIELDS,
  createHubSubscriptionClient,
  hubGraphqlWsUrl,
  RECENT_TRIP_GQL_FIELDS,
  RIDE_OFFER_GQL_FIELDS,
  RIDE_REQUEST_GQL_FIELDS,
  type SubscriptionHandlers,
} from './subscriptions.js';
import {
  AvailableRideRequest,
  AvailableRideOffer,
  AvailableActiveTrip,
  AvailableCompletedTrip,
  AvailableRecentTrip,
  BurnArgs,
  FaucetResponse,
  MapBounds,
  RideRequestArgs,
  RideOfferArgs,
  RideAcceptanceArgs,
  RidePayArgs,
  RideCancelArgs,
  RideRequestCancelArgs,
  Signature,
} from './types.js';

/** Strip 0x/0X prefix - hex parsers (e.g. @noble/secp256k1) do not accept it. Exported for consumers. */
export function stripHexPrefix(hex: string): string {
  return hex.replace(/^0x/i, '');
}

/**
 * Prepare a tx hash for RLP: strip accidental JSON wrapping (legacy node stored `"0x…"` as a JSON string)
 * and remove the `0x` prefix.
 */
export function normalizeTxHashForRlp(hex: string): string {
  let s = String(hex).trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    try {
      const parsed = JSON.parse(s);
      if (typeof parsed === 'string') {
        s = parsed;
      } else {
        s = s.slice(1, -1);
      }
    } catch {
      s = s.slice(1, -1);
    }
  }
  return stripHexPrefix(s);
}

// Expose Buffer to browser contexts
declare global {
  interface Window { Buffer: typeof Buffer }
}
if (typeof window !== 'undefined' && !window.Buffer) {
  window.Buffer = Buffer;
}

type TokenCacheEntry = {
  token: string;
  /** Epoch milliseconds when the JWT should be considered expired */
  expireTimeMs: number;
};

/**
 * Global JWT cache keyed by `publicKey`.
 * This prevents every `new ClutchHubSdk(...)` instance from repeatedly calling `generateToken`.
 */
const globalTokenCache = new Map<string, TokenCacheEntry>();

/**
 * Deduplicate concurrent `generateToken` calls per `publicKey`.
 */
const inFlightTokenRequests = new Map<string, Promise<TokenCacheEntry>>();

/**
 * Module-global private-key store keyed by `publicKey` (parallel to the JWT cache).
 * `generateToken` requires proof of key ownership (a signed challenge), so token issuance
 * needs the wallet's private key. Keys are kept in memory only and are **never** sent to
 * the Hub API — only the challenge signature is.
 */
const globalPrivateKeys = new Map<string, string>();

/** Prefix of the canonical proof-of-key-ownership message signed for `generateToken`. */
export const AUTH_CHALLENGE_PREFIX = 'clutch-auth';

/**
 * Canonical auth challenge message for `generateToken`. Must match clutch-hub-api
 * (`hub::auth::build_auth_challenge_message`) byte-for-byte: `clutch-auth:{chainId}:{publicKey}:{timestamp}`.
 * `chainId` binds the signed challenge to this hub's chain — without it, a challenge captured
 * on one chain would authenticate the same key on any other Clutch hub within the clock-skew
 * window. Breaking change from the pre-treasury (chainId-less) format; no fallback.
 */
export function buildAuthChallengeMessage(chainId: number, publicKey: string, timestamp: number): string {
  return `${AUTH_CHALLENGE_PREFIX}:${chainId}:${publicKey}:${timestamp}`;
}

/**
 * Keccak-256 of the canonical auth message as 64-char lowercase hex (no 0x).
 * The signature is then computed over the UTF-8 bytes of this hex string (see `signHashHex`),
 * the same convention used for transaction hashes.
 */
export function authChallengeHashHex(chainId: number, publicKey: string, timestamp: number): string {
  const message = buildAuthChallengeMessage(chainId, publicKey, timestamp);
  return Buffer.from(keccak_256(Buffer.from(message, 'utf8'))).toString('hex');
}

/**
 * Signs a hash-hex string the way the Rust node/hub verify:
 * - message_hash = Keccak256(hashHex.as_utf8_bytes()) — i.e. over the hex *string*, not its bytes
 * - recoverable secp256k1 over that message_hash; v = recovery id + 27
 */
async function signHashHex(hashHex: string, privateKey: string): Promise<Signature> {
  const privKeyClean = stripHexPrefix(privateKey);
  const messageHash = keccak_256(Buffer.from(hashHex, 'utf8'));
  const sig = await secp.signAsync(messageHash, privKeyClean);
  const r = sig.r.toString(16).padStart(64, '0');
  const s = sig.s.toString(16).padStart(64, '0');
  const v = (typeof sig.recovery === 'number' ? sig.recovery : 0) + 27;
  return {
    r: '0x' + r,
    s: '0x' + s,
    v,
  };
}

/**
 * Sign the `generateToken` proof-of-key-ownership challenge.
 * @param timestamp Unix seconds; the Hub API rejects timestamps more than ±120s from server time.
 */
export async function signAuthChallenge(
  chainId: number,
  publicKey: string,
  timestamp: number,
  privateKey: string
): Promise<Signature> {
  return signHashHex(authChallengeHashHex(chainId, publicKey, timestamp), privateKey);
}

type SharedGraphqlWsEntry = { client: Client; refcount: number };

/**
 * One graphql-ws connection per hub URL + wallet; multiplex all subscriptions on it.
 * Without this, each subscribe* call opened a new socket (`lazy: false`), which explodes
 * when the app mounts several subscriptions or switches views that create new SDKs.
 */
const sharedGraphqlWsClients = new Map<string, SharedGraphqlWsEntry>();

function sharedGraphqlWsCacheKey(baseURL: string, publicKey: string): string {
  return `${baseURL.replace(/\/$/, '')}\0${publicKey}`;
}

/**
 * Resolve a valid JWT for `publicKey` into the global cache (and return it), generating one
 * via the `generateToken` mutation when needed. Shared by `ensureAuth` and the WebSocket
 * `connectionParams` so all SDK instances and subscriptions share tokens.
 *
 * Token issuance signs the proof-of-key-ownership challenge, so a private key for
 * `publicKey` must have been provided (constructor or `setPrivateKey`) unless a cached
 * token is still valid.
 */
async function ensureTokenInCacheForPublicKey(
  publicKey: string,
  apiClient: AxiosInstance,
  chainId: number
): Promise<TokenCacheEntry> {
  const now = Date.now();
  const bufferTime = 30000;

  const cached = globalTokenCache.get(publicKey);
  if (cached && now < cached.expireTimeMs - bufferTime) {
    return cached;
  }

  const existingInFlight = inFlightTokenRequests.get(publicKey);
  if (existingInFlight) {
    return existingInFlight;
  }

  const privateKey = globalPrivateKeys.get(publicKey);
  if (!privateKey) {
    throw new Error(
      `ClutchHubSdk: generateToken requires proof of key ownership; provide the private key for ${publicKey} via the ClutchHubSdk constructor or setPrivateKey().`
    );
  }

  const query = `
    mutation GenerateToken($publicKey: String!, $timestamp: Int!, $signature: AuthSignatureInput!) {
      generateToken(publicKey: $publicKey, timestamp: $timestamp, signature: $signature) {
        token
        expiresAt
      }
    }
  `;

  const requestPromise: Promise<TokenCacheEntry> = (async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await signAuthChallenge(chainId, publicKey, timestamp, privateKey);
    const response = await apiClient.post<{ data?: unknown; errors?: { message: string }[] }>(
      '/graphql',
      {
        query,
        variables: {
          publicKey,
          timestamp,
          signature: { r: signature.r, s: signature.s, v: signature.v },
        },
      }
    );
    const body = response.data as { errors?: { message: string }[]; data?: { generateToken: { token: string; expiresAt: number } } };
    if (body.errors?.length) {
      throw new Error(body.errors.map((e) => e.message).join('\n'));
    }
    if (!body.data?.generateToken) {
      throw new Error('No data returned from GraphQL.');
    }
    const entry: TokenCacheEntry = {
      token: body.data.generateToken.token,
      expireTimeMs: body.data.generateToken.expiresAt * 1000,
    };
    globalTokenCache.set(publicKey, entry);
    return entry;
  })();

  inFlightTokenRequests.set(publicKey, requestPromise);
  try {
    return await requestPromise;
  } finally {
    inFlightTokenRequests.delete(publicKey);
  }
}

/**
 * Represents an unsigned transaction returned by the GraphQL API.
 */
export interface UnsignedTransaction {
  data: any;
  from: string;
  nonce: number;
  /** u64 on the wire; kept as `number` here since real chain ids fit well under 2^53. */
  chain_id: number;
}

/**
 * Expectations `signTransaction` verifies an unsigned blob against before signing it — see
 * `verifyUnsignedTransaction`. The hub is untrusted in this design (that's the entire point of
 * client-side signing), so a caller who knows what it asked for should say so and have the SDK
 * check the hub's answer instead of signing it blind.
 */
export interface ExpectedTx {
  type: 'RideRequest' | 'RideOffer' | 'RidePay' | 'RideAcceptance' | 'RideCancel' | 'RideRequestCancel' | 'Burn';
  /** The wallet's own address/pk form; `signTransaction` fills this in automatically. */
  from?: string;
  /** Pinned CLIENT-side (app config, e.g. 2077) — never sourced from the hub's own `chainInfo`. */
  chainId?: number;
  /** RideRequest/RideOffer/RidePay. */
  fare?: bigint;
  /** Burn. */
  amount?: bigint;
  /** The acceptance/offer/request hash the caller itself passed in. */
  refTxHash?: string;
  /** Burn. */
  redemptionRef?: string;
}

/**
 * Result of a passing `verifyUnsignedTransaction` check.
 */
export interface VerifiedTx {
  /**
   * The referrer the hub injected into this transaction, if any. The hub picks the referrer
   * server-side and there is currently no signed-quote flow to pin it client-side, so this
   * value CANNOT be verified — it is surfaced only so a caller can display it to the user
   * before they sign. Displaying it is the interim mitigation, not a fix; full referrer
   * pinning needs the signed-quote flow (a later plan).
   */
  referrer: string | null;
}

/** Reads `arguments.<snake>` falling back to `arguments.<camel>`, matching `encodeFunctionCall`'s tolerance for either shape. */
function readArg(argsData: any, snakeKey: string, camelKey: string): unknown {
  return argsData?.[snakeKey] ?? argsData?.[camelKey];
}

/**
 * The reference-hash field each transaction type carries, if any (mirrors the cases in
 * `encodeFunctionCall`). Returns `undefined` for types with no single reference hash
 * (RideRequest, Burn).
 */
function refHashFromArgs(type: ExpectedTx['type'], argsData: any): string | undefined {
  switch (type) {
    case 'RideOffer':
      return readArg(argsData, 'ride_request_transaction_hash', 'rideRequestTxHash') as string | undefined;
    case 'RideAcceptance':
      return readArg(argsData, 'ride_offer_transaction_hash', 'rideOfferTxHash') as string | undefined;
    case 'RidePay':
      return readArg(argsData, 'ride_acceptance_transaction_hash', 'rideAcceptanceTxHash') as string | undefined;
    case 'RideCancel':
      return readArg(argsData, 'ride_acceptance_transaction_hash', 'rideAcceptanceTxHash') as string | undefined;
    case 'RideRequestCancel':
      return readArg(argsData, 'ride_request_transaction_hash', 'rideRequestTxHash') as string | undefined;
    default:
      return undefined;
  }
}

/**
 * Verify an unsigned-transaction blob from the hub against what the caller actually asked for,
 * before it gets signed. Pure and side-effect-free.
 *
 * WHY THIS EXISTS: the hub is the untrusted party in this design — the private key never
 * leaves the client precisely because the hub is not trusted — yet without this check a
 * compromised hub can alter the fare, swap the referrer, or hand back a different chain's id,
 * and the SDK would sign whatever it was given. This closes the blind-signing hole for every
 * field it's possible to pin client-side. It does NOT close the referrer hole (see
 * `VerifiedTx.referrer`).
 *
 * Any mismatch throws `Error('unsigned tx does not match request: <field>')` naming the
 * offending field.
 */
export function verifyUnsignedTransaction(
  unsignedTx: UnsignedTransaction,
  expected: ExpectedTx
): VerifiedTx {
  const fail = (field: string): never => {
    throw new Error(`unsigned tx does not match request: ${field}`);
  };

  if (expected.from !== undefined && stripHexPrefix(unsignedTx.from).toLowerCase() !== stripHexPrefix(expected.from).toLowerCase()) {
    fail('from');
  }

  // Presence-only checking would let a compromised hub hand back a different chain's id and
  // defeat the exact replay protection chain_id was added to close — so this is a strict
  // equality check whenever the caller pinned a chainId, not merely "is chain_id present".
  if (expected.chainId !== undefined && Number(unsignedTx.chain_id) !== expected.chainId) {
    fail('chain_id');
  }

  const type = (unsignedTx.data?.function_call_type ?? unsignedTx.data?.type) as ExpectedTx['type'] | undefined;
  if (type !== expected.type) {
    fail('function_call_type');
  }

  const argsData = unsignedTx.data?.arguments ?? unsignedTx.data ?? {};

  if (expected.fare !== undefined) {
    const fareRaw = readArg(argsData, 'fare', 'fare');
    if (fareRaw === undefined || BigInt(fareRaw as string | number | bigint) !== expected.fare) {
      fail('fare');
    }
  }

  if (expected.amount !== undefined) {
    const amountRaw = readArg(argsData, 'amount', 'amount');
    if (amountRaw === undefined || BigInt(amountRaw as string | number | bigint) !== expected.amount) {
      fail('amount');
    }
  }

  if (expected.refTxHash !== undefined) {
    const actualRef = refHashFromArgs(expected.type, argsData);
    if (actualRef === undefined || normalizeTxHashForRlp(String(actualRef)) !== normalizeTxHashForRlp(expected.refTxHash)) {
      fail('refTxHash');
    }
  }

  if (expected.redemptionRef !== undefined) {
    const actualRefRaw = readArg(argsData, 'redemption_ref', 'redemptionRef');
    const actualRef = actualRefRaw != null && String(actualRefRaw).length > 0 ? String(actualRefRaw) : '';
    if (actualRef !== expected.redemptionRef) {
      fail('redemptionRef');
    }
  }

  const referrerRaw = argsData?.referrer;
  const referrer = referrerRaw != null && String(referrerRaw).length > 0 ? String(referrerRaw) : null;
  return { referrer };
}

/**
 * SDK for interacting with the Clutch Hub API and signing transactions.
 * Provides client-side transaction signing and blockchain interaction capabilities.
 */
export class ClutchHubSdk {
  private apiClient: AxiosInstance;
  private publicKey: string;
  private token: string | null = null;
  private tokenExpireTime: number = 0;
  private chainId: number;
  /** Whether the caller actually passed a `chainId` (vs. the 0 default) — see `signTransaction`. */
  private chainIdConfigured: boolean;

  /**
   * @param apiUrl Hub API base URL.
   * @param publicKey Wallet address (0x + 40 hex) or uncompressed public key (130 hex).
   * @param privateKey Optional wallet private key, required to obtain JWTs: `generateToken`
   *   demands a signed proof-of-key-ownership challenge. May also be provided later via
   *   {@link setPrivateKey}. Never sent to the API — only used for local signing.
   * @param chainId This chain's id (e.g. 2077 for the app's own config), used for the
   *   chain-bound auth challenge and as the default `expected.chainId` pin in
   *   {@link signTransaction}'s `verifyUnsignedTransaction` check. Get this from app config,
   *   never from the hub's own `chainInfo` response — asking the untrusted party what chain
   *   it is defeats the check chain_id exists to provide. If omitted, `signTransaction` still
   *   verifies every other `expected` field but skips the chain_id pin (nothing was pinned to
   *   check against) rather than failing every real transaction against a phantom "chain 0".
   */
  constructor(apiUrl: string, publicKey: string, privateKey?: string, chainId?: number) {
    this.apiClient = axios.create({ baseURL: apiUrl });
    this.publicKey = publicKey;
    this.chainId = chainId ?? 0;
    this.chainIdConfigured = chainId !== undefined;
    if (privateKey) {
      globalPrivateKeys.set(publicKey, privateKey);
    }
  }

  /**
   * Get the current public key associated with this SDK instance.
   * @returns The public key string
   */
  public getPublicKey(): string {
    return this.publicKey;
  }

  /**
   * Provide (or replace) the private key used to sign `generateToken` auth challenges for
   * this SDK's public key. Stored in a module-global map keyed by publicKey — like the JWT
   * cache — so every SDK instance and shared WebSocket connection for this wallet can
   * authenticate. In-memory only; never sent to the API.
   */
  public setPrivateKey(privateKey: string): void {
    globalPrivateKeys.set(this.publicKey, privateKey);
  }

  /**
   * Check if the SDK is currently authenticated.
   * @returns True if authenticated and token is not expired
   */
  public isAuthenticated(): boolean {
    const now = Date.now();
    const bufferTime = 30000; // 30 seconds
    return !!(this.token && now < (this.tokenExpireTime - bufferTime));
  }

  private get authHeaders(): Record<string, string> {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }

  /**
   * WebSocket URL for GraphQL subscriptions (same host as REST/GraphQL HTTP).
   */
  public getGraphqlWsUrl(): string {
    const base = this.apiClient.defaults.baseURL;
    if (!base) {
      throw new Error('ClutchHubSdk: missing API base URL');
    }
    return hubGraphqlWsUrl(base);
  }

  /**
   * Acquire the shared graphql-ws client for this hub + public key.
   * Call `release` when unsubscribing; last release disposes the socket.
   */
  private acquireGraphqlWsClient(): { client: Client; release: () => void } {
    const base = this.apiClient.defaults.baseURL;
    if (!base) {
      throw new Error('ClutchHubSdk: missing API base URL');
    }
    const key = sharedGraphqlWsCacheKey(base, this.publicKey);
    let entry = sharedGraphqlWsClients.get(key);
    if (!entry) {
      const pk = this.publicKey;
      const apiClient = this.apiClient;
      const chainId = this.chainId;
      const client = createHubSubscriptionClient({
        url: hubGraphqlWsUrl(base),
        connectionParams: async () => {
          try {
            await ensureTokenInCacheForPublicKey(pk, apiClient, chainId);
          } catch {
            /* public list subscriptions work without JWT */
          }
          const c = globalTokenCache.get(pk);
          return c?.token ? { Authorization: `Bearer ${c.token}` } : {};
        },
      });
      entry = { client, refcount: 0 };
      sharedGraphqlWsClients.set(key, entry);
    }
    entry.refcount += 1;
    const release = () => {
      const e = sharedGraphqlWsClients.get(key);
      if (!e) {
        return;
      }
      e.refcount -= 1;
      if (e.refcount <= 0) {
        e.client.dispose();
        sharedGraphqlWsClients.delete(key);
      }
    };
    return { client: entry.client, release };
  }

  /**
   * Shared graphql-ws list subscription: one multiplexed client via {@link acquireGraphqlWsClient}.
   */
  private subscribeGraphqlListField<T>(
    query: string,
    variables: Record<string, unknown>,
    responseField: string,
    handlers: SubscriptionHandlers<T[]>
  ): () => void {
    const { client, release } = this.acquireGraphqlWsClient();
    const disposeSub = client.subscribe(
      { query, variables },
      {
        next: (res) => {
          const root = res.data as Record<string, T[] | undefined> | null | undefined;
          const items = root?.[responseField];
          if (items) {
            handlers.onData(items);
          }
        },
        error: (err) => handlers.onError?.(err as Error),
        complete: () => {},
      }
    );
    return () => {
      disposeSub();
      release();
    };
  }

  private async executeGraphQL<T>(query: string, variables: any): Promise<T> {
    const response = await this.apiClient.post(
      '/graphql',
      { query, variables },
      { headers: this.authHeaders }
    );
    if (response.data.errors) {
      throw new Error(response.data.errors.map((e: any) => e.message).join('\n'));
    }
    if (!response.data.data) {
      throw new Error('No data returned from GraphQL.');
    }
    return response.data.data as T;
  }

  private async ensureAuth(): Promise<void> {
    const entry = await ensureTokenInCacheForPublicKey(this.publicKey, this.apiClient, this.chainId);
    this.token = entry.token;
    this.tokenExpireTime = entry.expireTimeMs;
  }

  /**
   * Public wrapper around `ensureAuth`: resolves (fetching if needed) a valid JWT for this
   * wallet and returns it as an `Authorization: Bearer <token>` header ready to attach to a
   * hand-rolled request (e.g. an orchestrator REST client that reuses this SDK's auth).
   */
  public async getAuthHeaders(): Promise<Record<string, string>> {
    await this.ensureAuth();
    return { ...this.authHeaders };
  }

  /**
   * Fetches an unsigned ride request transaction from the GraphQL API.
   */
  public async createUnsignedRideRequest(
    args: RideRequestArgs
  ): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const pickupLat = (args.pickup as any).latitude ?? (args.pickup as any).lat;
    const pickupLng = (args.pickup as any).longitude ?? (args.pickup as any).lng;
    const dropoffLat = (args.dropoff as any).latitude ?? (args.dropoff as any).lat;
    const dropoffLng = (args.dropoff as any).longitude ?? (args.dropoff as any).lng;

    const query = `
      mutation CreateUnsignedRideRequest(
        $pickupLatitude: Float!, $pickupLongitude: Float!,
        $dropoffLatitude: Float!, $dropoffLongitude: Float!, $fare: String!
      ) {
        createUnsignedRideRequest(
          pickupLatitude: $pickupLatitude,
          pickupLongitude: $pickupLongitude,
          dropoffLatitude: $dropoffLatitude,
          dropoffLongitude: $dropoffLongitude,
          fare: $fare
        )
      }
    `;
    const variables = {
      pickupLatitude: pickupLat,
      pickupLongitude: pickupLng,
      dropoffLatitude: dropoffLat,
      dropoffLongitude: dropoffLng,
      fare: args.fare.toString(),
    };
    const result = await this.executeGraphQL<{
      createUnsignedRideRequest: UnsignedTransaction
    }>(query, variables);
    return result.createUnsignedRideRequest;
  }

  /**
   * Fetches an unsigned ride offer transaction from the GraphQL API.
   * Driver offers to fulfill a ride request at the specified fare.
   */
  public async createUnsignedRideOffer(
    args: RideOfferArgs
  ): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const query = `
      mutation CreateUnsignedRideOffer(
        $rideRequestTransactionHash: String!, $fare: String!
      ) {
        createUnsignedRideOffer(
          rideRequestTransactionHash: $rideRequestTransactionHash,
          fare: $fare
        )
      }
    `;
    const variables = {
      rideRequestTransactionHash: args.rideRequestTxHash,
      fare: args.fare.toString(),
    };
    const result = await this.executeGraphQL<{
      createUnsignedRideOffer: UnsignedTransaction
    }>(query, variables);
    return result.createUnsignedRideOffer;
  }

  /**
   * Fetches an unsigned ride acceptance transaction from the GraphQL API.
   * Passenger confirms a driver's offer for their ride request.
   */
  public async createUnsignedRideAcceptance(
    args: RideAcceptanceArgs
  ): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const query = `
      mutation CreateUnsignedRideAcceptance($rideOfferTransactionHash: String!) {
        createUnsignedRideAcceptance(rideOfferTransactionHash: $rideOfferTransactionHash)
      }
    `;
    const variables = {
      rideOfferTransactionHash: args.rideOfferTxHash,
    };
    const result = await this.executeGraphQL<{
      createUnsignedRideAcceptance: UnsignedTransaction
    }>(query, variables);
    return result.createUnsignedRideAcceptance;
  }

  /**
   * Fetches an unsigned RidePay transaction. Passenger pays the driver in portions until the offer fare is covered.
   */
  public async createUnsignedRidePay(args: RidePayArgs): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const query = `
      mutation CreateUnsignedRidePay(
        $rideAcceptanceTransactionHash: String!,
        $fare: String!
      ) {
        createUnsignedRidePay(
          rideAcceptanceTransactionHash: $rideAcceptanceTransactionHash,
          fare: $fare
        )
      }
    `;
    const variables = {
      rideAcceptanceTransactionHash: args.rideAcceptanceTxHash,
      fare: args.fare.toString(),
    };
    const result = await this.executeGraphQL<{
      createUnsignedRidePay: UnsignedTransaction;
    }>(query, variables);
    return result.createUnsignedRidePay;
  }

  /**
   * Fetches an unsigned RideCancel transaction. Either passenger or driver may cancel an active ride.
   * Refunds unpaid fare to the passenger. Cannot cancel if full fare has already been paid.
   */
  public async createUnsignedRideCancel(args: RideCancelArgs): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const query = `
      mutation CreateUnsignedRideCancel($rideAcceptanceTransactionHash: String!) {
        createUnsignedRideCancel(rideAcceptanceTransactionHash: $rideAcceptanceTransactionHash)
      }
    `;
    const variables = {
      rideAcceptanceTransactionHash: args.rideAcceptanceTxHash,
    };
    const result = await this.executeGraphQL<{
      createUnsignedRideCancel: UnsignedTransaction;
    }>(query, variables);
    return result.createUnsignedRideCancel;
  }

  /**
   * Fetches an unsigned RideRequestCancel transaction. Cancels a pending ride request before a driver accepts.
   * Only the passenger who created the request can cancel.
   */
  public async createUnsignedRideRequestCancel(args: RideRequestCancelArgs): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const query = `
      mutation CreateUnsignedRideRequestCancel($rideRequestTransactionHash: String!) {
        createUnsignedRideRequestCancel(rideRequestTransactionHash: $rideRequestTransactionHash)
      }
    `;
    const variables = {
      rideRequestTransactionHash: args.rideRequestTxHash,
    };
    const result = await this.executeGraphQL<{
      createUnsignedRideRequestCancel: UnsignedTransaction;
    }>(query, variables);
    return result.createUnsignedRideRequestCancel;
  }

  /**
   * Fetches an unsigned Burn transaction. Burns `amount` CLT from the caller's balance,
   * optionally tagged with a treasury `redemptionRef` (hex(keccak256(intent_id))).
   */
  public async createUnsignedBurn(args: BurnArgs): Promise<UnsignedTransaction> {
    await this.ensureAuth();
    const query = `
      mutation CreateUnsignedBurn($amount: String!, $redemptionRef: String) {
        createUnsignedBurn(amount: $amount, redemptionRef: $redemptionRef)
      }
    `;
    const variables = {
      amount: args.amount.toString(),
      redemptionRef: args.redemptionRef ?? null,
    };
    const result = await this.executeGraphQL<{
      createUnsignedBurn: UnsignedTransaction;
    }>(query, variables);
    return result.createUnsignedBurn;
  }

  /**
   * Signs a transaction and returns the signature and raw RLP-encoded payload.
   */
  public async signTransaction(
    unsignedTx: UnsignedTransaction,
    privateKey: string,
    expected?: ExpectedTx
  ): Promise<Signature & { rawTransaction: string, txHash: string }> {
    if (expected) {
      // Inject the checks the caller gets "for free": its own address form, and this SDK
      // instance's pinned chainId IF the constructor was actually given one — an unconfigured
      // chainId means nothing was pinned, so there's nothing to check (as opposed to silently
      // enforcing a phantom "chain 0" against every real chain_id). Mismatch throws before
      // anything is signed.
      verifyUnsignedTransaction(unsignedTx, {
        ...expected,
        from: expected.from ?? this.publicKey,
        chainId: expected.chainId ?? (this.chainIdConfigured ? this.chainId : undefined),
      });
    }

    // Encode the function call into a nested array for RLP
    const callDataArray = this.encodeFunctionCall(unsignedTx.data);

    // RLP-encode unsigned transaction [from (no 0x), nonce, chain_id, data] — node Plan A
    // format. chain_id sits between nonce and data in BOTH the hash preimage and the full
    // signed payload below; the node's `calculate_hash` computes this exact 4-item list.
    const fromForUnsigned = stripHexPrefix(unsignedTx.from);
    const unsignedPayload = rlp.encode([
      fromForUnsigned,
      unsignedTx.nonce,
      unsignedTx.chain_id,
      callDataArray
    ]);
    const hashBytes = keccak_256(unsignedPayload);
    const rawHashHex = Buffer.from(hashBytes).toString('hex');

    // Sign the transaction hash
    const signature = await signHashHex(rawHashHex, privateKey);
    const rNo0x = stripHexPrefix(signature.r);
    const sNo0x = stripHexPrefix(signature.s);

    // RLP-encode full signed transaction to match Rust: [from, nonce, chain_id, r, s, v, hash, data]
    // — chain_id inserted after nonce, same index as the unsigned preimage; everything after
    // it shifts by one versus the pre-treasury 7-item wire format.
    const fromNo0x = stripHexPrefix(unsignedTx.from);
    const fullPayload = rlp.encode([
      fromNo0x,
      unsignedTx.nonce,
      unsignedTx.chain_id,
      rNo0x,
      sNo0x,
      signature.v,
      rawHashHex,
      callDataArray
    ]);

    return {
      ...signature,
      rawTransaction: '0x' + Buffer.from(fullPayload).toString('hex'),
      txHash: '0x' + rawHashHex
    };
  }

  /**
   * Submits a signed raw transaction to the network.
   */
  public async submitTransaction(
    rawTransaction: string
  ): Promise<string> {
    await this.ensureAuth();
    const query = `
      mutation SendRawTransaction($raw_transaction: String!) {
        sendRawTransaction(rawTransaction: $raw_transaction)
      }
    `;
    const result = await this.executeGraphQL<{
      sendRawTransaction: string;
    }>(query, { raw_transaction: rawTransaction });
    return result.sendRawTransaction;
  }

  /**
   * Subscribe to periodic snapshots of available ride requests (graphql-ws).
   * @returns Dispose function to stop the subscription and release the shared client refcount.
   */
  public subscribeRideRequests(
    bounds: MapBounds | null | undefined,
    handlers: SubscriptionHandlers<AvailableRideRequest[]>
  ): () => void {
    const query = `
      subscription RideRequestsUpdated($bounds: MapBoundsInput) {
        rideRequestsUpdated(bounds: $bounds) {
          ${RIDE_REQUEST_GQL_FIELDS}
        }
      }
    `;
    return this.subscribeGraphqlListField<AvailableRideRequest>(
      query,
      { bounds: bounds ?? null },
      'rideRequestsUpdated',
      handlers
    );
  }

  /**
   * Subscribe to ride offers for a single ride request tx hash.
   */
  public subscribeRideOffers(
    rideRequestTxHash: string,
    handlers: SubscriptionHandlers<AvailableRideOffer[]>
  ): () => void {
    const query = `
      subscription RideOffersUpdated($rideRequestTxHash: String!) {
        rideOffersUpdated(rideRequestTxHash: $rideRequestTxHash) {
          ${RIDE_OFFER_GQL_FIELDS}
        }
      }
    `;
    return this.subscribeGraphqlListField<AvailableRideOffer>(
      query,
      { rideRequestTxHash },
      'rideOffersUpdated',
      handlers
    );
  }

  /**
   * Subscribe to active trips, optionally filtered by driver or passenger address.
   */
  public subscribeActiveTrips(
    options: { driverAddress?: string; passengerAddress?: string } | undefined,
    handlers: SubscriptionHandlers<AvailableActiveTrip[]>
  ): () => void {
    const query = `
      subscription ActiveTripsUpdated($driverAddress: String, $passengerAddress: String) {
        activeTripsUpdated(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          ${ACTIVE_TRIP_GQL_FIELDS}
        }
      }
    `;
    return this.subscribeGraphqlListField<AvailableActiveTrip>(
      query,
      {
        driverAddress: options?.driverAddress ?? null,
        passengerAddress: options?.passengerAddress ?? null,
      },
      'activeTripsUpdated',
      handlers
    );
  }

  /**
   * Subscribe to completed trips, optionally filtered by driver or passenger address.
   */
  public subscribeCompletedTrips(
    options: { driverAddress?: string; passengerAddress?: string } | undefined,
    handlers: SubscriptionHandlers<AvailableCompletedTrip[]>
  ): () => void {
    const query = `
      subscription CompletedTripsUpdated($driverAddress: String, $passengerAddress: String) {
        completedTripsUpdated(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          ${ACTIVE_TRIP_GQL_FIELDS}
        }
      }
    `;
    return this.subscribeGraphqlListField<AvailableCompletedTrip>(
      query,
      {
        driverAddress: options?.driverAddress ?? null,
        passengerAddress: options?.passengerAddress ?? null,
      },
      'completedTripsUpdated',
      handlers
    );
  }

  /**
   * Subscribe to recent finished trips (completed or cancelled), optionally filtered by driver or passenger.
   */
  public subscribeRecentTrips(
    options: { driverAddress?: string; passengerAddress?: string } | undefined,
    handlers: SubscriptionHandlers<AvailableRecentTrip[]>
  ): () => void {
    const query = `
      subscription RecentTripsUpdated($driverAddress: String, $passengerAddress: String) {
        recentTripsUpdated(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          ${RECENT_TRIP_GQL_FIELDS}
        }
      }
    `;
    return this.subscribeGraphqlListField<AvailableRecentTrip>(
      query,
      {
        driverAddress: options?.driverAddress ?? null,
        passengerAddress: options?.passengerAddress ?? null,
      },
      'recentTripsUpdated',
      handlers
    );
  }

  public async listRideRequests(bounds?: MapBounds | null): Promise<AvailableRideRequest[]> {
    const query = `
      query ListRideRequests($bounds: MapBoundsInput) {
        listRideRequests(bounds: $bounds) {
          txHash
          pickupLocation { latitude longitude }
          dropoffLocation { latitude longitude }
          fare
          passengerAddress
        }
      }
    `;
    const result = await this.executeGraphQL<{
      listRideRequests: (Omit<AvailableRideRequest, 'fare'> & { fare: string })[];
    }>(query, { bounds: bounds ?? null });
    return result.listRideRequests.map((r) => ({ ...r, fare: BigInt(r.fare) }));
  }

  /**
   * Lists ride offers for a specific ride request.
   * @param rideRequestTxHash The transaction hash of the ride request
   * @returns Array of available ride offers
   */
  public async listRideOffers(rideRequestTxHash: string): Promise<AvailableRideOffer[]> {
    const query = `
      query ListRideOffers($rideRequestTxHash: String!) {
        listRideOffers(rideRequestTxHash: $rideRequestTxHash) {
          txHash
          rideRequestTxHash
          fare
          driverAddress
        }
      }
    `;
    const result = await this.executeGraphQL<{
      listRideOffers: (Omit<AvailableRideOffer, 'fare'> & { fare: string })[];
    }>(query, { rideRequestTxHash });
    return result.listRideOffers.map((r) => ({ ...r, fare: BigInt(r.fare) }));
  }

  /**
   * Lists active trips (ride accepted, in progress).
   * Optionally filter by driver or passenger address.
   */
  public async listActiveTrips(options?: {
    driverAddress?: string;
    passengerAddress?: string;
  }): Promise<AvailableActiveTrip[]> {
    const query = `
      query ListActiveTrips($driverAddress: String, $passengerAddress: String) {
        listActiveTrips(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          txHash
          rideOfferTxHash
          rideRequestTxHash
          pickupLocation { latitude longitude }
          dropoffLocation { latitude longitude }
          fare
          farePaid
          driverAddress
          passengerAddress
        }
      }
    `;
    const result = await this.executeGraphQL<{
      listActiveTrips: (Omit<AvailableActiveTrip, 'fare' | 'farePaid'> & { fare: string; farePaid: string })[];
    }>(query, {
      driverAddress: options?.driverAddress ?? null,
      passengerAddress: options?.passengerAddress ?? null,
    });
    return result.listActiveTrips.map((r) => ({ ...r, fare: BigInt(r.fare), farePaid: BigInt(r.farePaid) }));
  }

  /**
   * Lists completed trips (accepted, full fare paid, not cancelled).
   * Optionally filter by driver or passenger address.
   */
  public async listCompletedTrips(options?: {
    driverAddress?: string;
    passengerAddress?: string;
  }): Promise<AvailableCompletedTrip[]> {
    const query = `
      query ListCompletedTrips($driverAddress: String, $passengerAddress: String) {
        listCompletedTrips(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          txHash
          rideOfferTxHash
          rideRequestTxHash
          pickupLocation { latitude longitude }
          dropoffLocation { latitude longitude }
          fare
          farePaid
          driverAddress
          passengerAddress
        }
      }
    `;
    const result = await this.executeGraphQL<{
      listCompletedTrips: (Omit<AvailableCompletedTrip, 'fare' | 'farePaid'> & { fare: string; farePaid: string })[];
    }>(query, {
      driverAddress: options?.driverAddress ?? null,
      passengerAddress: options?.passengerAddress ?? null,
    });
    return result.listCompletedTrips.map((r) => ({ ...r, fare: BigInt(r.fare), farePaid: BigInt(r.farePaid) }));
  }

  /**
   * Lists recent finished trips (full fare paid or cancelled).
   * Optionally filter by driver or passenger address.
   */
  public async listRecentTrips(options?: {
    driverAddress?: string;
    passengerAddress?: string;
  }): Promise<AvailableRecentTrip[]> {
    const query = `
      query ListRecentTrips($driverAddress: String, $passengerAddress: String) {
        listRecentTrips(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          ${RECENT_TRIP_GQL_FIELDS}
        }
      }
    `;
    const result = await this.executeGraphQL<{
      listRecentTrips: (Omit<AvailableRecentTrip, 'fare' | 'farePaid'> & { fare: string; farePaid: string })[];
    }>(query, {
      driverAddress: options?.driverAddress ?? null,
      passengerAddress: options?.passengerAddress ?? null,
    });
    return result.listRecentTrips.map((r) => ({ ...r, fare: BigInt(r.fare), farePaid: BigInt(r.farePaid) }));
  }

  /**
   * Fetches the current account balance for a public key.
   */
  public async getAccountBalance(publicKey?: string): Promise<bigint> {
    await this.ensureAuth();
    const query = `
      query AccountBalance($publicKey: String) {
        accountBalance(publicKey: $publicKey)
      }
    `;
    const result = await this.executeGraphQL<{
      accountBalance: string;
    }>(query, { publicKey: publicKey ?? this.publicKey });
    return BigInt(result.accountBalance);
  }

  /**
   * Subscribes to periodic `accountBalance` updates over WebSocket.
   * Returns a dispose function to stop the subscription.
   */
  public subscribeAccountBalance(
    options: { publicKey?: string } | undefined,
    handlers: SubscriptionHandlers<bigint>
  ): () => void {
    const { client, release } = this.acquireGraphqlWsClient();
    const query = `
      subscription AccountBalanceUpdated($publicKey: String!) {
        accountBalanceUpdated(publicKey: $publicKey)
      }
    `;

    const publicKey = options?.publicKey ?? this.publicKey;

    const disposeSub = client.subscribe(
      { query, variables: { publicKey } },
      {
        next: (res) => {
          const value = (res.data as { accountBalanceUpdated?: number | string | null | undefined })
            ?.accountBalanceUpdated;
          // BigInt(value) throws on null/undefined/non-integer input rather than yielding NaN
          // (Number's failure mode), so the same "silently skip a bad payload" guard needs a
          // try/catch instead of Number.isFinite.
          if (value == null) {
            return;
          }
          try {
            handlers.onData(BigInt(value));
          } catch {
            /* malformed balance payload — skip, same as the old Number.isFinite guard */
          }
        },
        error: (err) => handlers.onError?.(err as Error),
        complete: () => {},
      }
    );

    return () => {
      disposeSub();
      release();
    };
  }

  /**
   * Request test CLT from the Hub API faucet (POST /faucet). Requires `faucet_enabled` and a funded
   * `faucet_private_key` on the server. No GraphQL auth token required for this HTTP endpoint.
   */
  public async requestFaucet(recipientAddress: string): Promise<FaucetResponse> {
    try {
      const res = await this.apiClient.post<{ ok: boolean; amount_clt: number; node: unknown }>(
        '/faucet',
        { address: recipientAddress }
      );
      return {
        ok: true,
        amount_clt: res.data.amount_clt,
        node: res.data.node,
      };
    } catch (err: unknown) {
      const ax = err as { response?: { data?: { error?: string } }; message?: string };
      const msg =
        typeof ax.response?.data?.error === 'string'
          ? ax.response.data.error
          : ax.message ?? 'Faucet request failed';
      return { ok: false, error: String(msg) };
    }
  }

  /**
   * Builds the nested array representing the function call for RLP encoding.
   */
  private encodeFunctionCall(data: any): any[] {
    const type = data.function_call_type || data.type;
    switch (type) {
      case 'RideRequest': {
        const argsData = data.arguments || data;
        const { pickup_location, dropoff_location, fare } = argsData;
        const pickupLatBits = this.float64ToUint64(pickup_location.latitude);
        const pickupLngBits = this.float64ToUint64(pickup_location.longitude);
        const dropoffLatBits = this.float64ToUint64(dropoff_location.latitude);
        const dropoffLngBits = this.float64ToUint64(dropoff_location.longitude);
        const referrerRaw = argsData.referrer;
        const referrerForRlp =
          referrerRaw != null && String(referrerRaw).length > 0
            ? stripHexPrefix(String(referrerRaw))
            : '';
        const args = [
          [pickupLatBits, pickupLngBits],
          [dropoffLatBits, dropoffLngBits],
          BigInt(fare),
          referrerForRlp,
        ];
        // Return the array: [tag, arguments]
        return [1, args];
      }
      case 'RideOffer': {
        const argsData = data.arguments || data;
        const rideRequestTxHash = argsData.ride_request_transaction_hash ?? argsData.rideRequestTxHash ?? '';
        const fare = BigInt(argsData.fare ?? 0);
        const referrerRaw = argsData.referrer;
        const referrerForRlp =
          referrerRaw != null && String(referrerRaw).length > 0
            ? stripHexPrefix(String(referrerRaw))
            : '';
        const args = [normalizeTxHashForRlp(String(rideRequestTxHash)), fare, referrerForRlp];
        return [2, args];
      }
      case 'RideAcceptance': {
        const argsData = data.arguments || data;
        const rideOfferTxHash = argsData.ride_offer_transaction_hash ?? argsData.rideOfferTxHash ?? '';
        const args = [normalizeTxHashForRlp(String(rideOfferTxHash))];
        return [3, args];
      }
      case 'RidePay': {
        const argsData = data.arguments || data;
        const rideAcceptanceTxHash =
          argsData.ride_acceptance_transaction_hash ?? argsData.rideAcceptanceTxHash ?? '';
        const fare = BigInt(argsData.fare ?? 0);
        const args = [normalizeTxHashForRlp(String(rideAcceptanceTxHash)), fare];
        return [4, args];
      }
      case 'RideCancel': {
        const argsData = data.arguments || data;
        const rideAcceptanceTxHash =
          argsData.ride_acceptance_transaction_hash ?? argsData.rideAcceptanceTxHash ?? '';
        const args = [normalizeTxHashForRlp(String(rideAcceptanceTxHash))];
        return [5, args];
      }
      case 'RideRequestCancel': {
        const argsData = data.arguments || data;
        const rideRequestTxHash =
          argsData.ride_request_transaction_hash ?? argsData.rideRequestTxHash ?? '';
        const args = [normalizeTxHashForRlp(String(rideRequestTxHash))];
        return [8, args];
      }
      case 'Burn': {
        const argsData = data.arguments || data;
        const amount = BigInt(argsData.amount ?? 0);
        const refRaw = argsData.redemption_ref ?? argsData.redemptionRef;
        const refForRlp = refRaw != null && String(refRaw).length > 0 ? String(refRaw) : '';
        return [7, [amount, refForRlp]];
      }
      default:
        throw new Error(`Unsupported FunctionCall type: ${type}`);
    }
  }

  /**
   * Converts a JavaScript number to uint64 bits as BigInt.
   * Uses cached ArrayBuffer and DataView for better performance.
   */
  private static readonly floatBuffer = new ArrayBuffer(8);
  private static readonly floatView = new DataView(ClutchHubSdk.floatBuffer);
  
  private float64ToUint64(value: number): bigint {
    ClutchHubSdk.floatView.setFloat64(0, value, false);
    const high = BigInt(ClutchHubSdk.floatView.getUint32(0, false));
    const low = BigInt(ClutchHubSdk.floatView.getUint32(4, false));
    return (high << BigInt(32)) | low;
  }
}

/**
 * Formats CLT base units (micro-USD, at the 1 USD = 1,000,000 CLT peg) as a `$`-prefixed
 * decimal string for display — integer math only, never floats, since a float division would
 * reintroduce the precision loss bigint amounts exist to avoid. Cents are floored (truncated),
 * matching how the treasury peg treats CLT as an integer.
 */
export function formatUsd(microUsd: bigint): string {
  const negative = microUsd < 0n;
  const abs = negative ? -microUsd : microUsd;
  const cents = abs / 10000n; // 1,000,000 microUsd = 1 USD = 100 cents
  const dollars = cents / 100n;
  const remainderCents = cents % 100n;
  const sign = negative ? '-' : '';
  return `${sign}$${dollars.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')}.${remainderCents.toString().padStart(2, '0')}`;
}