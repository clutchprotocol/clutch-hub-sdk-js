import axios, { AxiosInstance } from 'axios';
import { Buffer } from 'buffer';
import { keccak_256 } from '@noble/hashes/sha3';
import * as rlp from 'rlp';
import * as secp from '@noble/secp256k1';
import {
  ACTIVE_TRIP_GQL_FIELDS,
  createHubSubscriptionClient,
  hubGraphqlWsUrl,
  RIDE_OFFER_GQL_FIELDS,
  RIDE_REQUEST_GQL_FIELDS,
  type SubscriptionHandlers,
} from './subscriptions';
import {
  AvailableRideRequest,
  AvailableRideOffer,
  AvailableActiveTrip,
  AvailableCompletedTrip,
  MapBounds,
  RideRequestArgs,
  RideOfferArgs,
  RideAcceptanceArgs,
  RidePayArgs,
  Signature,
} from './types';

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

/**
 * Represents an unsigned transaction returned by the GraphQL API.
 */
export interface UnsignedTransaction {
  data: any;
  from: string;
  nonce: number;
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

  constructor(apiUrl: string, publicKey: string) {
    this.apiClient = axios.create({ baseURL: apiUrl });
    this.publicKey = publicKey;
  }

  /**
   * Get the current public key associated with this SDK instance.
   * @returns The public key string
   */
  public getPublicKey(): string {
    return this.publicKey;
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

  private createGraphqlWsClient() {
    return createHubSubscriptionClient({
      url: this.getGraphqlWsUrl(),
      connectionParams: async () => {
        try {
          await this.ensureAuth();
        } catch {
          /* public list subscriptions work without JWT */
        }
        return this.token ? { Authorization: `Bearer ${this.token}` } : {};
      },
    });
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
    const now = Date.now();
    // Add buffer time to prevent race conditions near token expiration
    const bufferTime = 30000; // 30 seconds
    if (!this.token || now >= (this.tokenExpireTime - bufferTime)) {
      const query = `
        mutation GenerateToken($publicKey: String!) {
          generateToken(publicKey: $publicKey) {
            token
            expiresAt
          }
        }
      `;
      const data = await this.executeGraphQL<{
        generateToken: { token: string; expiresAt: number }
      }>(query, { publicKey: this.publicKey });
      this.token = data.generateToken.token;
      this.tokenExpireTime = data.generateToken.expiresAt * 1000;
    }
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
        $dropoffLatitude: Float!, $dropoffLongitude: Float!, $fare: Int!
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
      fare: args.fare,
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
        $rideRequestTransactionHash: String!, $fare: Int!
      ) {
        createUnsignedRideOffer(
          rideRequestTransactionHash: $rideRequestTransactionHash,
          fare: $fare
        )
      }
    `;
    const variables = {
      rideRequestTransactionHash: args.rideRequestTxHash,
      fare: args.fare,
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
        $fare: Int!
      ) {
        createUnsignedRidePay(
          rideAcceptanceTransactionHash: $rideAcceptanceTransactionHash,
          fare: $fare
        )
      }
    `;
    const variables = {
      rideAcceptanceTransactionHash: args.rideAcceptanceTxHash,
      fare: args.fare,
    };
    const result = await this.executeGraphQL<{
      createUnsignedRidePay: UnsignedTransaction;
    }>(query, variables);
    return result.createUnsignedRidePay;
  }

  /**
   * Signs a transaction and returns the signature and raw RLP-encoded payload.
   */
  public async signTransaction(
    unsignedTx: UnsignedTransaction,
    privateKey: string
  ): Promise<Signature & { rawTransaction: string, txHash: string }> {
    // Encode the function call into a nested array for RLP
    const callDataArray = this.encodeFunctionCall(unsignedTx.data);

    // RLP-encode unsigned transaction [from, nonce, data]
    // Ensure from field is properly encoded as string (remove 0x prefix for consistency)
    const fromForUnsigned = stripHexPrefix(unsignedTx.from);
    const unsignedPayload = rlp.encode([
      fromForUnsigned,
      unsignedTx.nonce,
      callDataArray
    ]);
    const hashBytes = keccak_256(unsignedPayload);
    const rawHashHex = Buffer.from(hashBytes).toString('hex');

    // Sign the transaction hash
    const signature = await this.signHash(rawHashHex, privateKey);
    const rNo0x = stripHexPrefix(signature.r);
    const sNo0x = stripHexPrefix(signature.s);

    // RLP-encode full signed transaction to match Rust: [from, nonce, r, s, v, hash, data]
    // Ensure from field is properly encoded as string (remove 0x prefix for consistency)
    const fromNo0x = stripHexPrefix(unsignedTx.from);
    const fullPayload = rlp.encode([
      fromNo0x,
      unsignedTx.nonce,
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
   * Lists available ride requests (not yet accepted by a driver).
   * Optionally filter by map bounds to show only requests in the visible viewport.
   * @param bounds Optional map bounds { minLat, maxLat, minLng, maxLng }
   * @returns Array of available ride requests
   */
  /**
   * Subscribe to periodic snapshots of available ride requests (graphql-ws).
   * @returns Dispose function to stop the subscription and close the socket.
   */
  public subscribeRideRequests(
    bounds: MapBounds | null | undefined,
    handlers: SubscriptionHandlers<AvailableRideRequest[]>
  ): () => void {
    const client = this.createGraphqlWsClient();
    const query = `
      subscription RideRequestsUpdated($bounds: MapBoundsInput) {
        rideRequestsUpdated(bounds: $bounds) {
          ${RIDE_REQUEST_GQL_FIELDS}
        }
      }
    `;
    const disposeSub = client.subscribe(
      { query, variables: { bounds: bounds ?? null } },
      {
        next: (res) => {
          const items = (res.data as { rideRequestsUpdated?: AvailableRideRequest[] } | null | undefined)
            ?.rideRequestsUpdated;
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
      client.dispose();
    };
  }

  /**
   * Subscribe to ride offers for a single ride request tx hash.
   */
  public subscribeRideOffers(
    rideRequestTxHash: string,
    handlers: SubscriptionHandlers<AvailableRideOffer[]>
  ): () => void {
    const client = this.createGraphqlWsClient();
    const query = `
      subscription RideOffersUpdated($rideRequestTxHash: String!) {
        rideOffersUpdated(rideRequestTxHash: $rideRequestTxHash) {
          ${RIDE_OFFER_GQL_FIELDS}
        }
      }
    `;
    const disposeSub = client.subscribe(
      { query, variables: { rideRequestTxHash } },
      {
        next: (res) => {
          const items = (res.data as { rideOffersUpdated?: AvailableRideOffer[] } | null | undefined)
            ?.rideOffersUpdated;
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
      client.dispose();
    };
  }

  /**
   * Subscribe to active trips, optionally filtered by driver or passenger address.
   */
  public subscribeActiveTrips(
    options: { driverAddress?: string; passengerAddress?: string } | undefined,
    handlers: SubscriptionHandlers<AvailableActiveTrip[]>
  ): () => void {
    const client = this.createGraphqlWsClient();
    const query = `
      subscription ActiveTripsUpdated($driverAddress: String, $passengerAddress: String) {
        activeTripsUpdated(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          ${ACTIVE_TRIP_GQL_FIELDS}
        }
      }
    `;
    const disposeSub = client.subscribe(
      {
        query,
        variables: {
          driverAddress: options?.driverAddress ?? null,
          passengerAddress: options?.passengerAddress ?? null,
        },
      },
      {
        next: (res) => {
          const items = (res.data as { activeTripsUpdated?: AvailableActiveTrip[] } | null | undefined)
            ?.activeTripsUpdated;
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
      client.dispose();
    };
  }

  /**
   * Subscribe to completed trips, optionally filtered by driver or passenger address.
   */
  public subscribeCompletedTrips(
    options: { driverAddress?: string; passengerAddress?: string } | undefined,
    handlers: SubscriptionHandlers<AvailableCompletedTrip[]>
  ): () => void {
    const client = this.createGraphqlWsClient();
    const query = `
      subscription CompletedTripsUpdated($driverAddress: String, $passengerAddress: String) {
        completedTripsUpdated(driverAddress: $driverAddress, passengerAddress: $passengerAddress) {
          ${ACTIVE_TRIP_GQL_FIELDS}
        }
      }
    `;
    const disposeSub = client.subscribe(
      {
        query,
        variables: {
          driverAddress: options?.driverAddress ?? null,
          passengerAddress: options?.passengerAddress ?? null,
        },
      },
      {
        next: (res) => {
          const items = (res.data as { completedTripsUpdated?: AvailableActiveTrip[] } | null | undefined)
            ?.completedTripsUpdated;
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
      client.dispose();
    };
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
      listRideRequests: AvailableRideRequest[];
    }>(query, { bounds: bounds ?? null });
    return result.listRideRequests;
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
      listRideOffers: AvailableRideOffer[];
    }>(query, { rideRequestTxHash });
    return result.listRideOffers;
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
      listActiveTrips: AvailableActiveTrip[];
    }>(query, {
      driverAddress: options?.driverAddress ?? null,
      passengerAddress: options?.passengerAddress ?? null,
    });
    return result.listActiveTrips;
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
      listCompletedTrips: AvailableCompletedTrip[];
    }>(query, {
      driverAddress: options?.driverAddress ?? null,
      passengerAddress: options?.passengerAddress ?? null,
    });
    return result.listCompletedTrips;
  }

  /**
   * Fetches the current account balance for a public key.
   */
  public async getAccountBalance(publicKey?: string): Promise<number> {
    await this.ensureAuth();
    const query = `
      query AccountBalance($publicKey: String) {
        accountBalance(publicKey: $publicKey)
      }
    `;
    const result = await this.executeGraphQL<{
      accountBalance: number;
    }>(query, { publicKey: publicKey ?? this.publicKey });
    return result.accountBalance;
  }

  /**
   * Signs a hex-encoded hash.
   */
  private async signHash(
    hashHex: string,
    privateKey: string
  ): Promise<Signature> {
    const hashBuffer = Buffer.from(stripHexPrefix(hashHex), 'hex');
    const privKeyClean = stripHexPrefix(privateKey);
    const sig = await secp.signAsync(hashBuffer, privKeyClean);
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
   * Builds the nested array representing the function call for RLP encoding.
   */
  private encodeFunctionCall(data: any): any[] {
    const type = data.function_call_type || data.type;
    switch (type) {
      case 'RideRequest': {
        const { pickup_location, dropoff_location, fare } = data.arguments || data;
        const pickupLatBits = this.float64ToUint64(pickup_location.latitude);
        const pickupLngBits = this.float64ToUint64(pickup_location.longitude);
        const dropoffLatBits = this.float64ToUint64(dropoff_location.latitude);
        const dropoffLngBits = this.float64ToUint64(dropoff_location.longitude);
        const args = [
          [pickupLatBits, pickupLngBits],
          [dropoffLatBits, dropoffLngBits],
          fare,
        ];
        // Return the array: [tag, arguments]
        return [1, args];
      }
      case 'RideOffer': {
        const argsData = data.arguments || data;
        const rideRequestTxHash = argsData.ride_request_transaction_hash ?? argsData.rideRequestTxHash ?? '';
        const fare = argsData.fare ?? 0;
        const args = [normalizeTxHashForRlp(String(rideRequestTxHash)), fare];
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
        const fare = argsData.fare ?? 0;
        const args = [normalizeTxHashForRlp(String(rideAcceptanceTxHash)), fare];
        return [4, args];
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