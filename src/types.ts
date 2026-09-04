export {};

/**
 * Represents geographical coordinates for location-based operations.
 */
export interface Coordinates {
  latitude: number;
  longitude: number;
}

export interface RideRequestArgs {
  pickup: Coordinates;
  dropoff: Coordinates;
  /** CLT base units (1 USD = 1,000,000 CLT). bigint because GraphQL/JSON `number` loses precision above 2^53. */
  fare: bigint;
}

export interface RideOfferArgs {
  rideRequestTxHash: string;
  fare: bigint;
}

export interface RideAcceptanceArgs {
  rideOfferTxHash: string;
}

export interface RidePayArgs {
  rideAcceptanceTxHash: string;
  fare: bigint;
}

export interface RideCancelArgs {
  rideAcceptanceTxHash: string;
}

export interface RideRequestCancelArgs {
  rideRequestTxHash: string;
}

export interface BurnArgs {
  /** CLT base units to burn. */
  amount: bigint;
  /** hex(keccak256(intent_id)) for treasury redemptions; omit for a plain burn. */
  redemptionRef?: string;
}

/**
 * Genesis-committed consensus parameters (hub `chainInfo` query). Every numeric field is a
 * `String` on the wire — `total_supply` is the one value that can exceed 2^53, and one rule
 * for every field here is cheaper to remember than a per-field exception.
 */
export interface ChainInfo {
  chainId: bigint;
  isTestnet: boolean;
  txFee: bigint;
  totalSupply: bigint;
  mintAuthority: string;
}

/** Map viewport bounds for filtering ride requests by pickup location. */
export interface MapBounds {
  minLat: number;
  maxLat: number;
  minLng: number;
  maxLng: number;
}

/** A ride request available for drivers to accept (no acceptance yet). */
export interface AvailableRideRequest {
  txHash: string;
  pickupLocation: Coordinates;
  dropoffLocation: Coordinates;
  fare: bigint;
  passengerAddress: string;
}

/** A ride offer from a driver for a specific request. */
export interface AvailableRideOffer {
  txHash: string;
  rideRequestTxHash: string;
  fare: bigint;
  driverAddress: string;
}

/** An active trip (ride accepted, in progress). */
export interface AvailableActiveTrip {
  txHash: string;
  rideOfferTxHash: string;
  rideRequestTxHash: string;
  pickupLocation: Coordinates;
  dropoffLocation: Coordinates;
  fare: bigint;
  /** Amount already paid to the driver (partial payments). */
  farePaid: bigint;
  driverAddress: string;
  passengerAddress: string;
}

/** Completed trip (full fare paid); same payload as active trip from the API. */
export type AvailableCompletedTrip = AvailableActiveTrip;

/** Recent finished trip: full fare paid or cancelled (`tripStatus`). */
export interface AvailableRecentTrip extends AvailableActiveTrip {
  tripStatus: 'completed' | 'cancelled' | string;
}

export interface Signature {
  r: string;
  s: string;
  v: number;
}

export interface SignedTx {
  from: string;
  nonce: number;
  payload: Uint8Array;
  r: string;
  s: string;
  v: number;
}

/**
 * Transaction status enumeration for tracking transaction states.
 */
export enum TransactionStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
} 