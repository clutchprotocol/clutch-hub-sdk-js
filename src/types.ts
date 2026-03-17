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
  fare: number;
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
  fare: number;
  passengerAddress: string;
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