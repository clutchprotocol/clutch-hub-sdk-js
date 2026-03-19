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

export interface RideOfferArgs {
  rideRequestTxHash: string;
  fare: number;
}

export interface RideAcceptanceArgs {
  rideOfferTxHash: string;
}

export interface RidePayArgs {
  rideAcceptanceTxHash: string;
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

/** A ride offer from a driver for a specific request. */
export interface AvailableRideOffer {
  txHash: string;
  rideRequestTxHash: string;
  fare: number;
  driverAddress: string;
}

/** An active trip (ride accepted, in progress). */
export interface AvailableActiveTrip {
  txHash: string;
  rideOfferTxHash: string;
  rideRequestTxHash: string;
  pickupLocation: Coordinates;
  dropoffLocation: Coordinates;
  fare: number;
  /** Amount already paid to the driver (partial payments). */
  farePaid: number;
  driverAddress: string;
  passengerAddress: string;
}

/** Completed trip (full fare paid); same payload as active trip from the API. */
export type AvailableCompletedTrip = AvailableActiveTrip;

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