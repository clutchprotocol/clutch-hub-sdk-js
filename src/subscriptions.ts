import { createClient, type Client } from 'graphql-ws';

/**
 * WebSocket URL for GraphQL subscriptions (`graphql-transport-ws` protocol).
 * Mirrors HTTP API origin with path `/graphql/ws`.
 */
export function hubGraphqlWsUrl(apiBaseUrl: string): string {
  const base = apiBaseUrl.replace(/\/$/, '');
  const u = new URL(base);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  const path = u.pathname.replace(/\/$/, '');
  u.pathname = `${path}/graphql/ws`;
  return u.href;
}

export const RIDE_REQUEST_GQL_FIELDS = `
  txHash
  pickupLocation { latitude longitude }
  dropoffLocation { latitude longitude }
  fare
  passengerAddress
`;

export const RIDE_OFFER_GQL_FIELDS = `
  txHash
  rideRequestTxHash
  fare
  driverAddress
`;

export const ACTIVE_TRIP_GQL_FIELDS = `
  txHash
  rideOfferTxHash
  rideRequestTxHash
  pickupLocation { latitude longitude }
  dropoffLocation { latitude longitude }
  fare
  farePaid
  driverAddress
  passengerAddress
`;

export type SubscriptionHandlers<T> = {
  onData: (items: T) => void;
  onError?: (err: Error) => void;
};

export function createHubSubscriptionClient(options: {
  url: string;
  connectionParams?: () => Promise<Record<string, unknown>> | Record<string, unknown>;
}): Client {
  return createClient({
    url: options.url,
    lazy: false,
    keepAlive: 10000,
    shouldRetry: () => true,
    retryAttempts: Infinity,
    retryWait: async (retries) => {
      await new Promise((r) =>
        setTimeout(r, Math.min(3000 * (retries + 1), 15000))
      );
    },
    connectionParams: options.connectionParams,
  });
}
