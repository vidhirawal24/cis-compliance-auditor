import React, { createContext, useContext } from 'react';
import { apiClient, ApiClientInterface } from './client';

const ApiContext = createContext<ApiClientInterface>(apiClient);
const adapterKeys = new WeakMap<ApiClientInterface, number>();
let nextAdapterKey = 0;

// Avoid sharing cached DEMO records with a different authenticated API adapter.
export function apiCacheKey(client: ApiClientInterface): number {
  if (!adapterKeys.has(client)) adapterKeys.set(client, ++nextAdapterKey);
  return adapterKeys.get(client)!;
}

export const ApiProvider: React.FC<{ client?: ApiClientInterface; children: React.ReactNode }> = ({
  client = apiClient,
  children,
}) => {
  return <ApiContext.Provider value={client}>{children}</ApiContext.Provider>;
};

export const useApi = () => {
  return useContext(ApiContext);
};

