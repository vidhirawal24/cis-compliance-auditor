import React, { createContext, useContext } from 'react';
import { apiClient, ApiClientInterface } from './client';

const ApiContext = createContext<ApiClientInterface>(apiClient);

export const ApiProvider: React.FC<{ client?: ApiClientInterface; children: React.ReactNode }> = ({
  client = apiClient,
  children,
}) => {
  return <ApiContext.Provider value={client}>{children}</ApiContext.Provider>;
};

export const useApi = () => {
  return useContext(ApiContext);
};

