import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { AuthProvider } from './auth/context';
import { ApiProvider } from './api/context';
import { AppRouter } from './routes/AppRouter';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 1000 * 60 * 5, // 5 minutes
    },
  },
});

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ApiProvider>
          <BrowserRouter>
            <AppRouter />
            <Toaster position="top-right" richColors theme="dark" />
          </BrowserRouter>
        </ApiProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;

