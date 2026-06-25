import axios from 'axios';
import { env } from '@/config/env';
import { getAccessToken } from '@/auth/tokenStore';

const API_BASE_URL = env.API_BASE_URL;

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 600000, // 10 minutes for large file uploads
});

// Request interceptor
apiClient.interceptors.request.use(
  config => {
    // Prefer the OIDC access token. The legacy localStorage `authToken` fallback applies only when
    // auth is disabled — otherwise a stale token could revive a bearer after logout / during signin.
    const token = getAccessToken() ?? (env.AUTH_ENABLED ? null : localStorage.getItem('authToken'));
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Set Content-Type to application/json for non-FormData requests
    if (!(config.data instanceof FormData) && !config.headers['Content-Type']) {
      config.headers['Content-Type'] = 'application/json';
    }

    return config;
  },
  error => Promise.reject(error)
);

// Response interceptor
apiClient.interceptors.response.use(
  response => response,
  error => {
    // Handle global errors
    if (error.response?.status === 401) {
      // Handle unauthorized - could redirect to login if needed
      localStorage.removeItem('authToken');
    }

    if (error.response?.status === 500) {
      console.error('Server error:', error.response.data);
    }

    return Promise.reject(error);
  }
);
