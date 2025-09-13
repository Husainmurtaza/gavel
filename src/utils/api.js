// API utility functions with automatic token refresh
import { API_BASE_URL } from '../config/api.js';

// Function to make authenticated API calls
export const authenticatedFetch = async (endpoint, options = {}) => {
  const accessToken = localStorage.getItem('accessToken');
  
  if (!accessToken) {
    throw new Error('No access token found');
  }

  // Add authorization header
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`,
    ...options.headers
  };

  try {

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
      credentials: 'include'
    });

    // If token expired, try to refresh
    if (response.status === 401) {
      const errorData = await response.json();
      if (errorData.code === 'TOKEN_EXPIRED') {
        const newToken = await refreshToken();
        if (newToken) {
          // Retry the request with new token
          headers.Authorization = `Bearer ${newToken}`;
          const retryResponse = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers,
            credentials: 'include'
          });
          return retryResponse;
        }
      }
    }

    return response;
  } catch (error) {

    throw error;
  }
};

// Function to refresh access token
export const refreshToken = async () => {
  try {

    const response = await fetch(`${API_BASE_URL}/api/refresh-token`, {
      method: 'POST',
      credentials: 'include'
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('accessToken', data.accessToken);
      return data.accessToken;
    } else {
      // Refresh failed, redirect to login
      localStorage.removeItem('accessToken');
      localStorage.removeItem('user');
      localStorage.removeItem('admin_logged_in');
      localStorage.removeItem('client_logged_in');
      localStorage.removeItem('candidate_logged_in');
      window.location.href = '/login';
      return null;
    }
  } catch (error) {

    // Redirect to login on refresh failure
    localStorage.removeItem('accessToken');
    localStorage.removeItem('user');
    localStorage.removeItem('admin_logged_in');
    localStorage.removeItem('client_logged_in');
    localStorage.removeItem('candidate_logged_in');
    window.location.href = '/login';
    return null;
  }
};

// Function to logout
export const logout = async () => {
  try {
    await fetch(`${API_BASE_URL}/api/logout`, {
      method: 'POST',
      credentials: 'include'
    });
  } catch (error) {

  } finally {
    // Clear all local storage
    localStorage.removeItem('accessToken');
    localStorage.removeItem('user');
    localStorage.removeItem('admin_logged_in');
    localStorage.removeItem('client_logged_in');
    localStorage.removeItem('candidate_logged_in');
  }
};

// Function to test if backend is reachable
export const testBackendConnection = async () => {
  try {

    const response = await fetch(`${API_BASE_URL}/`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (response.ok) {
      const data = await response.text();

      return true;
    } else {

      return false;
    }
  } catch (error) {

    return false;
  }
};
