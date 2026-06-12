import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api',
  withCredentials: true,
});

export default api;

/**
 * Intercepts requests to automatically attach the JWT token.
 * This ensures that protected routes receive the token in the Authorization header.
 * @param {Object} config - The Axios request config object.
 * @returns {Object} The updated config object.
 */
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('jwt_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/**
 * Intercepts responses to handle global errors like 401 Unauthorized.
 * If a 401 is encountered, it clears the token and redirects to login.
 * @param {Object} response - The successful Axios response object.
 * @returns {Object|Promise} The response or rejected promise.
 */
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear local storage and redirect to login
      localStorage.removeItem('jwt_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);
