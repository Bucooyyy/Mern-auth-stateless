import { create } from 'zustand';
import api from '../lib/api';

export const useAuthStore = create((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,

  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      const response = await api.post('/auth/login', { email, password });
      
      if (response.data.requiresMfa) {
        set({ isLoading: false });
        return { requiresMfa: true, tempToken: response.data.tempToken };
      }

      set({ 
        user: response.data.user, 
        isAuthenticated: true, 
        isLoading: false 
      });
      return { success: true };
    } catch (error) {
      set({ 
        error: error.response?.data?.error?.message || error.response?.data?.message || 'Login failed', 
        isLoading: false 
      });
      return { success: false };
    }
  },

  verifyMfa: async (token, tempToken) => {
    set({ isLoading: true, error: null });
    try {
      const response = await api.post('/auth/verify-mfa', { token }, {
        headers: { Authorization: `Bearer ${tempToken}` }
      });
      
      set({ 
        user: response.data.user, 
        isAuthenticated: true, 
        isLoading: false 
      });
      return { success: true };
    } catch (error) {
      set({ 
        error: error.response?.data?.error?.message || error.response?.data?.message || 'Invalid MFA code', 
        isLoading: false 
      });
      return { success: false };
    }
  },

  register: async (name, email, password) => {
    set({ isLoading: true, error: null });
    try {
      const response = await api.post('/auth/register', { name, email, password });
      set({ 
        user: response.data.user, 
        isAuthenticated: true, 
        isLoading: false 
      });
      return { success: true };
    } catch (error) {
      set({ 
        error: error.response?.data?.error?.message || error.response?.data?.message || 'Registration failed', 
        isLoading: false 
      });
      return { success: false };
    }
  },
  
  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error(error);
    } finally {
      set({ user: null, isAuthenticated: false });
    }
  }
}));
