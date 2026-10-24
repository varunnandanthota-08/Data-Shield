import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  UserResponse,
  checkBootstrapStatus,
  loginUser,
  setupInitialAdmin,
  logoutUser,
  getCurrentUser,
  getAuthToken,
  setAuthToken,
  setOnUnauthorizedCallback,
} from '../api/client';

interface AuthContextType {
  user: UserResponse | null;
  token: string | null;
  isLoading: boolean;
  requiresBootstrap: boolean;
  login: (username: string, password: string) => Promise<void>;
  setupAdmin: (username: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  isAdmin: boolean;
  isAnalyst: boolean;
  isViewer: boolean;
  canScan: boolean;
  canManagePolicies: boolean;
  canViewAudit: boolean;
  canManageUsers: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setTokenState] = useState<string | null>(getAuthToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [requiresBootstrap, setRequiresBootstrap] = useState<boolean>(false);

  // Initialize session and verify bootstrap requirements
  const checkInitialAuth = useCallback(async () => {
    setIsLoading(true);
    try {
      // 1. Check if database has 0 users (first run)
      const bootStatus = await checkBootstrapStatus();
      setRequiresBootstrap(bootStatus.requires_bootstrap);

      if (bootStatus.requires_bootstrap) {
        setUser(null);
        setAuthToken(null);
        setTokenState(null);
        setIsLoading(false);
        return;
      }

      // 2. If token exists in memory or session, validate against /auth/me
      const currentToken = getAuthToken();
      if (currentToken) {
        try {
          const userData = await getCurrentUser();
          setUser(userData);
          setTokenState(currentToken);
        } catch {
          // Token expired or invalid
          setUser(null);
          setAuthToken(null);
          setTokenState(null);
        }
      } else {
        setUser(null);
      }
    } catch {
      // If server unreachable, preserve offline state
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkInitialAuth();

    // Hook unauthorized callback to gracefully expire session
    setOnUnauthorizedCallback(() => {
      setUser(null);
      setAuthToken(null);
      setTokenState(null);
    });

    return () => {
      setOnUnauthorizedCallback(null);
    };
  }, [checkInitialAuth]);

  const login = async (username: string, password: string) => {
    const res = await loginUser({ username, password });
    setUser(res.user);
    setTokenState(res.access_token);
  };

  const setupAdmin = async (username: string, email: string, password: string) => {
    const res = await setupInitialAdmin({ username, email, password });
    setUser(res.user);
    setTokenState(res.access_token);
    setRequiresBootstrap(false);
  };

  const logout = async () => {
    await logoutUser();
    setUser(null);
    setTokenState(null);
  };

  const refreshUser = async () => {
    try {
      const userData = await getCurrentUser();
      setUser(userData);
    } catch {
      setUser(null);
      setAuthToken(null);
      setTokenState(null);
    }
  };

  const role = user?.role;
  const isAdmin = role === 'admin';
  const isAnalyst = role === 'analyst';
  const isViewer = role === 'viewer';

  const canScan = isAdmin || isAnalyst;
  const canManagePolicies = isAdmin;
  const canViewAudit = isAdmin || isAnalyst;
  const canManageUsers = isAdmin;

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        requiresBootstrap,
        login,
        setupAdmin,
        logout,
        refreshUser,
        isAdmin,
        isAnalyst,
        isViewer,
        canScan,
        canManagePolicies,
        canViewAudit,
        canManageUsers,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
