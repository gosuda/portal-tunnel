import { useEffect, useState } from "react";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";
import { readAdminAuthToken, writeAdminAuthToken } from "@/lib/adminAuthToken";
import type {
  AdminAuthLoginRequest,
  AdminAuthLoginResponse,
  AdminAuthStatusResponse,
} from "@/types/api";

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
}

interface LoginResult {
  success: boolean;
  error?: string;
}

function emptyAuthState(): AuthState {
  return {
    isAuthenticated: false,
    isLoading: false,
  };
}

function authErrorMessage(err: unknown): string {
  if (err instanceof APIClientError) {
    return err.message || "Admin login failed.";
  }
  return err instanceof Error ? err.message : "Admin login failed.";
}

async function fetchAuthState(): Promise<AuthState> {
  if (!readAdminAuthToken()) {
    return emptyAuthState();
  }
  try {
    const data = await apiClient.get<AdminAuthStatusResponse>(
      RELAY_API_PATHS.admin.authStatus
    );
    if (!data.authenticated) {
      writeAdminAuthToken("");
      return emptyAuthState();
    }
    return {
      isAuthenticated: data.authenticated,
      isLoading: false,
    };
  } catch {
    writeAdminAuthToken("");
    return emptyAuthState();
  }
}

export function useAuth() {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
  });

  const checkAuth = async () => {
    setAuthState(await fetchAuthState());
  };

  useEffect(() => {
    void (async () => {
      setAuthState(await fetchAuthState());
    })();
  }, []);

  const login = async (token: string): Promise<LoginResult> => {
    const trimmed = token.trim();
    if (!trimmed) {
      return { success: false, error: "Admin token is required." };
    }
    try {
      const body: AdminAuthLoginRequest = { token: trimmed };
      const data = await apiClient.post<AdminAuthLoginResponse>(
        RELAY_API_PATHS.admin.authLogin,
        body
      );
      const accessToken = data.access_token?.trim() || "";
      if (!accessToken) {
        writeAdminAuthToken("");
        return { success: false, error: "Admin login did not return an access token." };
      }
      writeAdminAuthToken(accessToken);
      setAuthState({
        isAuthenticated: true,
        isLoading: false,
      });
      return { success: true };
    } catch (err: unknown) {
      writeAdminAuthToken("");
      setAuthState(emptyAuthState());
      return { success: false, error: authErrorMessage(err) };
    }
  };

  const logout = async () => {
    try {
      await apiClient.post<unknown>(RELAY_API_PATHS.admin.logout);
    } catch {
      // Logging out should clear local state even if the remote token is stale.
    } finally {
      writeAdminAuthToken("");
    }
    setAuthState(emptyAuthState());
  };

  return {
    isAuthenticated: authState.isAuthenticated,
    isLoading: authState.isLoading,
    login,
    logout,
    checkAuth,
  };
}
