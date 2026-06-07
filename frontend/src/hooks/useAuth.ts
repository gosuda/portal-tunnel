import { useEffect, useState } from "react";
import {
  useCurrentAccount,
  useDisconnectWallet,
  useSignPersonalMessage,
  useWallets,
} from "@mysten/dapp-kit";
import { BROWSER_API_PATHS } from "@/lib/apiPaths";
import { APIClientError, apiClient } from "@/lib/apiClient";
import { writeAdminAuthToken } from "@/lib/adminAuthToken";
import type {
  WalletAuthChallengeResponse,
  WalletAuthLoginResponse,
  WalletAuthStatusResponse,
} from "@/types/api";

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  walletAddress: string;
}

interface LoginResult {
  success: boolean;
  error?: string;
}

function emptyAuthState(): AuthState {
  return {
    isAuthenticated: false,
    isLoading: false,
    walletAddress: "",
  };
}

async function fetchAuthState(): Promise<AuthState> {
  try {
    const data = await apiClient.get<WalletAuthStatusResponse>(
      BROWSER_API_PATHS.admin.authStatus
    );
    return {
      isAuthenticated: data.authenticated,
      isLoading: false,
      walletAddress: data.wallet_address || "",
    };
  } catch {
    return emptyAuthState();
  }
}

export function useAuth() {
  const currentAccount = useCurrentAccount();
  const wallets = useWallets();
  const { mutateAsync: disconnectWallet } = useDisconnectWallet();
  const { mutateAsync: signPersonalMessage } = useSignPersonalMessage();
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    walletAddress: "",
  });

  const checkAuth = async () => {
    setAuthState(await fetchAuthState());
  };

  useEffect(() => {
    void (async () => {
      setAuthState(await fetchAuthState());
    })();
  }, []);

  const login = async (): Promise<LoginResult> => {
    try {
      const address = currentAccount?.address || "";
      if (!address) {
        return {
          success: false,
          error: wallets.length === 0
            ? "Sui wallet is unavailable."
            : "Connect Sui wallet first.",
        };
      }
      const challenge = await apiClient.post<WalletAuthChallengeResponse>(
        BROWSER_API_PATHS.admin.authChallenge,
        { address, auth_method: "sui_wallet" }
      );
      const signed = await signPersonalMessage({
        message: new TextEncoder().encode(challenge.message),
      });
      const data = await apiClient.post<WalletAuthLoginResponse>(
        BROWSER_API_PATHS.admin.authLogin,
        {
          challenge_id: challenge.challenge_id,
          address,
          auth_method: "sui_wallet",
          message: challenge.message,
          signature: signed.signature,
        }
      );
      const accessToken = data.access_token?.trim() || "";
      if (!accessToken) {
        writeAdminAuthToken("");
        return { success: false, error: "Admin login did not return an access token." };
      }
      writeAdminAuthToken(accessToken);
      setAuthState((prev) => ({
        ...prev,
        isAuthenticated: true,
        walletAddress: data.wallet_address || address,
      }));
      return { success: true };
    } catch (err: unknown) {
      if (err instanceof APIClientError) {
        return {
          success: false,
          error: err.message || "Sui wallet login failed.",
        };
      }

      return {
        success: false,
        error: err instanceof Error ? err.message : "Sui wallet login failed.",
      };
    }
  };

  const logout = async () => {
    try {
      await apiClient.post<unknown>(BROWSER_API_PATHS.admin.logout);
    } catch {
      // Logging out should clear local state even if the remote token is stale.
    } finally {
      writeAdminAuthToken("");
    }
    setAuthState((prev) => ({ ...prev, isAuthenticated: false, walletAddress: "" }));
    try {
      await disconnectWallet();
    } catch {
      // Some wallet connectors cannot be disconnected programmatically.
    }
  };

  return {
    isAuthenticated: authState.isAuthenticated,
    isLoading: authState.isLoading,
    walletAddress: authState.walletAddress,
    connectedWalletAddress: currentAccount?.address || "",
    hasAvailableWallet: wallets.length > 0,
    login,
    logout,
    checkAuth,
  };
}
