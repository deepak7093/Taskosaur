import { useEffect } from "react";
import { useRouter } from "next/router";
import { authApi } from "@/utils/api/authApi";
import { TokenManager } from "@/lib/api";
import { Loader2 } from "lucide-react";

export default function OIDCCallback() {
  const router = useRouter();

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const { access_token, refresh_token, error } = router.query;

        if (error) {
          console.error("OIDC authentication error:", error);
          router.push(`/login?error=${encodeURIComponent(String(error))}`);
          return;
        }

        if (!access_token) {
          console.error("No access token received");
          router.push("/login?error=no_token");
          return;
        }

        // Store tokens
        TokenManager.setAccessToken(String(access_token));
        if (refresh_token) {
          TokenManager.setRefreshToken(String(refresh_token));
        }

        // Fetch user profile to store in localStorage
        const user = await authApi.getUserProfile();
        if (user) {
          localStorage.setItem("user", JSON.stringify(user));
        }

        // Redirect to dashboard
        router.push("/dashboard");
      } catch (error) {
        console.error("OIDC callback error:", error);
        router.push("/login?error=callback_failed");
      }
    };

    if (router.isReady) {
      handleCallback();
    }
  }, [router]);

  return (
    <div className="min-h-screen bg-[var(--background)] flex items-center justify-center">
      <div className="text-center">
        <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-primary" />
        <p className="text-muted-foreground">Completing authentication...</p>
      </div>
    </div>
  );
}

