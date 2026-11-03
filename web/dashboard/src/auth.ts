import { User, UserManager, WebStorageStateStore } from "oidc-client-ts";

interface UiConfig {
  issuer: string;
  clientId: string;
}

let manager: UserManager | null = null;

async function loadManager(): Promise<UserManager> {
  if (manager) return manager;
  const response = await fetch("/ui-config");
  if (!response.ok) throw new Error("ui configuration is unavailable");
  const config = (await response.json()) as UiConfig;
  manager = new UserManager({
    authority: config.issuer,
    client_id: config.clientId,
    redirect_uri: `${window.location.origin}/`,
    post_logout_redirect_uri: `${window.location.origin}/`,
    response_type: "code",
    scope: "openid",
    automaticSilentRenew: true,
    // Session storage ends with the tab, so a token outlives no more than the work.
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
  return manager;
}

export async function completeSignIn(): Promise<User | null> {
  const users = await loadManager();
  const parameters = new URLSearchParams(window.location.search);
  if (parameters.has("code") && parameters.has("state")) {
    const user = await users.signinRedirectCallback();
    window.history.replaceState({}, "", "/");
    return user;
  }
  const user = await users.getUser();
  return user && !user.expired ? user : null;
}

export async function signIn(): Promise<void> {
  await (await loadManager()).signinRedirect();
}

export async function signOut(): Promise<void> {
  await (await loadManager()).signoutRedirect();
}

export async function accessToken(): Promise<string | null> {
  const user = await (await loadManager()).getUser();
  return user?.access_token ?? null;
}
