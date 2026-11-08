import { describe, expect, it } from "vitest";

import login from "../../../deployments/keycloak/themes/dataguard/login/resources/css/login.css?raw";
import dashboard from "./styles.css?raw";

// The Keycloak login pages are served by Keycloak, not built with the dashboard,
// so they carry a copy of its colour tokens. This keeps the copy honest.
const tokens = (css: string) => [...css.matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)].map((match) => `${match[1]}: ${match[2]}`);

describe("login theme", () => {
  it("uses exactly the dashboard's colours in both schemes", () => {
    // --icon holds the login form's icons and has no counterpart in the dashboard.
    const copy = tokens(login).filter((token) => !token.startsWith("--icon"));
    expect(tokens(dashboard).length).toBeGreaterThan(0);
    expect(copy).toEqual(tokens(dashboard));
  });
});
