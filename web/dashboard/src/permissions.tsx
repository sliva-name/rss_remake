import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";

import type { Schemas } from "./api";

export type Permission = Schemas["Permission"];

const Permissions = createContext<ReadonlySet<Permission>>(new Set());

export function PermissionsProvider({ permissions, children }: { permissions: readonly Permission[]; children: ReactNode }) {
  const set = useMemo(() => new Set(permissions), [permissions]);
  return <Permissions.Provider value={set}>{children}</Permissions.Provider>;
}

// The server checks every call; this only spares the user a button that would
// answer 403 (ADR-0010). The function is stable while permissions are, so
// memoised tables do not rebuild on every render.
export function useCan(): (permission: Permission) => boolean {
  const permissions = useContext(Permissions);
  return useCallback((permission: Permission) => permissions.has(permission), [permissions]);
}
