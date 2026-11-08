import { createContext, use, useCallback, useMemo, type ReactNode } from "react";

import type { Schemas } from "./api";

export type Permission = Schemas["Permission"];

const Permissions = createContext<ReadonlySet<Permission>>(new Set());

export function PermissionsProvider({ permissions, children }: { permissions: readonly Permission[]; children: ReactNode }) {
  const set = useMemo(() => new Set(permissions), [permissions]);
  return <Permissions value={set}>{children}</Permissions>;
}

// The server checks every call; this only spares the user a button that would
// answer 403 (ADR-0010). The function is stable while permissions are, so
// memoised tables do not rebuild on every render.
export function useCan(): (permission: Permission) => boolean {
  const permissions = use(Permissions);
  return useCallback((permission: Permission) => permissions.has(permission), [permissions]);
}
