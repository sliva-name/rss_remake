import { createContext, useContext, type ReactNode } from "react";

import type { Schemas } from "./api";

export type Permission = Schemas["Permission"];

const Permissions = createContext<ReadonlySet<Permission>>(new Set());

export function PermissionsProvider({ permissions, children }: { permissions: readonly Permission[]; children: ReactNode }) {
  return <Permissions.Provider value={new Set(permissions)}>{children}</Permissions.Provider>;
}

// The server checks every call; this only spares the user a button that would
// answer 403 (ADR-0010).
export function useCan(): (permission: Permission) => boolean {
  const permissions = useContext(Permissions);
  return (permission) => permissions.has(permission);
}

export function Allowed({ to, children }: { to: Permission; children: ReactNode }) {
  return useCan()(to) ? <>{children}</> : null;
}
