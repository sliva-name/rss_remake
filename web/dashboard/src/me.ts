import { useQuery } from "@tanstack/react-query";

import { api } from "./api";

// The signed-in account, loaded once by the shell and shared from the cache.
export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: api.me, refetchInterval: false, staleTime: Infinity });
}
