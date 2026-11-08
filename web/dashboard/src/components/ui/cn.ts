import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// Later classes win over earlier ones, so a caller can override a component's
// padding or colour without fighting the cascade.
export function cn(...values: ClassValue[]): string {
  return twMerge(clsx(values));
}
