import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "./cn";

export type Tone = "neutral" | "ok" | "warn" | "bad" | "accent";

const tones: Record<Tone, string> = {
  neutral: "bg-neutral-bg text-fg-2",
  ok: "bg-ok-bg text-ok",
  warn: "bg-warn-bg text-warn",
  bad: "bg-bad-bg text-bad",
  accent: "bg-accent-bg text-accent",
};

export function Badge({ tone = "neutral", className, ...props }: { tone?: Tone } & HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn("inline-flex h-6 items-center gap-1 rounded-md px-2 text-xs font-medium whitespace-nowrap", tones[tone], className)}
      {...props}
    />
  );
}

const dots: Record<Tone, string> = {
  neutral: "bg-fg-3",
  ok: "bg-ok",
  warn: "bg-warn",
  bad: "bg-bad",
  accent: "bg-accent",
};

// State is never colour alone: the dot always comes with its label.
export function Status({ tone, children, className }: { tone: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-sm whitespace-nowrap", className)}>
      <span aria-hidden className={cn("size-2 shrink-0 rounded-full", dots[tone])} />
      {children}
    </span>
  );
}
