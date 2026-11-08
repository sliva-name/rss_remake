import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "./cn";

export type Tone = "neutral" | "ok" | "warn" | "bad" | "accent";

// A tinted fill with a hairline of the same colour, so a badge holds its shape
// on a white row and on a grey one.
const tones: Record<Tone, string> = {
  neutral: "bg-neutral-bg text-fg-2 ring-fg-3/15",
  ok: "bg-ok-bg text-ok ring-ok/20",
  warn: "bg-warn-bg text-warn ring-warn/25",
  bad: "bg-bad-bg text-bad ring-bad/20",
  accent: "bg-accent-bg text-accent ring-accent/20",
};

export function Badge({ tone = "neutral", className, ...props }: { tone?: Tone } & HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn("inline-flex h-[22px] items-center gap-1.5 rounded-md px-2 text-xs font-medium whitespace-nowrap ring-1 ring-inset", tones[tone], className)}
      {...props}
    />
  );
}

const dots: Record<Tone, string> = {
  neutral: "bg-fg-3 ring-fg-3/20",
  ok: "bg-ok ring-ok/20",
  warn: "bg-warn ring-warn/25",
  bad: "bg-bad ring-bad/20",
  accent: "bg-accent ring-accent/20",
};

// State is never colour alone: the dot always comes with its label.
export function Status({ tone, children, className }: { tone: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2 text-sm whitespace-nowrap", className)}>
      <span aria-hidden className={cn("size-2 shrink-0 rounded-full ring-[3px]", dots[tone])} />
      {children}
    </span>
  );
}
