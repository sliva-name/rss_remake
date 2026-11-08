import { cloneElement, isValidElement, useId, type ComponentProps, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

import { cn } from "./cn";

const control =
  "h-8 w-full min-w-0 rounded-md border border-border bg-surface px-2.5 text-sm text-fg placeholder:text-fg-3 " +
  "transition-colors hover:border-border-strong focus:border-accent focus:outline-none focus-visible:outline-none " +
  "focus:ring-2 focus:ring-accent/20 disabled:opacity-60 aria-[invalid=true]:border-bad";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(control, className)} {...props} />;
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cn(control, "cursor-pointer pr-7", className)} {...props} />;
}

export function Checkbox({ className, ...props }: Omit<ComponentProps<"input">, "type">) {
  return <input type="checkbox" className={cn("size-4 cursor-pointer rounded accent-[var(--accent)]", className)} {...props} />;
}

// A labelled control. The label wraps the control, so clicking it focuses the
// control; the hint sits outside the label so the control's name stays just
// the label, and the hint is announced as its description.
export function Field({ label, hint, error, className, children }: { label: string; hint?: ReactNode; error?: string; className?: string; children: ReactNode }) {
  const describedBy = useId();
  const note = error ?? hint;
  const control = note && isValidElement<{ "aria-describedby"?: string }>(children) ? cloneElement(children, { "aria-describedby": describedBy }) : children;
  return (
    <div className={cn("flex min-w-0 flex-col gap-1", className)}>
      <label className="flex min-w-0 flex-col gap-1">
        <span className="text-xs font-medium text-fg-2">{label}</span>
        {control}
      </label>
      {note && <span id={describedBy} className={cn("text-xs", error ? "text-bad" : "text-fg-3")}>{note}</span>}
    </div>
  );
}

export function CheckField({ label, className, ...props }: { label: string } & Omit<InputHTMLAttributes<HTMLInputElement>, "type">) {
  return (
    <label className={cn("inline-flex h-8 cursor-pointer items-center gap-2 text-sm text-fg-2", className)}>
      <Checkbox {...props} />
      {label}
    </label>
  );
}
