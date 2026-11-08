import { Slot } from "radix-ui";
import type { ButtonHTMLAttributes } from "react";

import { cn } from "./cn";

const variants = {
  primary: "bg-accent text-accent-fg border-transparent shadow-[inset_0_1px_0_rgb(255_255_255/0.14),var(--shadow-xs)] hover:bg-accent-hover",
  secondary: "bg-surface text-fg border-border shadow-xs hover:bg-surface-2 hover:border-border-strong",
  ghost: "bg-transparent text-fg-2 border-transparent hover:bg-neutral-bg hover:text-fg",
  danger: "bg-surface text-bad border-border shadow-xs hover:bg-bad-bg hover:border-bad/40",
};

const sizes = {
  sm: "h-8 px-3 text-xs gap-1.5",
  md: "h-9 px-3.5 text-sm gap-2",
  icon: "h-9 w-9 justify-center",
  "icon-sm": "h-8 w-8 justify-center",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
  // Renders the child element (a router Link, say) with the button's look.
  asChild?: boolean;
}

export function Button({ variant = "secondary", size = "md", asChild, className, type, ...props }: ButtonProps) {
  const Component = asChild ? Slot.Root : "button";
  return (
    <Component
      type={asChild ? undefined : (type ?? "button")}
      className={cn(
        "inline-flex shrink-0 cursor-pointer items-center rounded-md border font-medium whitespace-nowrap transition-[background-color,border-color,color,box-shadow] active:translate-y-px",
        "disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  );
}
