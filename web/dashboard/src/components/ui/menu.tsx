import { Check } from "lucide-react";
import { DropdownMenu, Tooltip as TooltipPrimitive } from "radix-ui";
import type { ReactNode } from "react";

import { cn } from "./cn";

const content = "z-50 min-w-48 rounded-md border border-border bg-surface p-1 text-sm text-fg shadow-lg";
const item = "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 outline-none select-none data-[highlighted]:bg-surface-2 data-[disabled]:opacity-50";

export function Menu({ trigger, label, children, align = "end" }: { trigger: ReactNode; label?: string; children: ReactNode; align?: "start" | "end" }) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>{trigger}</DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align={align} sideOffset={4} className={content}>
          {label && <DropdownMenu.Label className="px-2 py-1 text-xs font-medium text-fg-3">{label}</DropdownMenu.Label>}
          {children}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

export function MenuItem({ onSelect, icon, children, className }: { onSelect: () => void; icon?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <DropdownMenu.Item onSelect={onSelect} className={cn(item, "[&_svg]:size-4 [&_svg]:text-fg-2", className)}>
      {icon}
      {children}
    </DropdownMenu.Item>
  );
}

export function MenuCheckbox({ checked, onChange, children }: { checked: boolean; onChange: (checked: boolean) => void; children: ReactNode }) {
  return (
    <DropdownMenu.CheckboxItem
      checked={checked}
      onCheckedChange={(value) => onChange(value === true)}
      onSelect={(event) => event.preventDefault()}
      className={cn(item, "pl-7 relative")}
    >
      <DropdownMenu.ItemIndicator className="absolute left-2">
        <Check className="size-3.5" />
      </DropdownMenu.ItemIndicator>
      {children}
    </DropdownMenu.CheckboxItem>
  );
}

export function MenuSeparator() {
  return <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />;
}

export function TooltipProvider({ children }: { children: ReactNode }) {
  return <TooltipPrimitive.Provider delayDuration={300}>{children}</TooltipPrimitive.Provider>;
}

export function Tooltip({ content: text, children }: { content: ReactNode; children: ReactNode }) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content sideOffset={4} className="z-50 max-w-xs rounded-md bg-fg px-2 py-1 text-xs text-bg shadow-md">
          {text}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}
