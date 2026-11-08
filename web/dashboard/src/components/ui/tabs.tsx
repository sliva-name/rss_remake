import { Tabs as Primitive } from "radix-ui";
import type { ReactNode } from "react";
import { useSearchParams } from "react-router";

import { type Permission, useCan } from "../../permissions";
import { cn } from "./cn";

export interface TabItem {
  id: string;
  label: ReactNode;
  content: ReactNode;
  // The tab is shown with any of these permissions.
  needs?: Permission | readonly Permission[];
}

// Tabs keep their choice in the address, so a link or a reload opens the same tab.
export function Tabs({ items: all, param = "tab", className }: { items: TabItem[]; param?: string; className?: string }) {
  const can = useCan();
  const items = all.filter(({ needs }) => needs === undefined || (typeof needs === "string" ? can(needs) : needs.some(can)));
  const [parameters, setParameters] = useSearchParams();
  const requested = parameters.get(param);
  const current = items.some((item) => item.id === requested) ? (requested as string) : (items[0]?.id ?? "");
  const choose = (id: string) => {
    const next = new URLSearchParams();
    if (id !== items[0]?.id) next.set(param, id);
    setParameters(next, { replace: true });
  };
  return (
    <Primitive.Root value={current} onValueChange={choose} className={className}>
      <Primitive.List aria-label="Разделы страницы" className="mb-6 flex gap-2 overflow-x-auto border-b border-border">
        {items.map((item) => (
          <Primitive.Trigger
            key={item.id}
            value={item.id}
            className={cn(
              "-mb-px cursor-pointer border-b-2 border-transparent px-3 py-2.5 text-sm font-medium whitespace-nowrap text-fg-2 transition-colors",
              "hover:text-fg data-[state=active]:border-accent data-[state=active]:text-fg",
            )}
          >
            {item.label}
          </Primitive.Trigger>
        ))}
      </Primitive.List>
      {items.map((item) => (
        <Primitive.Content key={item.id} value={item.id} className="focus-visible:outline-hidden">
          {item.content}
        </Primitive.Content>
      ))}
    </Primitive.Root>
  );
}
