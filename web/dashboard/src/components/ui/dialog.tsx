import { X } from "lucide-react";
import { Dialog as Primitive } from "radix-ui";
import { createContext, use, useCallback, useRef, useState, type ReactNode } from "react";

import { Button } from "./button";
import { cn } from "./cn";

const overlay = "fixed inset-0 z-40 bg-black/40";

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  footer,
  className,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  footer?: ReactNode;
  className?: string;
  children?: ReactNode;
}) {
  return (
    <Primitive.Root open={open} onOpenChange={onOpenChange}>
      <Primitive.Portal>
        <Primitive.Overlay className={overlay} />
        <Primitive.Content
          className={cn(
            "fixed top-1/2 left-1/2 z-50 flex max-h-[85vh] w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col",
            "rounded-lg border border-border bg-surface shadow-xl focus:outline-hidden",
            className,
          )}
        >
          <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-3.5">
            <div>
              <Primitive.Title className="text-base font-semibold text-fg">{title}</Primitive.Title>
              {description ? (
                <Primitive.Description className="mt-0.5 text-sm text-fg-2">{description}</Primitive.Description>
              ) : (
                <Primitive.Description className="sr-only">{title}</Primitive.Description>
              )}
            </div>
            <Primitive.Close asChild>
              <Button variant="ghost" size="icon-sm" aria-label="Закрыть"><X /></Button>
            </Primitive.Close>
          </div>
          {children && <div className="min-h-0 overflow-y-auto px-5 py-4">{children}</div>}
          {footer && <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>}
        </Primitive.Content>
      </Primitive.Portal>
    </Primitive.Root>
  );
}

// A panel from the right edge: details of a record without leaving the list.
export function Drawer({
  open,
  onOpenChange,
  title,
  description,
  actions,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Primitive.Root open={open} onOpenChange={onOpenChange}>
      <Primitive.Portal>
        <Primitive.Overlay className="fixed inset-0 z-40 bg-black/20" />
        <Primitive.Content
          className="fixed inset-y-0 right-0 z-50 flex w-[min(36rem,100vw)] flex-col border-l border-border bg-surface shadow-xl focus:outline-hidden"
        >
          <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-3.5">
            <div className="min-w-0">
              <Primitive.Title className="text-base font-semibold break-words text-fg">{title}</Primitive.Title>
              {description ? (
                <Primitive.Description className="mt-0.5 text-sm text-fg-2">{description}</Primitive.Description>
              ) : (
                <Primitive.Description className="sr-only">Подробности</Primitive.Description>
              )}
            </div>
            <div className="flex items-center gap-1">
              {actions}
              <Primitive.Close asChild>
                <Button variant="ghost" size="icon-sm" aria-label="Закрыть"><X /></Button>
              </Primitive.Close>
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        </Primitive.Content>
      </Primitive.Portal>
    </Primitive.Root>
  );
}

interface ConfirmRequest {
  title: string;
  description: ReactNode;
  confirm: string;
  danger?: boolean;
}

const ConfirmContext = createContext<(request: ConfirmRequest) => Promise<boolean>>(() => Promise.resolve(false));

// Asks before an action that cannot be undone, in the app's own dialog rather
// than the browser's.
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const resolver = useRef<(answer: boolean) => void>(() => undefined);
  const ask = useCallback((next: ConfirmRequest) => {
    setRequest(next);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);
  const answer = (value: boolean) => {
    resolver.current(value);
    setRequest(null);
  };
  return (
    <ConfirmContext value={ask}>
      {children}
      <Dialog
        open={request !== null}
        onOpenChange={(open) => { if (!open) answer(false); }}
        title={request?.title ?? ""}
        description={request?.description}
        footer={
          <>
            <Button onClick={() => answer(false)}>Отмена</Button>
            <Button variant={request?.danger ? "danger" : "primary"} onClick={() => answer(true)}>{request?.confirm}</Button>
          </>
        }
      />
    </ConfirmContext>
  );
}

export function useConfirm(): (request: ConfirmRequest) => Promise<boolean> {
  return use(ConfirmContext);
}
