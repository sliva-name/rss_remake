import { CheckCircle2, X, XCircle } from "lucide-react";
import { Toast } from "radix-ui";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

import { cn } from "./cn";

interface Notice {
  id: number;
  tone: "ok" | "bad";
  title: string;
  description?: string;
}

const NotifyContext = createContext<(notice: Omit<Notice, "id">) => void>(() => undefined);

// The outcome of an action the user started: queued, saved, refused.
export function NotificationsProvider({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<Notice[]>([]);
  const notify = useCallback((notice: Omit<Notice, "id">) => {
    setNotices((current) => [...current, { ...notice, id: Date.now() + Math.random() }]);
  }, []);
  const dismiss = (id: number) => setNotices((current) => current.filter((notice) => notice.id !== id));
  return (
    <NotifyContext.Provider value={notify}>
      <Toast.Provider swipeDirection="right" duration={6000} label="Уведомление">
        {children}
        {notices.map((notice) => (
          <Toast.Root
            key={notice.id}
            onOpenChange={(open) => { if (!open) dismiss(notice.id); }}
            className="flex items-start gap-2.5 rounded-lg border border-border bg-surface p-3 shadow-lg"
          >
            {notice.tone === "ok" ? <CheckCircle2 aria-hidden className="mt-0.5 size-4 shrink-0 text-ok" /> : <XCircle aria-hidden className="mt-0.5 size-4 shrink-0 text-bad" />}
            <div className="min-w-0 flex-1">
              <Toast.Title className={cn("text-sm font-medium", notice.tone === "bad" ? "text-bad" : "text-fg")}>{notice.title}</Toast.Title>
              {notice.description && <Toast.Description className="mt-0.5 text-sm text-fg-2">{notice.description}</Toast.Description>}
            </div>
            <Toast.Close aria-label="Закрыть" className="cursor-pointer rounded p-0.5 text-fg-3 hover:text-fg">
              <X className="size-4" />
            </Toast.Close>
          </Toast.Root>
        ))}
        <Toast.Viewport className="fixed right-4 bottom-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2 outline-none" />
      </Toast.Provider>
    </NotifyContext.Provider>
  );
}

export function useNotify(): (notice: Omit<Notice, "id">) => void {
  return useContext(NotifyContext);
}
