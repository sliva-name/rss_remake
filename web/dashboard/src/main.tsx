import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, StrictMode, Suspense, useEffect, useRef, useState, type ReactElement } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";

import { completeSignIn, SignInRefused, signIn } from "./auth";
import { AppShell } from "./components/shell";
import { Button } from "./components/ui/button";
import { ConfirmProvider } from "./components/ui/dialog";
import { TooltipProvider } from "./components/ui/menu";
import { EmptyState, Loading } from "./components/ui/state";
import { NotificationsProvider } from "./components/ui/toast";
import { categoryNeeds } from "./links";
import { useMe } from "./me";
import { type Permission, PermissionsProvider } from "./permissions";
import { movedSections, visibleSections } from "./sections";
import "./styles.css";

const client = new QueryClient({
  defaultOptions: { queries: { refetchInterval: 15_000, retry: 1, staleTime: 5_000 } },
});

// Each page is its own chunk: the charting library, for one, loads only with
// the overview.
const Overview = lazy(() => import("./pages/Overview").then((module) => ({ default: module.Overview })));
const Inventory = lazy(() => import("./pages/Inventory").then((module) => ({ default: module.Inventory })));
const Classification = lazy(() => import("./pages/Classification").then((module) => ({ default: module.Classification })));
const Audit = lazy(() => import("./pages/Audit").then((module) => ({ default: module.Audit })));
const Principals = lazy(() => import("./pages/Principals").then((module) => ({ default: module.Principals })));
const SourcesList = lazy(() => import("./pages/SourcesList").then((module) => ({ default: module.SourcesList })));
const AgentsList = lazy(() => import("./pages/AgentsList").then((module) => ({ default: module.AgentsList })));
const Policy = lazy(() => import("./pages/Policy").then((module) => ({ default: module.Policy })));
const Environments = lazy(() => import("./pages/Admin").then((module) => ({ default: module.Environments })));
const Tenants = lazy(() => import("./pages/Admin").then((module) => ({ default: module.Tenants })));
const SourcePage = lazy(() => import("./pages/SourcePage").then((module) => ({ default: module.SourcePage })));
const AgentPage = lazy(() => import("./pages/AgentPage").then((module) => ({ default: module.AgentPage })));
const TablePage = lazy(() => import("./pages/TablePage").then((module) => ({ default: module.TablePage })));
const ColumnPage = lazy(() => import("./pages/ColumnPage").then((module) => ({ default: module.ColumnPage })));
const CategoryPage = lazy(() => import("./pages/CategoryPage").then((module) => ({ default: module.CategoryPage })));

const pages: Record<string, (tenantId: string) => ReactElement> = {
  "/overview": () => <Overview />,
  "/inventory": () => <Inventory />,
  "/classification": () => <Classification />,
  "/audit": () => <Audit />,
  "/principals": () => <Principals />,
  "/sources": (tenantId) => <SourcesList tenantId={tenantId} />,
  "/agents": () => <AgentsList />,
  "/policy": () => <Policy />,
  "/environments": () => <Environments />,
  "/tenants": () => <Tenants />,
};

// Every object has an address, so any list can link to it (ADR-0010).
const objectPages: { path: string; needs: readonly Permission[]; element: ReactElement }[] = [
  { path: "/sources/:id", needs: ["getSource"], element: <SourcePage /> },
  { path: "/agents/:id", needs: ["getAgent"], element: <AgentPage /> },
  { path: "/tables/:id", needs: ["getCatalogTable"], element: <TablePage /> },
  { path: "/columns/:id", needs: ["getCatalogColumn"], element: <ColumnPage /> },
  { path: "/categories/:id", needs: categoryNeeds, element: <CategoryPage /> },
];

// An old address opens its new place with the filters it carried.
function Moved({ to }: { to: string }) {
  const { search } = useLocation();
  const [path, preset = ""] = to.split("?");
  const merged = new URLSearchParams(preset);
  for (const [key, value] of new URLSearchParams(search)) merged.set(key, value);
  const query = merged.toString();
  return <Navigate to={`${path}${query ? `?${query}` : ""}`} replace />;
}

function Workspace() {
  const me = useMe();
  if (me.isPending) return <div className="grid min-h-screen place-items-center text-sm text-fg-2">Загрузка…</div>;
  if (me.isError) return <div className="grid min-h-screen place-items-center text-sm text-bad">Нет доступа: {me.error.message}</div>;

  const permissions = new Set(me.data.permissions);
  const visible = visibleSections((permission) => permissions.has(permission));
  const tenantId = me.data.tenantId ?? "";
  return (
    <PermissionsProvider permissions={me.data.permissions}>
      <AppShell visible={visible}>
        {visible.length === 0 ? (
          <EmptyState title="Разрешений пока нет">Учётной записи не выдано ни одного разрешения. Обратитесь к администратору организации.</EmptyState>
        ) : (
          <Suspense fallback={<Loading rows={6} />}>
            <Routes>
              {visible.map((section) => (
                <Route key={section.path} path={section.path} element={pages[section.path]?.(tenantId)} />
              ))}
              {objectPages.filter((page) => page.needs.some((permission) => permissions.has(permission))).map((page) => (
                <Route key={page.path} path={page.path} element={page.element} />
              ))}
              {Object.entries(movedSections).map(([from, to]) => (
                <Route key={from} path={from} element={<Moved to={to} />} />
              ))}
              <Route path="*" element={<Navigate to={visible[0]?.path ?? "/"} replace />} />
            </Routes>
          </Suspense>
        )}
      </AppShell>
    </PermissionsProvider>
  );
}

const signInUnavailable = "Сервис входа недоступен. Попробуйте позже или обратитесь к администратору.";

function refusal(code: string): string {
  if (code === "access_denied") return "Вход отклонён. Обратитесь к администратору организации.";
  return `Сервис входа вернул ошибку ${code}. Попробуйте ещё раз или обратитесь к администратору.`;
}

// Signed-out users go straight to the provider's sign-in page, styled like the
// dashboard. A card appears only when that is impossible.
function App() {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "signed-in" } | { kind: "problem"; message: string }>({ kind: "loading" });
  const started = useRef(false);
  const goSignIn = () => {
    setState({ kind: "loading" });
    signIn().catch(() => setState({ kind: "problem", message: signInUnavailable }));
  };
  useEffect(() => {
    // The authorization code can be exchanged once; StrictMode runs effects twice.
    if (started.current) return;
    started.current = true;
    completeSignIn()
      .then((user) => (user ? setState({ kind: "signed-in" }) : goSignIn()))
      .catch((error: unknown) => setState({ kind: "problem", message: error instanceof SignInRefused ? refusal(error.code) : signInUnavailable }));
  }, []);

  if (state.kind === "loading") return <div className="grid min-h-screen place-items-center text-sm text-fg-2">Переход ко входу…</div>;
  if (state.kind === "problem") {
    return (
      <div className="grid min-h-screen place-items-center px-4">
        <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-6">
          <h1 className="text-xl font-semibold tracking-tight text-fg">DataGuard</h1>
          <p role="alert" className="mt-1 mb-4 text-sm text-fg-2">{state.message}</p>
          <Button variant="primary" className="w-full justify-center" onClick={goSignIn}>Попробовать снова</Button>
        </div>
      </div>
    );
  }
  return (
    <BrowserRouter>
      <TooltipProvider>
        <NotificationsProvider>
          <ConfirmProvider>
            <Workspace />
          </ConfirmProvider>
        </NotificationsProvider>
      </TooltipProvider>
    </BrowserRouter>
  );
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={client}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  );
}
