import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { StrictMode, useEffect, useState, type ReactElement } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";

import { api } from "./api";
import { completeSignIn, signIn, signOut } from "./auth";
import { Access } from "./pages/Access";
import { AgentPage } from "./pages/AgentPage";
import { Catalog } from "./pages/Catalog";
import { ColumnPage } from "./pages/ColumnPage";
import { Compliance } from "./pages/Compliance";
import { Identities } from "./pages/Identities";
import { Infrastructure } from "./pages/Infrastructure";
import { Overview } from "./pages/Overview";
import { SourcePage } from "./pages/SourcePage";
import { TablePage } from "./pages/TablePage";
import { Tenants } from "./pages/Tenants";
import { type Permission, PermissionsProvider } from "./permissions";
import { visibleSections } from "./sections";
import "./styles.css";

const client = new QueryClient({
  defaultOptions: { queries: { refetchInterval: 15_000, retry: 1, staleTime: 5_000 } },
});

const themes = ["auto", "light", "dark"] as const;
const themeNames = { auto: "Как в системе", light: "Светлая", dark: "Тёмная" };

function ThemeSwitch() {
  const [theme, setTheme] = useState<(typeof themes)[number]>(() => {
    try {
      return (localStorage.getItem("theme") as (typeof themes)[number]) ?? "auto";
    } catch {
      return "auto";
    }
  });
  useEffect(() => {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("theme", theme);
    } catch {
      // Without storage the choice lasts until reload, which is harmless.
    }
  }, [theme]);
  return (
    <button onClick={() => setTheme(themes[(themes.indexOf(theme) + 1) % themes.length] ?? "auto")}>
      Тема: {themeNames[theme]}
    </button>
  );
}

const pages: Record<string, (tenantId: string) => ReactElement> = {
  "/overview": () => <Overview />,
  "/catalog": () => <Catalog />,
  "/access": () => <Access />,
  "/identities": () => <Identities />,
  "/compliance": () => <Compliance />,
  "/infrastructure": (tenantId) => <Infrastructure tenantId={tenantId} />,
  "/tenants": () => <Tenants />,
};

// Every object has an address, so any list can link to it (ADR-0010).
const objectPages: { path: string; needs: Permission; element: ReactElement }[] = [
  { path: "/sources/:id", needs: "getSource", element: <SourcePage /> },
  { path: "/agents/:id", needs: "getAgent", element: <AgentPage /> },
  { path: "/tables/:id", needs: "getCatalogTable", element: <TablePage /> },
  { path: "/columns/:id", needs: "getCatalogColumn", element: <ColumnPage /> },
];

function Shell() {
  const me = useQuery({ queryKey: ["me"], queryFn: api.me, refetchInterval: false });
  if (me.isPending) return <div className="login">Загрузка…</div>;
  if (me.isError) return <div className="login">Нет доступа: {me.error.message}</div>;

  const permissions = new Set(me.data.permissions);
  const visible = visibleSections((permission) => permissions.has(permission));
  const tenantId = me.data.tenantId ?? "";
  return (
    <PermissionsProvider permissions={me.data.permissions}>
      <div className="shell">
        <nav className="side" aria-label="Разделы">
          <div className="brand">DataGuard</div>
          {visible.map((section) => (
            <NavLink key={section.path} to={section.path}>{section.title}</NavLink>
          ))}
          <div className="side-foot">
            <ThemeSwitch />
            <button onClick={() => void signOut()}>Выйти</button>
          </div>
        </nav>
        <main>
          {visible.length === 0 ? (
            <div className="empty">Учётной записи пока не выдано ни одного разрешения. Обратитесь к администратору организации.</div>
          ) : (
            <Routes>
              {visible.map((section) => (
                <Route key={section.path} path={section.path} element={pages[section.path]?.(tenantId)} />
              ))}
              {objectPages.filter((page) => permissions.has(page.needs)).map((page) => (
                <Route key={page.path} path={page.path} element={page.element} />
              ))}
              <Route path="*" element={<Navigate to={visible[0]?.path ?? "/"} replace />} />
            </Routes>
          )}
        </main>
      </div>
    </PermissionsProvider>
  );
}

function App() {
  const [state, setState] = useState<"loading" | "signed-in" | "signed-out" | "failed">("loading");
  const [loginError, setLoginError] = useState("");
  useEffect(() => {
    completeSignIn()
      .then((user) => setState(user ? "signed-in" : "signed-out"))
      .catch(() => setState("failed"));
  }, []);

  if (state === "loading") return <div className="login">Загрузка…</div>;
  if (state === "failed") return <div className="login">Сервис входа недоступен. Обновите страницу позже.</div>;
  if (state === "signed-out") {
    return (
      <div className="login">
        <div className="card">
          <h1>DataGuard</h1>
          <p className="lead">Обнаружение чувствительных данных и контроль доступа к ним.</p>
          <button
            className="primary"
            onClick={() => {
              setLoginError("");
              signIn().catch(() => setLoginError("Сервис входа недоступен. Попробуйте позже или обратитесь к администратору."));
            }}
          >
            Войти
          </button>
          {loginError && <div className="error" role="alert">{loginError}</div>}
        </div>
      </div>
    );
  }
  return (
    <BrowserRouter>
      <Shell />
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
