import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";

import { api } from "./api";
import { completeSignIn, signIn, signOut } from "./auth";
import { Access } from "./pages/Access";
import { Catalog } from "./pages/Catalog";
import { Compliance } from "./pages/Compliance";
import { Identities } from "./pages/Identities";
import { Infrastructure } from "./pages/Infrastructure";
import { Overview } from "./pages/Overview";
import { Tenants } from "./pages/Tenants";
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

function Shell() {
  const me = useQuery({ queryKey: ["me"], queryFn: api.me, refetchInterval: false });
  if (me.isPending) return <div className="login">Загрузка…</div>;
  if (me.isError) return <div className="login">Нет доступа: {me.error.message}</div>;

  const inTenant = me.data.tenantId !== undefined;
  const platform = me.data.roles.includes("platform_admin");
  return (
    <div className="shell">
      <nav className="side" aria-label="Разделы">
        <div className="brand">DataGuard</div>
        {inTenant && (
          <>
            <NavLink to="/overview">Обзор</NavLink>
            <NavLink to="/catalog">Каталог данных</NavLink>
            <NavLink to="/access">Обращения</NavLink>
            <NavLink to="/identities">Пользователи</NavLink>
            <NavLink to="/compliance">Отчёты</NavLink>
            <NavLink to="/infrastructure">Инфраструктура</NavLink>
          </>
        )}
        {platform && <NavLink to="/tenants">Организации</NavLink>}
        <div className="side-foot">
          <ThemeSwitch />
          <button onClick={() => void signOut()}>Выйти</button>
        </div>
      </nav>
      <main>
        <Routes>
          {inTenant && (
            <>
              <Route path="/overview" element={<Overview />} />
              <Route path="/catalog" element={<Catalog />} />
              <Route path="/access" element={<Access />} />
              <Route path="/identities" element={<Identities />} />
              <Route path="/compliance" element={<Compliance />} />
              <Route path="/infrastructure" element={<Infrastructure roles={me.data.roles} />} />
            </>
          )}
          {platform && <Route path="/tenants" element={<Tenants />} />}
          <Route path="*" element={<Navigate to={inTenant ? "/overview" : "/tenants"} replace />} />
        </Routes>
      </main>
    </div>
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
