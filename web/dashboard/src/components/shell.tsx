import { useQuery } from "@tanstack/react-query";
import { Bookmark, LogOut, Menu as MenuIcon, Monitor, Moon, Search, Shield, Star, Sun, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router";

import { displayName, signOut } from "../auth";
import { groupSections, type Section, sectionOf } from "../sections";
import { kindNames, pathOf, useFavorites, useViews } from "../workspace";
import { SearchPalette } from "./search";
import { Button } from "./ui/button";
import { cn } from "./ui/cn";
import { Menu, MenuItem, MenuSeparator } from "./ui/menu";
import { groupLabel } from "./ui/panel";

const themes = [
  { id: "auto", label: "Как в системе", icon: Monitor },
  { id: "light", label: "Светлая", icon: Sun },
  { id: "dark", label: "Тёмная", icon: Moon },
] as const;

type Theme = (typeof themes)[number]["id"];

function useTheme(): [Theme, (theme: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem("theme");
      return themes.some((item) => item.id === saved) ? (saved as Theme) : "auto";
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
      // Without storage the choice lasts until reload.
    }
  }, [theme]);
  return [theme, setTheme];
}

function Navigation({ visible, onNavigate }: { visible: readonly Section[]; onNavigate?: () => void }) {
  const current = sectionOf(useLocation().pathname);
  return (
    <nav aria-label="Разделы" className="flex flex-col gap-6">
      {groupSections(visible).map(({ group, sections }) => (
        <div key={group || "start"} className="flex flex-col gap-1">
          {group && <div className={cn("px-3 pb-1", groupLabel)}>{group}</div>}
          {sections.map((section) => {
            const Icon = section.icon;
            const active = section === current;
            return (
              <NavLink
                key={section.path}
                to={section.path}
                onClick={onNavigate}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "flex h-9 items-center gap-3 rounded-md px-3 text-sm text-fg-2 transition-colors hover:bg-surface-2 hover:text-fg",
                  active && "bg-surface-2 font-medium text-fg",
                )}
              >
                <Icon aria-hidden className={cn("size-4 shrink-0", active ? "text-accent" : "text-fg-3")} />
                {section.title}
              </NavLink>
            );
          })}
        </div>
      ))}
      <Personal onNavigate={onNavigate} />
    </nav>
  );
}

const personalLink = "flex h-8 items-center gap-3 rounded-md px-3 text-sm text-fg-2 transition-colors hover:bg-surface-2 hover:text-fg";

// The account's own shortcuts, from its settings in the center.
function Personal({ onNavigate }: { onNavigate?: () => void }) {
  const favorites = useFavorites();
  const views = useViews();
  return (
    <>
      {favorites.value.length > 0 && (
        <div className="flex flex-col gap-1">
          <div className={cn("px-3 pb-1", groupLabel)}>Избранное</div>
          {favorites.value.slice(0, 8).map((item) => (
            <Link key={`${item.kind}-${item.id}`} to={pathOf(item)} onClick={onNavigate} className={personalLink} title={`${kindNames[item.kind]} ${item.label}`}>
              <Star aria-hidden className="size-4 shrink-0 text-fg-3" />
              <span className="truncate">{item.label}</span>
            </Link>
          ))}
        </div>
      )}
      {views.value.length > 0 && (
        <div className="flex flex-col gap-1">
          <div className={cn("px-3 pb-1", groupLabel)}>Мои представления</div>
          {views.value.slice(0, 8).map((view) => (
            <Link key={view.id} to={`${view.path}${view.query ? `?${view.query}` : ""}`} onClick={onNavigate} className={personalLink}>
              <Bookmark aria-hidden className="size-4 shrink-0 text-fg-3" />
              <span className="truncate">{view.name}</span>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

function Brand() {
  return (
    <div className="flex h-16 items-center gap-2.5 px-3">
      <span className="grid size-7 place-items-center rounded-md bg-accent text-accent-fg">
        <Shield aria-hidden className="size-4" />
      </span>
      <span className="text-base font-semibold tracking-tight text-fg">DataGuard</span>
    </div>
  );
}

function Account() {
  const [theme, setTheme] = useTheme();
  const name = useQuery({ queryKey: ["display-name"], queryFn: displayName, staleTime: Infinity, refetchInterval: false });
  const current = themes.find((item) => item.id === theme) ?? themes[0];
  const ThemeIcon = current.icon;
  return (
    <div className="flex items-center gap-1">
      <Menu
        label="Тема"
        trigger={<Button variant="ghost" size="icon" aria-label={`Тема: ${current.label}`} title={`Тема: ${current.label}`}><ThemeIcon /></Button>}
      >
        {themes.map((item) => {
          const Icon = item.icon;
          return (
            <MenuItem key={item.id} onSelect={() => setTheme(item.id)} icon={<Icon />} className={item.id === theme ? "font-medium" : undefined}>
              {item.label}
            </MenuItem>
          );
        })}
      </Menu>
      <Menu
        label={name.data || "Учётная запись"}
        trigger={
          <Button variant="ghost" className="max-w-48 gap-2 px-2" aria-label="Учётная запись">
            <span aria-hidden className="grid size-6 shrink-0 place-items-center rounded-full bg-accent-bg text-xs font-semibold text-accent uppercase">
              {(name.data || "?").slice(0, 1)}
            </span>
            <span className="hidden truncate text-sm text-fg md:inline">{name.data}</span>
          </Button>
        }
      >
        <MenuSeparator />
        <MenuItem onSelect={() => void signOut()} icon={<LogOut />}>Выйти</MenuItem>
      </Menu>
    </div>
  );
}

export function AppShell({ visible, children }: { visible: readonly Section[]; children: ReactNode }) {
  const [navOpen, setNavOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const { pathname } = useLocation();

  useEffect(() => setNavOpen(false), [pathname]);
  useEffect(() => {
    const open = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", open);
    return () => window.removeEventListener("keydown", open);
  }, []);

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-border bg-surface px-3 lg:flex">
        <Brand />
        <div className="mt-2 min-h-0 flex-1 overflow-y-auto pb-4">
          <Navigation visible={visible} />
        </div>
      </aside>

      {navOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button type="button" aria-label="Закрыть меню" className="absolute inset-0 bg-black/30" onClick={() => setNavOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-72 flex-col border-r border-border bg-surface px-3 shadow-xl">
            <div className="flex items-center justify-between">
              <Brand />
              <Button variant="ghost" size="icon-sm" aria-label="Закрыть меню" onClick={() => setNavOpen(false)}><X /></Button>
            </div>
            <div className="mt-2 min-h-0 flex-1 overflow-y-auto pb-4">
              <Navigation visible={visible} onNavigate={() => setNavOpen(false)} />
            </div>
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-surface/95 px-4 backdrop-blur-sm sm:px-8">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Меню" onClick={() => setNavOpen(true)}>
            <MenuIcon />
          </Button>
          <button
            type="button"
            onClick={() => setSearchOpen(true)}
            className="flex h-10 w-full max-w-lg min-w-0 cursor-pointer items-center gap-2.5 rounded-lg border border-border bg-bg px-3 text-sm text-fg-3 transition-colors hover:border-border-strong"
          >
            <Search aria-hidden className="size-4 shrink-0" />
            <span className="truncate">Поиск источников, таблиц, колонок, пользователей</span>
            <kbd className="ml-auto hidden rounded border border-border bg-surface px-1.5 font-sans text-xs text-fg-3 sm:inline">Ctrl K</kbd>
          </button>
          <div className="ml-auto">
            <Account />
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1480px] min-w-0 flex-1 px-4 py-8 sm:px-8 lg:px-10">{children}</main>
      </div>

      <SearchPalette open={searchOpen} onOpenChange={setSearchOpen} visible={visible} />
    </div>
  );
}
