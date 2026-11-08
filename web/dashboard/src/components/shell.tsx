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

// The navigation sits on a dark panel in both themes: it frames the work area
// and keeps its place however light the page is.
const navGroup = "px-3 pb-1.5 text-[11px] font-semibold tracking-[0.08em] text-nav-fg-3 uppercase";
const navItem = "flex items-center gap-3 rounded-lg px-3 text-sm text-nav-fg-2 transition-colors hover:bg-nav-hover hover:text-nav-fg";

function Navigation({ visible, onNavigate }: { visible: readonly Section[]; onNavigate?: () => void }) {
  const current = sectionOf(useLocation().pathname);
  return (
    <nav aria-label="Разделы" className="flex flex-col gap-6">
      {groupSections(visible).map(({ group, sections }) => (
        <div key={group || "start"} className="flex flex-col gap-0.5">
          {group && <div className={navGroup}>{group}</div>}
          {sections.map((section) => {
            const Icon = section.icon;
            const active = section === current;
            return (
              <NavLink
                key={section.path}
                to={section.path}
                onClick={onNavigate}
                aria-current={active ? "page" : undefined}
                className={cn(navItem, "relative h-9", active && "bg-nav-active font-medium text-nav-fg hover:bg-nav-active")}
              >
                {active && <span aria-hidden className="absolute inset-y-2 left-0 w-[3px] rounded-full bg-nav-accent" />}
                <Icon aria-hidden className={cn("size-4 shrink-0", active ? "text-nav-accent" : "text-nav-fg-3")} />
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

// The account's own shortcuts, from its settings in the center.
function Personal({ onNavigate }: { onNavigate?: () => void }) {
  const favorites = useFavorites();
  const views = useViews();
  return (
    <>
      {favorites.value.length > 0 && (
        <div className="flex flex-col gap-0.5">
          <div className={navGroup}>Избранное</div>
          {favorites.value.slice(0, 8).map((item) => (
            <Link key={`${item.kind}-${item.id}`} to={pathOf(item)} onClick={onNavigate} className={cn(navItem, "h-8")} title={`${kindNames[item.kind]} ${item.label}`}>
              <Star aria-hidden className="size-4 shrink-0 text-nav-fg-3" />
              <span className="truncate">{item.label}</span>
            </Link>
          ))}
        </div>
      )}
      {views.value.length > 0 && (
        <div className="flex flex-col gap-0.5">
          <div className={navGroup}>Мои представления</div>
          {views.value.slice(0, 8).map((view) => (
            <Link key={view.id} to={`${view.path}${view.query ? `?${view.query}` : ""}`} onClick={onNavigate} className={cn(navItem, "h-8")}>
              <Bookmark aria-hidden className="size-4 shrink-0 text-nav-fg-3" />
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
    <div className="flex h-16 items-center gap-3 px-3">
      <span className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-accent to-accent-hover text-accent-fg shadow-md shadow-accent/30">
        <Shield aria-hidden className="size-[18px]" strokeWidth={2.25} />
      </span>
      <span className="text-base font-semibold tracking-tight text-nav-fg">DataGuard</span>
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
            <span aria-hidden className="grid size-7 shrink-0 place-items-center rounded-full bg-accent text-xs font-semibold text-accent-fg uppercase">
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
    // Ctrl K anywhere; a slash when it would not be typed into a field.
    const open = (event: KeyboardEvent) => {
      const typing = event.target instanceof HTMLElement && event.target.closest("input, textarea, select, [contenteditable=true], [role=dialog]") !== null;
      if (((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") || (event.key === "/" && !typing && !event.metaKey && !event.ctrlKey && !event.altKey)) {
        event.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", open);
    return () => window.removeEventListener("keydown", open);
  }, []);

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-nav-border bg-nav px-3 lg:flex">
        <Brand />
        <div className="mt-3 min-h-0 flex-1 overflow-y-auto pb-4 [scrollbar-color:var(--nav-active)_transparent]">
          <Navigation visible={visible} />
        </div>
      </aside>

      {navOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button type="button" aria-label="Закрыть меню" className="absolute inset-0 bg-black/40" onClick={() => setNavOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-72 flex-col bg-nav px-3 shadow-xl">
            <div className="flex items-center justify-between">
              <Brand />
              <Button variant="ghost" size="icon-sm" className="text-nav-fg-2 hover:bg-nav-hover hover:text-nav-fg" aria-label="Закрыть меню" onClick={() => setNavOpen(false)}><X /></Button>
            </div>
            <div className="mt-3 min-h-0 flex-1 overflow-y-auto pb-4">
              <Navigation visible={visible} onNavigate={() => setNavOpen(false)} />
            </div>
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-bg/85 px-4 backdrop-blur-md sm:px-8">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Меню" onClick={() => setNavOpen(true)}>
            <MenuIcon />
          </Button>
          <button
            type="button"
            onClick={() => setSearchOpen(true)}
            className="flex h-10 w-full max-w-lg min-w-0 cursor-pointer items-center gap-2.5 rounded-lg border border-border bg-surface px-3 text-sm text-fg-3 shadow-xs transition-[border-color,box-shadow] hover:border-border-strong hover:shadow-card"
          >
            <Search aria-hidden className="size-4 shrink-0" />
            <span className="truncate sm:hidden">Поиск</span>
            <span className="hidden truncate sm:inline">Поиск источников, таблиц, колонок, пользователей</span>
            <kbd className="ml-auto hidden rounded-md border border-border bg-surface-2 px-1.5 py-px font-sans text-[11px] font-medium text-fg-3 sm:inline" title="Или клавиша /">Ctrl K</kbd>
          </button>
          <div className="ml-auto">
            <Account />
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1480px] min-w-0 flex-1 px-4 py-8 sm:px-8">{children}</main>
      </div>

      <SearchPalette open={searchOpen} onOpenChange={setSearchOpen} visible={visible} />
    </div>
  );
}
