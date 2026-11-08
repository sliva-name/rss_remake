import { useQuery } from "@tanstack/react-query";
import { Columns3, CornerDownLeft, History, Plug, Search, Star, Table2, UserRound } from "lucide-react";
import { Dialog } from "radix-ui";
import { useEffect, useMemo, useState, type ComponentType } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../api";
import { category, count } from "../labels";
import { paths } from "../links";
import { useCan } from "../permissions";
import type { Section } from "../sections";
import { kindNames, pathOf, useFavorites, useRecent } from "../workspace";
import { cn } from "./ui/cn";

interface Hit {
  key: string;
  group: string;
  title: string;
  context?: string;
  icon: ComponentType<{ className?: string }>;
  to: string;
}

function useDebounced(value: string, delay: number): string {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

// One box for everything the user can open: sections by title, and sources,
// tables and columns by name through the server, which returns only what the
// user may read.
export function SearchPalette({ open, onOpenChange, visible }: { open: boolean; onOpenChange: (open: boolean) => void; visible: readonly Section[] }) {
  const can = useCan();
  const navigate = useNavigate();
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const settled = useDebounced(text.trim(), 200);
  const searchable = can("search") && settled.length >= 2;
  const found = useQuery({ queryKey: ["search", settled], queryFn: () => api.search(settled), enabled: open && searchable, staleTime: 30_000 });
  const recent = useRecent();
  const favorites = useFavorites();

  const hits = useMemo<Hit[]>(() => {
    const needle = text.trim().toLowerCase();
    const result: Hit[] = [];
    // An empty box offers what the user opened lately and kept, before sections.
    if (!needle) {
      for (const item of recent.value.slice(0, 6)) {
        result.push({ key: `${item.kind}-${item.id}`, group: "Недавние", title: item.label, context: [kindNames[item.kind], item.context].filter(Boolean).join(" · "), icon: History, to: pathOf(item) });
      }
      for (const item of favorites.value.slice(0, 6)) {
        result.push({ key: `${item.kind}-${item.id}`, group: "Избранное", title: item.label, context: [kindNames[item.kind], item.context].filter(Boolean).join(" · "), icon: Star, to: pathOf(item) });
      }
    }
    result.push(...visible
      .filter((section) => !needle || section.title.toLowerCase().includes(needle))
      .map((section) => ({ key: section.path, group: "Разделы", title: section.title, icon: section.icon, to: section.path })));
    if (searchable && found.data) {
      for (const hit of found.data.principals) {
        const name = hit.applicationPrincipal || hit.databasePrincipal;
        result.push({
          key: `${hit.databasePrincipal}\u0000${hit.applicationPrincipal}`, group: "Пользователи СУБД", title: name,
          context: `${hit.applicationPrincipal ? `через ${hit.databasePrincipal} · ` : ""}${count(hit.events)} обращений за 30 дней`,
          icon: UserRound, to: paths.events({ principal: name, period: "30d" }),
        });
      }
      for (const hit of found.data.sources) result.push({ key: hit.id, group: "Источники", title: hit.name, context: hit.context, icon: Plug, to: paths.source(hit.id) });
      for (const hit of found.data.tables) result.push({ key: hit.id, group: "Таблицы", title: hit.name, context: hit.context, icon: Table2, to: paths.table(hit.id) });
      for (const hit of found.data.columns) {
        const kinds = (hit.categories ?? []).map(category).join(", ");
        result.push({ key: hit.id, group: "Колонки", title: hit.name, context: kinds ? `${hit.context} · ${kinds}` : hit.context, icon: Columns3, to: paths.column(hit.id) });
      }
    }
    return result;
  }, [text, visible, searchable, found.data, recent.value, favorites.value]);

  useEffect(() => setActive(0), [hits.length, text]);
  useEffect(() => {
    if (!open) setText("");
  }, [open]);

  const go = (hit: Hit | undefined) => {
    if (!hit) return;
    onOpenChange(false);
    navigate(hit.to);
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Content
          className="fixed top-[12vh] left-1/2 z-50 flex max-h-[70vh] w-[min(44rem,calc(100vw-2rem))] -translate-x-1/2 flex-col overflow-hidden rounded-lg border border-border bg-surface shadow-2xl focus:outline-none"
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") { event.preventDefault(); setActive((index) => Math.min(index + 1, hits.length - 1)); }
            if (event.key === "ArrowUp") { event.preventDefault(); setActive((index) => Math.max(index - 1, 0)); }
            if (event.key === "Enter") { event.preventDefault(); go(hits[active]); }
          }}
        >
          <Dialog.Title className="sr-only">Поиск</Dialog.Title>
          <Dialog.Description className="sr-only">Разделы, источники, таблицы и колонки</Dialog.Description>
          <div className="flex items-center gap-2 border-b border-border px-3">
            <Search aria-hidden className="size-4 text-fg-3" />
            <input
              autoFocus
              value={text}
              onChange={(event) => setText(event.target.value)}
              placeholder="Источник, таблица, колонка, пользователь или раздел"
              aria-label="Что найти"
              role="combobox"
              aria-expanded
              aria-controls="search-results"
              aria-activedescendant={hits[active] ? `hit-${active}` : undefined}
              className="h-14 w-full bg-transparent text-base text-fg placeholder:text-fg-3 focus:outline-none"
            />
          </div>
          <div id="search-results" role="listbox" className="min-h-0 overflow-y-auto p-1.5">
            {hits.length === 0 ? (
              <p className="px-3 py-8 text-center text-sm text-fg-2">
                {searchable && found.isPending ? "Ищем…" : text.trim().length === 1 ? "Введите хотя бы два символа." : "Ничего не найдено."}
              </p>
            ) : (
              hits.map((hit, index) => {
                const Icon = hit.icon;
                const first = index === 0 || hits[index - 1]?.group !== hit.group;
                return (
                  <div key={`${hit.group}-${hit.key}`}>
                    {first && <div className="px-2.5 pt-3 pb-1.5 text-xs font-semibold tracking-wide text-fg-3 uppercase">{hit.group}</div>}
                    <div
                      id={`hit-${index}`}
                      role="option"
                      aria-selected={index === active}
                      onMouseMove={() => setActive(index)}
                      onClick={() => go(hit)}
                      className={cn("flex cursor-pointer items-center gap-3 rounded-md px-2.5 py-2.5 text-sm", index === active && "bg-surface-2")}
                    >
                      <Icon className="size-4 shrink-0 text-fg-3" />
                      <span className="truncate font-medium text-fg">{hit.title}</span>
                      {hit.context && <span className="min-w-0 truncate text-xs text-fg-3">{hit.context}</span>}
                      {index === active && <CornerDownLeft aria-hidden className="ml-auto size-3.5 shrink-0 text-fg-3" />}
                    </div>
                  </div>
                );
              })
            )}
            {searchable && found.isError && <p className="px-3 py-2 text-sm text-bad">Поиск недоступен: {found.error.message}</p>}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
