import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Bookmark, BookmarkPlus, Settings2, Star, Trash2 } from "lucide-react";
import { useEffect, useRef, useState, type SubmitEvent } from "react";
import { useLocation, useNavigate } from "react-router";

import { api, type Schemas } from "./api";
import { Button } from "./components/ui/button";
import { Dialog } from "./components/ui/dialog";
import { Field, Input } from "./components/ui/form";
import { Menu, MenuItem, MenuSeparator } from "./components/ui/menu";
import { useNotify } from "./components/ui/toast";
import { paths } from "./links";
import { useCan } from "./permissions";
import { usePermittedQuery } from "./queries";

// Personal settings live in the center (ADR-0010): they follow the account to
// another browser. They hold addresses and names, never data values.

export type ObjectKind = "source" | "agent" | "table" | "column" | "category";

export interface ObjectRef {
  kind: ObjectKind;
  id: string;
  label: string;
  context?: string;
}

export interface RecentRef extends ObjectRef {
  at: string;
}

export interface SavedView {
  id: string;
  name: string;
  path: string;
  query: string;
}

export interface OverviewLayout {
  hidden: string[];
  order: string[];
}

export const kindNames: Record<ObjectKind, string> = {
  source: "Источник",
  agent: "Агент",
  table: "Таблица",
  column: "Колонка",
  category: "Категория",
};

export function pathOf(item: ObjectRef): string {
  switch (item.kind) {
    case "source":
      return paths.source(item.id);
    case "agent":
      return paths.agent(item.id);
    case "table":
      return paths.table(item.id);
    case "column":
      return paths.column(item.id);
    case "category":
      return paths.category(item.id);
  }
}

const maxRecent = 12;

// A setting of the signed-in account, with saving that shows at once and is
// undone if the server refuses. Saving is offered only once the stored value
// has loaded, so a failed read never lets a save replace it with the fallback.
// Without permission it is the fallback and saving does nothing: platform
// administrators have no organization to keep settings in.
export function usePreference<T>(key: Schemas["PreferenceKey"], fallback: T, valid: (value: unknown) => value is T) {
  const can = useCan();
  const client = useQueryClient();
  const notify = useNotify();
  const queryKey = ["preference", key];
  const stored = usePermittedQuery({ queryKey, queryFn: () => api.preference(key), meta: { needs: "getPreference" }, staleTime: 60_000, refetchInterval: false });
  const raw: unknown = stored.data?.value;
  const value = valid(raw) ? raw : fallback;
  const save = useMutation({
    mutationFn: (next: T) => api.savePreference(key, next),
    onMutate: async (next) => {
      await client.cancelQueries({ queryKey });
      const previous = client.getQueryData<Schemas["Preference"]>(queryKey);
      client.setQueryData<Schemas["Preference"]>(queryKey, { value: next });
      return { previous };
    },
    onError: (error, _next, context) => {
      client.setQueryData(queryKey, context?.previous);
      notify({ tone: "bad", title: "Настройка не сохранена", description: error.message });
    },
  });
  const canSave = can("savePreference") && stored.isSuccess;
  return { value, save: (next: T) => { if (canSave) save.mutate(next); }, canSave };
}

const isRefs = (value: unknown): value is ObjectRef[] => Array.isArray(value) && value.every((item) => typeof item?.id === "string" && typeof item?.kind === "string" && typeof item?.label === "string");
const isRecent = (value: unknown): value is RecentRef[] => isRefs(value) && value.every((item) => typeof (item as RecentRef).at === "string");
const isViews = (value: unknown): value is SavedView[] => Array.isArray(value) && value.every((item) => typeof item?.id === "string" && typeof item?.path === "string" && typeof item?.name === "string");
const isLayout = (value: unknown): value is OverviewLayout => typeof value === "object" && value !== null && Array.isArray((value as OverviewLayout).hidden) && Array.isArray((value as OverviewLayout).order);

// Fallbacks are constants: a new object on every render would change the value
// each time and re-run every effect that depends on it.
const noRefs: ObjectRef[] = [];
const noRecent: RecentRef[] = [];
const noViews: SavedView[] = [];
export const defaultLayout: OverviewLayout = { hidden: [], order: [] };

export const useFavorites = () => usePreference<ObjectRef[]>("favorites", noRefs, isRefs);
export const useRecent = () => usePreference<RecentRef[]>("recent", noRecent, isRecent);
export const useViews = () => usePreference<SavedView[]>("views", noViews, isViews);
export const useOverviewLayout = () => usePreference<OverviewLayout>("overview", defaultLayout, isLayout);

export function FavoriteButton({ item }: { item: ObjectRef }) {
  const favorites = useFavorites();
  if (!favorites.canSave) return null;
  const chosen = favorites.value.some((entry) => entry.kind === item.kind && entry.id === item.id);
  const toggle = () => favorites.save(chosen ? favorites.value.filter((entry) => !(entry.kind === item.kind && entry.id === item.id)) : [item, ...favorites.value].slice(0, 50));
  return (
    <Button onClick={toggle} aria-pressed={chosen} title={chosen ? "Убрать из избранного" : "В избранное"}>
      <Star className={chosen ? "fill-warn text-warn" : undefined} />
      {chosen ? "В избранном" : "В избранное"}
    </Button>
  );
}

// Remembers an opened object for the search box and the overview. Written once
// per object, not on every refresh of the page.
export function useRememberVisit(item: ObjectRef | undefined) {
  const recent = useRecent();
  const remembered = useRef("");
  useEffect(() => {
    if (!item || !recent.canSave) return;
    const key = `${item.kind}:${item.id}:${item.label}`;
    if (remembered.current === key) return;
    remembered.current = key;
    if (recent.value[0]?.kind === item.kind && recent.value[0]?.id === item.id && recent.value[0]?.label === item.label) return;
    const rest = recent.value.filter((entry) => !(entry.kind === item.kind && entry.id === item.id));
    recent.save([{ ...item, at: new Date().toISOString() }, ...rest].slice(0, maxRecent));
  }, [item, recent]);
}

// A saved address as text. A malformed escape stays as typed instead of
// breaking the list.
function readable(query: string): string {
  try {
    return decodeURIComponent(query);
  } catch {
    return query;
  }
}

function ViewsDialog({ open, onOpenChange, mode }: { open: boolean; onOpenChange: (open: boolean) => void; mode: "save" | "manage" }) {
  const views = useViews();
  const notify = useNotify();
  const location = useLocation();
  const [name, setName] = useState("");
  const save = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    const view: SavedView = { id: crypto.randomUUID(), name: name.trim(), path: location.pathname, query: location.search.replace(/^\?/, "") };
    views.save([view, ...views.value].slice(0, 100));
    notify({ tone: "ok", title: "Представление сохранено", description: "Оно в боковой панели и откроется в любом браузере." });
    setName("");
    onOpenChange(false);
  };
  if (mode === "save") {
    return (
      <Dialog open={open} onOpenChange={onOpenChange} title="Сохранить представление" description="Раздел и все фильтры текущей выборки под вашим именем. Видно только вам.">
        <form onSubmit={save} aria-label="Сохранить представление" className="flex flex-col gap-4">
          <Field label="Название">
            <Input required autoFocus maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Паспортные данные за неделю" />
          </Field>
          <div className="flex justify-end gap-2">
            <Button onClick={() => onOpenChange(false)}>Отмена</Button>
            <Button type="submit" variant="primary">Сохранить</Button>
          </div>
        </form>
      </Dialog>
    );
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Мои представления">
      {views.value.length === 0 ? (
        <p className="text-sm text-fg-2">Сохранённых представлений нет.</p>
      ) : (
        <ul className="flex flex-col divide-y divide-border">
          {views.value.map((view) => (
            <li key={view.id} className="flex items-center justify-between gap-3 py-2.5">
              <span className="min-w-0">
                <span className="block truncate text-sm font-medium text-fg">{view.name}</span>
                <span className="block truncate text-xs text-fg-3">{view.path}{view.query ? `?${readable(view.query)}` : ""}</span>
              </span>
              <Button variant="ghost" size="icon-sm" aria-label={`Удалить «${view.name}»`} onClick={() => views.save(views.value.filter((item) => item.id !== view.id))}><Trash2 /></Button>
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
}

// Saved views of the current section: open one, keep the current selection.
export function ViewsMenu() {
  const views = useViews();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [dialog, setDialog] = useState<"save" | "manage" | null>(null);
  if (!views.canSave) return null;
  const here = views.value.filter((view) => view.path === pathname);
  return (
    <>
      <Menu label="Представления" trigger={<Button><Bookmark /> Представления</Button>}>
        {here.map((view) => (
          <MenuItem key={view.id} icon={<Bookmark />} onSelect={() => navigate(`${view.path}${view.query ? `?${view.query}` : ""}`)}>{view.name}</MenuItem>
        ))}
        {here.length > 0 && <MenuSeparator />}
        <MenuItem icon={<BookmarkPlus />} onSelect={() => setDialog("save")}>Сохранить текущую выборку…</MenuItem>
        {views.value.length > 0 && <MenuItem icon={<Settings2 />} onSelect={() => setDialog("manage")}>Управлять…</MenuItem>}
      </Menu>
      <ViewsDialog open={dialog !== null} onOpenChange={(open) => { if (!open) setDialog(null); }} mode={dialog ?? "save"} />
    </>
  );
}
