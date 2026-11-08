import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { api, ApiError, type Schemas } from "../api";
import { Mono } from "../components/domain";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Drawer, useConfirm } from "../components/ui/dialog";
import { Field, Input } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Facts, Panel } from "../components/ui/panel";
import { EmptyState, ErrorState, Loadable, Loading } from "../components/ui/state";
import { useNotify } from "../components/ui/toast";
import { count, dateTime } from "../labels";
import { useCan } from "../permissions";
import { queries, usePermittedQuery } from "../queries";

type Detector = Schemas["CustomDetector"];
type Budget = NonNullable<Schemas["PolicyDraft"]["scanBudget"]>;

const categoryPattern = /^CUSTOM(\.[A-Z][A-Z0-9_]*)+$/;

const budgetFields: { key: keyof Budget; label: string; hint: string }[] = [
  { key: "maxDurationSeconds", label: "Длительность скана, с", hint: "Скан останавливается по истечении" },
  { key: "maxRowsPerTable", label: "Строк на таблицу", hint: "Сколько строк читать из одной таблицы" },
  { key: "maxBytesPerTable", label: "Байт на таблицу", hint: "Предел объёма выборки из таблицы" },
  { key: "maxConnections", label: "Соединений", hint: "Одновременно к одному источнику" },
  { key: "maxRowsPerSecond", label: "Строк в секунду", hint: "Ограничение скорости чтения" },
];

function problemOf(detector: Detector): string | undefined {
  if (!categoryPattern.test(detector.categoryId)) return "Имя категории: CUSTOM и части через точку, заглавными латинскими буквами, например CUSTOM.CONTRACT_NUMBER";
  if (!detector.namePattern && !detector.valuePattern) return "Укажите шаблон имени колонки, значения или оба";
  return undefined;
}

function View({ policy, onEdit }: { policy: Schemas["Policy"] | null; onEdit?: () => void }) {
  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
      <Panel title="Собственные детекторы" description="Дополняют встроенные категории. Совпадение ищется агентом, значения не покидают контур." actions={onEdit && <Button size="sm" onClick={onEdit}><Pencil /> Изменить</Button>} flush>
        {!policy || policy.customDetectors.length === 0 ? (
          <EmptyState title="Собственных детекторов нет">Работают только встроенные категории классификатора.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border bg-surface-2/60 text-xs text-fg-2"><th className="px-3 py-2 text-left font-medium">Категория</th><th className="px-3 py-2 text-left font-medium">Шаблон имени колонки</th><th className="px-3 py-2 text-left font-medium">Шаблон значения</th></tr></thead>
              <tbody>
                {policy.customDetectors.map((detector) => (
                  <tr key={detector.categoryId} className="border-b border-border last:border-0">
                    <td className="px-3 py-2"><Mono>{detector.categoryId}</Mono></td>
                    <td className="px-3 py-2">{detector.namePattern ? <Mono className="break-all">{detector.namePattern}</Mono> : <span className="text-fg-3">—</span>}</td>
                    <td className="px-3 py-2">{detector.valuePattern ? <Mono className="break-all">{detector.valuePattern}</Mono> : <span className="text-fg-3">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <Panel title="Бюджет сканирования" description="Ограничивает нагрузку скана на базу">
        <Facts items={budgetFields.map((field) => [field.label, policy?.scanBudget?.[field.key] !== undefined ? count(policy.scanBudget[field.key] as number) : <span key={field.key} className="text-fg-3">по умолчанию агента</span>])} />
      </Panel>
    </div>
  );
}

function Editor({ policy, onDone }: { policy: Schemas["Policy"] | null; onDone: () => void }) {
  const client = useQueryClient();
  const confirm = useConfirm();
  const notify = useNotify();
  const [detectors, setDetectors] = useState<Detector[]>(policy?.customDetectors ?? []);
  const [budget, setBudget] = useState<Record<string, string>>(() => Object.fromEntries(budgetFields.map((field) => [field.key, policy?.scanBudget?.[field.key]?.toString() ?? ""])));
  const problems = detectors.map(problemOf);
  const duplicate = new Set(detectors.map((item) => item.categoryId)).size !== detectors.length;
  const invalid = problems.some(Boolean) || duplicate;

  const publish = useMutation({
    mutationFn: () => {
      const scanBudget = Object.fromEntries(Object.entries(budget).filter(([, value]) => value.trim() !== "").map(([key, value]) => [key, Number(value)])) as Budget;
      return api.publishPolicy({
        customDetectors: detectors.map((item) => ({ categoryId: item.categoryId, namePattern: item.namePattern || undefined, valuePattern: item.valuePattern || undefined })),
        scanBudget: Object.keys(scanBudget).length > 0 ? scanBudget : undefined,
      });
    },
    onSuccess: async (published) => {
      notify({ tone: "ok", title: `Опубликована версия ${published.version}`, description: "Агенты получат подписанную политику со следующим сигналом." });
      await client.invalidateQueries({ queryKey: queries.policy().queryKey });
      onDone();
    },
  });
  const set = (index: number, patch: Partial<Detector>) => setDetectors((current) => current.map((item, at) => (at === index ? { ...item, ...patch } : item)));
  const submit = async () => {
    const yes = await confirm({
      title: "Опубликовать политику?",
      description: `Будет создана версия ${(policy?.version ?? 0) + 1}. Центр подпишет её, агенты применят при следующем скане. Прежняя версия останется в истории.`,
      confirm: "Опубликовать",
    });
    if (yes) publish.mutate();
  };

  return (
    <div className="flex flex-col gap-6">
      <Panel title="Собственные детекторы" description="Шаблоны — регулярные выражения RE2. Пустой шаблон не проверяется." actions={<Button size="sm" onClick={() => setDetectors([...detectors, { categoryId: "CUSTOM.", namePattern: "", valuePattern: "" }])}><Plus /> Детектор</Button>}>
        {detectors.length === 0 ? (
          <p className="text-sm text-fg-2">Детекторов нет. Добавьте, если у организации есть данные, которых нет среди встроенных категорий.</p>
        ) : (
          <ul className="flex flex-col gap-4">
            {detectors.map((detector, index) => (
              <li key={index} className="grid gap-3 rounded-md border border-border p-3 md:grid-cols-[minmax(0,14rem)_minmax(0,1fr)_minmax(0,1fr)_auto] md:items-start">
                <Field label="Категория" error={problems[index]?.startsWith("Имя") ? problems[index] : undefined}>
                  <Input value={detector.categoryId} aria-invalid={Boolean(problems[index]?.startsWith("Имя"))} onChange={(event) => set(index, { categoryId: event.target.value.toUpperCase() })} className="font-mono" />
                </Field>
                <Field label="Шаблон имени колонки" error={problems[index] && !problems[index]?.startsWith("Имя") ? problems[index] : undefined}>
                  <Input value={detector.namePattern ?? ""} maxLength={512} onChange={(event) => set(index, { namePattern: event.target.value })} placeholder="(?i)contract_?no" className="font-mono" />
                </Field>
                <Field label="Шаблон значения">
                  <Input value={detector.valuePattern ?? ""} maxLength={512} onChange={(event) => set(index, { valuePattern: event.target.value })} placeholder="^Д-\d{6}$" className="font-mono" />
                </Field>
                <Button variant="ghost" size="icon" className="md:mt-5" aria-label={`Удалить детектор ${detector.categoryId}`} onClick={() => setDetectors(detectors.filter((_, at) => at !== index))}><Trash2 /></Button>
              </li>
            ))}
          </ul>
        )}
        {duplicate && <p role="alert" className="mt-3 text-sm text-bad">Две категории с одним именем: оставьте одну.</p>}
      </Panel>
      <Panel title="Бюджет сканирования" description="Пустое поле — значение по умолчанию агента">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {budgetFields.map((field) => (
            <Field key={field.key} label={field.label} hint={field.hint}>
              <Input type="number" min={1} value={budget[field.key]} onChange={(event) => setBudget({ ...budget, [field.key]: event.target.value })} />
            </Field>
          ))}
        </div>
      </Panel>
      {publish.isError && <p role="alert" className="text-sm text-bad">Политика не опубликована: {publish.error.message}</p>}
      <div className="flex gap-2">
        <Button variant="primary" disabled={invalid || publish.isPending} onClick={() => void submit()}>{publish.isPending ? "Публикация…" : "Опубликовать"}</Button>
        <Button onClick={onDone}>Отмена</Button>
      </div>
    </div>
  );
}

export function Policy() {
  const can = useCan();
  const [editing, setEditing] = useState(false);
  const policy = useQuery(queries.policy());
  const missing = policy.error instanceof ApiError && policy.error.status === 404;
  const current = policy.data ?? null;

  return (
    <>
      <PageHeader
        title="Политика"
        description="Правила классификации и нагрузки скана для всех агентов организации. Каждая публикация — новая подписанная версия."
        meta={current ? <Badge tone="accent">Версия {current.version}</Badge> : missing ? <Badge>Не опубликована</Badge> : undefined}
      />
      {policy.isPending ? (
        <Loading rows={6} />
      ) : policy.isError && !missing ? (
        <ErrorState error={policy.error} />
      ) : editing ? (
        <Editor policy={current} onDone={() => setEditing(false)} />
      ) : (
        <div className="flex flex-col gap-6">
          <View policy={current} onEdit={can("publishPolicy") ? () => setEditing(true) : undefined} />
          {can("listPolicyVersions") && current && <History current={current.version} />}
        </div>
      )}
    </>
  );
}

// Every published version stays: agents may still run an older one, and an
// auditor asks what the rules were on a given day.
function History({ current }: { current: number }) {
  const can = useCan();
  const versions = useQuery(queries.policyVersions(current));
  const [opened, setOpened] = useState<number | null>(null);
  const version = usePermittedQuery(queries.policyVersion(opened));
  return (
    <Panel title="История версий" description="Каждая публикация подписана и хранится; агенты принимают только версию новее своей" flush>
      <Loadable query={versions} isEmpty={(rows) => rows.length === 0} empty={<EmptyState title="Версий нет" />}>
        {(rows) => (
          <ul className="divide-y divide-border">
            {rows.map((row) => (
              <li key={row.version} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
                <div className="flex min-w-0 items-center gap-3">
                  <Badge tone={row.version === current ? "accent" : "neutral"}>Версия {row.version}</Badge>
                  <span className="text-sm text-fg-2">
                    {dateTime(row.createdAt)} · детекторов: {row.customDetectors}{row.hasScanBudget ? " · свой бюджет скана" : ""}
                  </span>
                  <span className="truncate text-xs text-fg-3" title={row.createdBy}>опубликовал {row.createdBy}</span>
                </div>
                {can("getPolicyVersion") && <Button size="sm" variant="ghost" onClick={() => setOpened(row.version)}>Открыть</Button>}
              </li>
            ))}
          </ul>
        )}
      </Loadable>
      <Drawer open={opened !== null} onOpenChange={(open) => { if (!open) setOpened(null); }} title={`Политика, версия ${opened ?? ""}`} description={opened === current ? "Действующая версия" : "Прежняя версия"}>
        <Loadable query={version}>{(data) => <View policy={data} />}</Loadable>
      </Drawer>
    </Panel>
  );
}
