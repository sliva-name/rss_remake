import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { api, type Schemas } from "../api";
import { engine as engineLabel, failure, shortId } from "../labels";
import { paths } from "../links";
import { fromBase64, sealPassword, toBase64 } from "../sealing";
import { Button } from "./ui/button";
import { Drawer } from "./ui/dialog";
import { Field, Input, Select } from "./ui/form";

type EngineName = Schemas["SourceEngine"];
type TlsMode = Schemas["TlsMode"];

const engines: { name: EngineName; contract: string; port: number }[] = [
  { name: "postgresql", contract: "ENGINE_POSTGRESQL", port: 5432 },
  { name: "mysql", contract: "ENGINE_MYSQL", port: 3306 },
  { name: "mariadb", contract: "ENGINE_MARIADB", port: 3306 },
  { name: "mssql", contract: "ENGINE_MSSQL", port: 1433 },
];

const tlsModes: { mode: TlsMode; label: string }[] = [
  { mode: "verify-full", label: "Проверять сертификат и имя" },
  { mode: "require", label: "Шифровать без проверки" },
  { mode: "disable", label: "Без шифрования" },
];

type Draft = {
  name: string;
  agentId: string;
  engine: EngineName;
  host: string;
  port: string;
  database: string;
  username: string;
  password: string;
  tls: TlsMode;
  auditDirectory: string;
  maxConnections: string;
};

const blank = (agentId: string): Draft => ({
  name: "", agentId, engine: "postgresql", host: "", port: "5432", database: "", username: "", password: "",
  tls: "verify-full", auditDirectory: "", maxConnections: "2",
});

function draftOf(source: Schemas["Source"]): Draft {
  return {
    name: source.key, agentId: source.agentId,
    engine: engines.find((item) => item.contract === source.engine)?.name ?? "postgresql",
    host: source.host, port: String(source.port), database: source.database, username: source.username, password: "",
    tls: source.tls, auditDirectory: source.auditDirectory, maxConnections: String(source.maxConnections),
  };
}

// The password is sealed to these fields: changing one means entering it again.
const bindingChanged = (draft: Draft, source: Schemas["Source"]) =>
  draft.host !== source.host || Number(draft.port) !== source.port || draft.database !== source.database ||
  draft.username !== source.username || draft.tls !== source.tls;

// The agent picks a source up with its next heartbeat and tries to open it.
// ProbeStatus follows that attempt, so a wrong address or a missing permission
// is seen at once, with what to do about it.
function ProbeStatus({ sourceId, connected }: { sourceId: string; connected: string }) {
  const source = useQuery({ queryKey: ["source", sourceId], queryFn: () => api.source(sourceId), refetchInterval: (query) => (query.state.data?.probedAt ? false : 2000) });
  const data = source.data;
  if (!data?.probedAt) {
    return (
      <div role="status" className="flex items-start gap-3 rounded-md border border-border p-4">
        <Loader2 aria-hidden className="mt-0.5 size-5 shrink-0 animate-spin text-accent" />
        <div>
          <p className="text-sm font-medium text-fg">Ожидает агента</p>
          <p className="mt-0.5 text-sm text-fg-2">Агент заберёт источник со следующим сигналом, обычно в течение 10 секунд, и попробует подключиться.</p>
        </div>
      </div>
    );
  }
  if (!data.statusCode) {
    return (
      <div role="status" className="flex items-start gap-3 rounded-md border border-ok/30 bg-ok-bg p-4">
        <CheckCircle2 aria-hidden className="mt-0.5 size-5 shrink-0 text-ok" />
        <div>
          <p className="text-sm font-medium text-ok">Подключено</p>
          <p className="mt-0.5 text-sm text-fg-2">{engineLabel(data.engine)} {data.engineVersion}. {connected}</p>
        </div>
      </div>
    );
  }
  return (
    <div role="status" className="flex items-start gap-3 rounded-md border border-bad/30 bg-bad-bg p-4">
      <XCircle aria-hidden className="mt-0.5 size-5 shrink-0 text-bad" />
      <div>
        <p className="text-sm font-medium text-bad">{failure(data.statusCode).problem}</p>
        <p className="mt-0.5 text-sm text-fg-2">{failure(data.statusCode).action}</p>
      </div>
    </div>
  );
}

function Outcome({ sourceId, onClose }: { sourceId: string; onClose: () => void }) {
  return (
    <div className="flex flex-col gap-4">
      <ProbeStatus sourceId={sourceId} connected="Можно запускать сканирование." />
      <div className="flex gap-2">
        <Button variant="primary" asChild><Link to={paths.source(sourceId)} onClick={onClose}>Открыть источник</Link></Button>
        <Button onClick={onClose}>Закрыть</Button>
      </div>
    </div>
  );
}

export function SourceDrawer({ open, onOpenChange, tenantId, editing }: { open: boolean; onOpenChange: (open: boolean) => void; tenantId: string; editing?: Schemas["Source"] }) {
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents, enabled: open });
  const [saved, setSaved] = useState<string | null>(null);
  const close = (next: boolean) => {
    onOpenChange(next);
    if (!next) setSaved(null);
  };
  return (
    <Drawer
      open={open}
      onOpenChange={close}
      title={editing ? `Источник ${editing.key}` : "Новый источник"}
      description={saved ? "Источник сохранён" : "Пароль шифруется в браузере ключом агента. Центр его не видит."}
    >
      {saved ? (
        <Outcome sourceId={saved} onClose={() => close(false)} />
      ) : agents.data ? (
        <SourceForm key={editing?.id ?? "new"} tenantId={tenantId} agents={agents.data} editing={editing} onSaved={setSaved} onCancel={() => close(false)} />
      ) : agents.isError ? (
        <p className="text-sm text-bad">Не удалось загрузить агентов: {agents.error.message}</p>
      ) : (
        <p className="text-sm text-fg-2">Загрузка…</p>
      )}
    </Drawer>
  );
}

function SourceForm({ tenantId, agents, editing, onSaved, onCancel }: {
  tenantId: string;
  agents: Schemas["Agent"][];
  editing?: Schemas["Source"];
  onSaved: (id: string) => void;
  onCancel: () => void;
}) {
  const client = useQueryClient();
  const usable = agents.filter((agent) => agent.status === "active" && agent.sealingPublicKey);
  const [draft, setDraft] = useState<Draft>(editing ? draftOf(editing) : blank(usable[0]?.id ?? ""));
  const set = (patch: Partial<Draft>) => setDraft((current) => ({ ...current, ...patch }));
  const passwordRequired = !editing || bindingChanged(draft, editing);
  const form = useRef<HTMLFormElement>(null);

  // A connection check saves the new source as a draft: the agent opens it as
  // it would a real one, but neither scans it nor reads its audit, and nobody
  // else sees it. Saving activates the draft; leaving the form deletes it.
  const [trial, setTrial] = useState<{ id: string; of: string } | null>(null);
  const pending = useRef<string | null>(null);
  useEffect(() => () => {
    if (pending.current) void api.deleteSource(pending.current).catch(() => undefined);
  }, []);

  const bodyOf = async (): Promise<Schemas["SourceUpdate"]> => {
    const agent = agents.find((item) => item.id === draft.agentId);
    let sealedPassword: string | undefined;
    if (draft.password) {
      if (!agent?.sealingPublicKey) throw new Error("агент не может принять пароль: зарегистрируйте его заново");
      const sealed = await sealPassword(fromBase64(agent.sealingPublicKey), {
        tenantId, agentId: agent.id, engine: draft.engine, host: draft.host, port: Number(draft.port),
        database: draft.database, username: draft.username, tls: draft.tls,
      }, draft.password);
      sealedPassword = toBase64(sealed);
    }
    return {
      name: draft.name, engine: draft.engine, host: draft.host, port: Number(draft.port), database: draft.database,
      username: draft.username, tls: draft.tls, auditDirectory: draft.auditDirectory,
      maxConnections: Number(draft.maxConnections), sealedPassword,
    };
  };
  const snapshot = JSON.stringify(draft);

  const check = useMutation({
    mutationFn: async () => {
      const body = await bodyOf();
      if (trial) return api.updateSource(trial.id, body);
      return api.createSource({ ...body, agentId: draft.agentId, sealedPassword: body.sealedPassword ?? "", draft: true });
    },
    onSuccess: async (source) => {
      pending.current = source.id;
      setTrial({ id: source.id, of: snapshot });
      await client.invalidateQueries({ queryKey: ["source", source.id] });
    },
  });

  const save = useMutation({
    mutationFn: async () => {
      if (editing) return api.updateSource(editing.id, await bodyOf());
      if (!trial) {
        const body = await bodyOf();
        return api.createSource({ ...body, agentId: draft.agentId, sealedPassword: body.sealedPassword ?? "", draft: false });
      }
      if (trial.of !== snapshot) await api.updateSource(trial.id, await bodyOf());
      const source = await api.activateSource(trial.id);
      pending.current = null;
      return source;
    },
    onSuccess: async (source) => {
      await Promise.all([client.invalidateQueries({ queryKey: ["sources"] }), client.invalidateQueries({ queryKey: ["source", source.id] })]);
      onSaved(source.id);
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    save.mutate();
  };
  const runCheck = () => {
    if (form.current?.reportValidity()) check.mutate();
  };

  if (!editing && usable.length === 0) {
    return (
      <div className="flex flex-col gap-3 text-sm text-fg-2">
        <p>Нет агента, который может принять пароль. Сначала подключите агента в разделе «Агенты».</p>
        <Button asChild className="self-start"><Link to="/agents" onClick={onCancel}>К агентам</Link></Button>
      </div>
    );
  }
  return (
    <form ref={form} onSubmit={submit} aria-label={editing ? "Изменить источник" : "Новый источник"} className="flex flex-col gap-5">
      <fieldset className="grid gap-3 sm:grid-cols-2">
        <legend className="mb-2 text-xs font-semibold tracking-wide text-fg-3 uppercase">Где источник</legend>
        <Field label="Имя" hint="Строчные латинские буквы, цифры, - и _">
          <Input required pattern="[a-z][a-z0-9_\-]{0,63}" value={draft.name} onChange={(event) => set({ name: event.target.value })} placeholder="crm-main" />
        </Field>
        <Field label="Агент" hint={editing || trial ? "Источник привязан к агенту навсегда" : "Агент, который будет подключаться"}>
          <Select
            disabled={Boolean(editing || trial)}
            value={draft.agentId}
            onValueChange={(agentId) => set({ agentId })}
            options={(editing ? agents : usable).map((agent) => ({ value: agent.id, label: shortId(agent.id), hint: `версия ${agent.version}` }))}
          />
        </Field>
        <Field label="СУБД">
          <Select
            disabled={Boolean(editing || trial)}
            value={draft.engine}
            onValueChange={(value) => {
              const chosen = engines.find((item) => item.name === value);
              if (chosen) set({ engine: chosen.name, port: String(chosen.port) });
            }}
            options={engines.map((item) => ({ value: item.name, label: engineLabel(item.contract), hint: `порт ${item.port}` }))}
          />
        </Field>
        <Field label="TLS">
          <Select value={draft.tls} onValueChange={(value) => set({ tls: value as TlsMode })} options={tlsModes.map((item) => ({ value: item.mode, label: item.label }))} />
        </Field>
        <Field label="Хост">
          <Input required value={draft.host} onChange={(event) => set({ host: event.target.value.trim() })} placeholder="db.internal" />
        </Field>
        <Field label="Порт">
          <Input required type="number" min={1} max={65535} value={draft.port} onChange={(event) => set({ port: event.target.value })} />
        </Field>
      </fieldset>

      <fieldset className="grid gap-3 sm:grid-cols-2">
        <legend className="mb-2 text-xs font-semibold tracking-wide text-fg-3 uppercase">Доступ</legend>
        <Field label="База данных">
          <Input required value={draft.database} onChange={(event) => set({ database: event.target.value })} />
        </Field>
        <Field label="Пользователь" hint="Только чтение каталога и выборок">
          <Input required value={draft.username} autoComplete="off" onChange={(event) => set({ username: event.target.value })} />
        </Field>
        <Field
          label="Пароль"
          className="sm:col-span-2"
          hint={editing ? (passwordRequired ? "Параметры подключения изменились, поэтому пароль нужно ввести заново." : "Оставьте пустым, чтобы не менять") : "Шифруется ключом агента и привязан к адресу, базе, пользователю и TLS"}
        >
          <Input type="password" required={passwordRequired} autoComplete="new-password" value={draft.password} onChange={(event) => set({ password: event.target.value })} placeholder={passwordRequired ? "" : "Не менять"} />
        </Field>
      </fieldset>

      <fieldset className="grid gap-3 sm:grid-cols-2">
        <legend className="mb-2 text-xs font-semibold tracking-wide text-fg-3 uppercase">Аудит и нагрузка</legend>
        <Field label="Каталог журналов аудита" className="sm:col-span-2" hint="Должен быть в списке разрешённых каталогов агента">
          <Input value={draft.auditDirectory} onChange={(event) => set({ auditDirectory: event.target.value.trim() })} placeholder={draft.engine === "mssql" ? "Путь на сервере SQL Server" : "Пусто — аудит не собирается"} />
        </Field>
        <Field label="Соединений" hint="Не больше 8">
          <Input required type="number" min={1} max={8} value={draft.maxConnections} onChange={(event) => set({ maxConnections: event.target.value })} />
        </Field>
      </fieldset>

      {!editing && (
        <section aria-label="Проверка подключения" className="flex flex-col gap-3 rounded-lg border border-border bg-surface-2 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="max-w-md text-sm text-fg-2">
              Агент подключится с этими параметрами, но не будет сканировать источник и читать журналы, пока вы его не сохраните.
            </p>
            <Button onClick={runCheck} disabled={check.isPending || save.isPending}>
              {check.isPending ? "Отправка…" : trial ? "Проверить ещё раз" : "Проверить подключение"}
            </Button>
          </div>
          {check.isError && <p role="alert" className="text-sm text-bad">{check.error.message}</p>}
          {trial && !check.isPending && (
            <>
              <ProbeStatus sourceId={trial.id} connected="Можно сохранять." />
              {trial.of !== snapshot && <p className="text-sm text-warn">Параметры изменились после проверки. Проверьте ещё раз или сохраните как есть.</p>}
            </>
          )}
        </section>
      )}

      {save.isError && <p role="alert" className="text-sm text-bad">{save.error.message}</p>}
      <div className="flex gap-2 border-t border-border pt-4">
        <Button type="submit" variant="primary" disabled={save.isPending || check.isPending}>{save.isPending ? "Сохранение…" : "Сохранить"}</Button>
        <Button onClick={onCancel}>Отмена</Button>
      </div>
    </form>
  );
}
