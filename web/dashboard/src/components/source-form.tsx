import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { type FormEvent, useState } from "react";
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

// After saving, the agent picks the source up with its next heartbeat and tries
// to open it. The panel stays to show that outcome, so a wrong address or a
// missing permission is seen at once, with what to do about it.
function Outcome({ sourceId, onClose }: { sourceId: string; onClose: () => void }) {
  const source = useQuery({ queryKey: ["source", sourceId], queryFn: () => api.source(sourceId), refetchInterval: (query) => (query.state.data?.probedAt ? false : 2000) });
  const data = source.data;
  return (
    <div className="flex flex-col gap-4">
      {!data?.probedAt ? (
        <div className="flex items-start gap-3 rounded-md border border-border p-4">
          <Loader2 aria-hidden className="mt-0.5 size-5 shrink-0 animate-spin text-accent" />
          <div>
            <p className="text-sm font-medium text-fg">Ожидает агента</p>
            <p className="mt-0.5 text-sm text-fg-2">Агент заберёт источник со следующим сигналом, обычно в течение 10 секунд, и попробует подключиться.</p>
          </div>
        </div>
      ) : !data.statusCode ? (
        <div className="flex items-start gap-3 rounded-md border border-ok/30 bg-ok-bg p-4">
          <CheckCircle2 aria-hidden className="mt-0.5 size-5 shrink-0 text-ok" />
          <div>
            <p className="text-sm font-medium text-ok">Подключено</p>
            <p className="mt-0.5 text-sm text-fg-2">{engineLabel(data.engine)} {data.engineVersion}. Можно запускать сканирование.</p>
          </div>
        </div>
      ) : (
        <div className="flex items-start gap-3 rounded-md border border-bad/30 bg-bad-bg p-4">
          <XCircle aria-hidden className="mt-0.5 size-5 shrink-0 text-bad" />
          <div>
            <p className="text-sm font-medium text-bad">{failure(data.statusCode).problem}</p>
            <p className="mt-0.5 text-sm text-fg-2">{failure(data.statusCode).action}</p>
          </div>
        </div>
      )}
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

  const save = useMutation({
    mutationFn: async () => {
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
      const body: Schemas["SourceUpdate"] = {
        name: draft.name, engine: draft.engine, host: draft.host, port: Number(draft.port), database: draft.database,
        username: draft.username, tls: draft.tls, auditDirectory: draft.auditDirectory,
        maxConnections: Number(draft.maxConnections), sealedPassword,
      };
      if (editing) return api.updateSource(editing.id, body);
      return api.createSource({ ...body, agentId: draft.agentId, sealedPassword: sealedPassword ?? "" });
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

  if (!editing && usable.length === 0) {
    return (
      <div className="flex flex-col gap-3 text-sm text-fg-2">
        <p>Нет агента, который может принять пароль. Сначала подключите агента в разделе «Агенты».</p>
        <Button asChild className="self-start"><Link to="/agents" onClick={onCancel}>К агентам</Link></Button>
      </div>
    );
  }
  return (
    <form onSubmit={submit} aria-label={editing ? "Изменить источник" : "Новый источник"} className="flex flex-col gap-5">
      <fieldset className="grid gap-3 sm:grid-cols-2">
        <legend className="mb-2 text-xs font-semibold tracking-wide text-fg-3 uppercase">Где источник</legend>
        <Field label="Имя" hint="Строчные латинские буквы, цифры, - и _">
          <Input required pattern="[a-z][a-z0-9_\-]{0,63}" value={draft.name} onChange={(event) => set({ name: event.target.value })} placeholder="crm-main" />
        </Field>
        <Field label="Агент" hint={editing ? "Источник привязан к агенту навсегда" : "Агент, который будет подключаться"}>
          <Select disabled={Boolean(editing)} value={draft.agentId} onChange={(event) => set({ agentId: event.target.value })}>
            {(editing ? agents : usable).map((agent) => <option key={agent.id} value={agent.id}>{shortId(agent.id)} · {agent.version}</option>)}
          </Select>
        </Field>
        <Field label="СУБД">
          <Select disabled={Boolean(editing)} value={draft.engine} onChange={(event) => {
            const chosen = engines.find((item) => item.name === event.target.value);
            if (chosen) set({ engine: chosen.name, port: String(chosen.port) });
          }}>
            {engines.map((item) => <option key={item.name} value={item.name}>{engineLabel(item.contract)}</option>)}
          </Select>
        </Field>
        <Field label="TLS">
          <Select value={draft.tls} onChange={(event) => set({ tls: event.target.value as TlsMode })}>
            {tlsModes.map((item) => <option key={item.mode} value={item.mode}>{item.label}</option>)}
          </Select>
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

      {save.isError && <p role="alert" className="text-sm text-bad">{save.error.message}</p>}
      <div className="flex gap-2 border-t border-border pt-4">
        <Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? "Сохранение…" : "Сохранить"}</Button>
        <Button onClick={onCancel}>Отмена</Button>
      </div>
    </form>
  );
}
