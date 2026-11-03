import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import { api, type Schemas } from "../api";
import { engine as engineLabel, sourceStatus } from "../labels";
import { fromBase64, sealPassword, toBase64 } from "../sealing";
import { Loadable } from "../ui";

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

function SourceForm({ tenantId, agents, editing, onDone }: {
  tenantId: string;
  agents: Schemas["Agent"][];
  editing?: Schemas["Source"];
  onDone: () => void;
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
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["sources"] });
      onDone();
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    save.mutate();
  };

  if (!editing && usable.length === 0) {
    return <p className="muted">Нет агента, который может принять пароль. Подключите агента ниже.</p>;
  }
  return (
    <form className="form-grid" onSubmit={submit} aria-label={editing ? "Изменить источник" : "Новый источник"}>
      <label className="field">
        Имя
        <input required pattern="[a-z][a-z0-9_\-]{0,63}" value={draft.name} onChange={(event) => set({ name: event.target.value })}
          placeholder="crm-main" title="Строчные латинские буквы, цифры, - и _" />
      </label>
      <label className="field">
        Агент
        <select disabled={Boolean(editing)} value={draft.agentId} onChange={(event) => set({ agentId: event.target.value })}>
          {(editing ? agents : usable).map((agent) => <option key={agent.id} value={agent.id}>{agent.id.slice(0, 8)} · {agent.version}</option>)}
        </select>
      </label>
      <label className="field">
        СУБД
        <select disabled={Boolean(editing)} value={draft.engine} onChange={(event) => {
          const chosen = engines.find((item) => item.name === event.target.value);
          if (chosen) set({ engine: chosen.name, port: String(chosen.port) });
        }}>
          {engines.map((item) => <option key={item.name} value={item.name}>{engineLabel(item.contract)}</option>)}
        </select>
      </label>
      <label className="field">
        Хост
        <input required value={draft.host} onChange={(event) => set({ host: event.target.value.trim() })} placeholder="db.internal" />
      </label>
      <label className="field">
        Порт
        <input required type="number" min={1} max={65535} value={draft.port} onChange={(event) => set({ port: event.target.value })} />
      </label>
      <label className="field">
        База данных
        <input required value={draft.database} onChange={(event) => set({ database: event.target.value })} />
      </label>
      <label className="field">
        Пользователь
        <input required value={draft.username} autoComplete="off" onChange={(event) => set({ username: event.target.value })} />
      </label>
      <label className="field">
        Пароль
        <input type="password" required={passwordRequired} autoComplete="new-password" value={draft.password}
          onChange={(event) => set({ password: event.target.value })}
          placeholder={passwordRequired ? "" : "Не менять"} />
      </label>
      <label className="field">
        TLS
        <select value={draft.tls} onChange={(event) => set({ tls: event.target.value as TlsMode })}>
          {tlsModes.map((item) => <option key={item.mode} value={item.mode}>{item.label}</option>)}
        </select>
      </label>
      <label className="field wide">
        Каталог журналов аудита
        <input value={draft.auditDirectory} onChange={(event) => set({ auditDirectory: event.target.value.trim() })}
          placeholder={draft.engine === "mssql" ? "Путь на сервере SQL Server" : "Пусто — аудит не собирается"} />
      </label>
      <label className="field">
        Соединений
        <input required type="number" min={1} max={8} value={draft.maxConnections} onChange={(event) => set({ maxConnections: event.target.value })} />
      </label>
      <p className="muted wide">
        Пароль шифруется в браузере ключом выбранного агента и привязан к адресу, базе, пользователю и режиму TLS.
        Центр хранит только шифротекст. Агент получит источник в течение 10 секунд и подключится, только если адрес и
        каталог журналов есть в его списке разрешённых.
        {editing && passwordRequired && " Параметры подключения изменились, поэтому пароль нужно ввести заново."}
      </p>
      <div className="actions wide">
        <button type="submit" className="primary" disabled={save.isPending}>Сохранить</button>
        <button type="button" onClick={onDone}>Отмена</button>
      </div>
      {save.isError && <div className="error wide">{save.error.message}</div>}
    </form>
  );
}

export function Sources({ tenantId, admin, canScan }: { tenantId: string; admin: boolean; canScan: boolean }) {
  const client = useQueryClient();
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, refetchInterval: 5000 });
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents });
  const [mode, setMode] = useState<{ kind: "closed" } | { kind: "new" } | { kind: "edit"; source: Schemas["Source"] }>({ kind: "closed" });
  const remove = useMutation({
    mutationFn: api.deleteSource,
    onSuccess: () => client.invalidateQueries({ queryKey: ["sources"] }),
  });
  const scan = useMutation({
    mutationFn: api.requestScan,
    onSuccess: () => client.invalidateQueries({ queryKey: ["scans"] }),
  });

  return (
    <section className="card">
      <div className="card-head">
        <h2>Источники</h2>
        {admin && mode.kind === "closed" && <button onClick={() => setMode({ kind: "new" })}>Добавить источник</button>}
      </div>
      {mode.kind !== "closed" && agents.data && (
        <SourceForm
          key={mode.kind === "edit" ? mode.source.id : "new"}
          tenantId={tenantId}
          agents={agents.data}
          editing={mode.kind === "edit" ? mode.source : undefined}
          onDone={() => setMode({ kind: "closed" })}
        />
      )}
      <Loadable query={sources} empty="Источников пока нет." isEmpty={(rows) => rows.length === 0}>
        {(rows) => (
          <div className="scroll">
            <table>
              <thead>
                <tr><th>Имя</th><th>Подключение</th><th>Адрес</th><th>Агент</th><th>Аудит</th><th /></tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const status = sourceStatus(row.statusCode, row.probedAt);
                  return (
                    <tr key={row.id}>
                      <td>
                        {row.key}
                        <div className="muted">{engineLabel(row.engine)} {row.engineVersion}</div>
                      </td>
                      <td><span className={`badge ${status.tone}`}>{status.label}</span></td>
                      <td className="mono">
                        {row.host}:{row.port}/{row.database}
                        <div className="muted">{row.username}</div>
                      </td>
                      <td className="mono muted">{row.agentId.slice(0, 8)}</td>
                      <td className="mono muted">{row.auditDirectory || "—"}</td>
                      <td className="actions">
                        {canScan && !row.statusCode && row.probedAt && (
                          <button disabled={scan.isPending} onClick={() => scan.mutate(row.id)}>Сканировать</button>
                        )}
                        {admin && (
                          <>
                            <button onClick={() => setMode({ kind: "edit", source: row })}>Изменить</button>
                            <button
                              className="danger"
                              disabled={remove.isPending}
                              onClick={() => {
                                if (window.confirm(`Удалить источник ${row.key}? Агент перестанет с ним работать, история останется.`)) remove.mutate(row.id);
                              }}
                            >
                              Удалить
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Loadable>
      {remove.isError && <div className="error">{remove.error.message}</div>}
      {scan.isError && <div className="error">{scan.error.message}</div>}
      {scan.isSuccess && <p className="muted">Скан поставлен в очередь, ход виден в разделе «Сканирования».</p>}
    </section>
  );
}
