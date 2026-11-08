import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { capability, count, dateTime, engine, explain, percent, scanStatus, support } from "../labels";
import { Allowed, useCan } from "../permissions";
import { CoverageBadge, FailureNote, Loadable, Page } from "../ui";
import { Sources } from "./Sources";

const supportTone: Record<string, string> = { SUPPORT_AVAILABLE: "ok", SUPPORT_NOT_CONFIGURED: "warn", SUPPORT_UNKNOWN: "warn" };

function IssuedToken({ token, expiresAt }: { token: string; expiresAt: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard.writeText(token).then(() => setCopied(true), () => setCopied(false));
  return (
    <>
      <p className="muted">Токен показывается один раз, действует до {dateTime(expiresAt)} и годится для одной регистрации.</p>
      <div className="token-row">
        <div className="token">{token}</div>
        <button onClick={copy}>{copied ? "Скопировано" : "Скопировать"}</button>
      </div>
      <p className="muted">
        Агент читает токен со стандартного ввода, чтобы он не попал в историю команд. На стенде выполните
        <code> make agent-enroll</code>, вставьте токен, затем <code>make agent-up</code>. Источники для агента
        добавляются выше, в разделе «Источники».
      </p>
    </>
  );
}

function Enrollment() {
  const can = useCan();
  const environments = useQuery({ queryKey: ["environments"], queryFn: api.environments, enabled: can("listEnvironments") });
  const client = useQueryClient();
  const [environmentId, setEnvironmentId] = useState("");
  const [name, setName] = useState("");
  const token = useMutation({ mutationFn: api.createToken });
  const create = useMutation({
    mutationFn: () => api.createEnvironment({ name, kind: "production" }),
    onSuccess: () => {
      setName("");
      return client.invalidateQueries({ queryKey: ["environments"] });
    },
  });
  const selected = environmentId || environments.data?.[0]?.id || "";
  return (
    <section className="card">
      <h2>Подключить агента</h2>
      <div className="filters">
        {can("createEnvironment") && (
          <>
            <label className="field">
              Новая среда
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Название" />
            </label>
            <button disabled={!name || create.isPending} onClick={() => create.mutate()}>Создать</button>
          </>
        )}
        <label className="field">
          Среда
          <select value={selected} onChange={(event) => setEnvironmentId(event.target.value)}>
            {environments.data?.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </label>
        <button className="primary" disabled={!selected || token.isPending} onClick={() => token.mutate(selected)}>
          Выпустить токен
        </button>
      </div>
      {create.isError && <div className="error">{create.error.message}</div>}
      {token.isError && <div className="error">{token.error.message}</div>}
      {token.data && <IssuedToken token={token.data.token} expiresAt={token.data.expiresAt} />}
    </section>
  );
}

export function Infrastructure({ tenantId }: { tenantId: string }) {
  const client = useQueryClient();
  const can = useCan();
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24), enabled: can("getAuditCoverage") });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents, enabled: can("listAgents") });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans, enabled: can("listScans") });
  const scan = useMutation({
    mutationFn: api.requestScan,
    onSuccess: () => client.invalidateQueries({ queryKey: ["scans"] }),
  });
  const revoke = useMutation({
    mutationFn: api.revokeAgent,
    onSuccess: () => client.invalidateQueries({ queryKey: ["agents"] }),
  });
  const keyOf = (id: string) => sources.data?.find((source) => source.id === id)?.key ?? id;

  return (
    <Page title="Инфраструктура" lead="Что платформа видит и чего не видит. «Нет данных» значит, что измерять было нечего: это не ноль.">
      <Allowed to="listSources">
        <Sources tenantId={tenantId} />
      </Allowed>

      <Allowed to="getAuditCoverage">
        <section className="card">
          <h2>Покрытие аудита за сутки</h2>
          <Loadable query={coverage} empty="Источники ещё не подключены." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Источник</th>
                      <th>Состояние</th>
                      <th>Аудит чтения</th>
                      <th>Последний скан</th>
                      <th className="num">Запросов</th>
                      <th className="num">До колонок</th>
                      <th className="num">Учётная запись</th>
                      <th className="num">Подтверждён</th>
                      <th className="num">Потерь</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.sourceId}>
                        <td>
                          {row.sourceKey}
                          <div className="muted">{engine(row.engine)}</div>
                        </td>
                        <td>
                          <CoverageBadge status={row.status} reason={row.reason} />
                          <FailureNote code={row.reason} />
                        </td>
                        <td>{row.readsAudited ? "Да" : <span className="badge bad">Нет</span>}</td>
                        <td>
                          {row.lastScanStatus ? scanStatus(row.lastScanStatus) : "Не было"}
                          <div className="muted">{dateTime(row.lastScanAt)}</div>
                        </td>
                        <td className="num">{count(row.statements)}</td>
                        <td className="num">{percent(row.columnsShare)}</td>
                        <td className="num">{percent(row.principalShare)}</td>
                        <td className="num">{percent(row.verifiedShare)}</td>
                        <td className="num">{count(row.gaps)}</td>
                        <td>
                          {can("requestScan") && (
                            <button disabled={scan.isPending} onClick={() => scan.mutate(row.sourceId)}>Сканировать</button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Loadable>
          {scan.isError && <div className="error">{scan.error.message}</div>}
        </section>

        <Allowed to="listSources">
          <section className="card">
            <h2>Возможности источников</h2>
            <Loadable query={sources} empty="Источники ещё не подключены." isEmpty={(rows) => rows.length === 0}>
              {(rows) => (
                <div className="scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Возможность</th>
                        {rows.map((source) => <th key={source.id}>{source.key}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {[...new Set(rows.flatMap((source) => source.capabilities.map((item) => item.capability)))].sort().map((name) => (
                        <tr key={name}>
                          <td>{capability(name)}</td>
                          {rows.map((source) => {
                            const item = source.capabilities.find((candidate) => candidate.capability === name);
                            return (
                              <td key={source.id}>
                                {item ? (
                                  <span className={`badge ${supportTone[item.support] ?? ""}`} title={item.reasonCode ? explain(item.reasonCode) : undefined}>
                                    {support(item.support)}
                                  </span>
                                ) : "—"}
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Loadable>
          </section>
        </Allowed>

      </Allowed>

      <Allowed to="listScans">
        <section className="card">
          <h2>Сканирования</h2>
          <Loadable query={scans} empty="Сканирований ещё не было." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <div className="scroll">
                <table>
                  <thead>
                    <tr><th>Источник</th><th>Статус</th><th>Запущено</th><th>Завершено</th><th>Причина</th></tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.id}>
                        <td>{keyOf(row.sourceId)}</td>
                        <td>{scanStatus(row.status)}</td>
                        <td className="muted">{dateTime(row.createdAt)}</td>
                        <td className="muted">{dateTime(row.finishedAt)}</td>
                        <td><FailureNote code={row.failureCode} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Loadable>
        </section>

      </Allowed>

      <Allowed to="listAgents">
        <section className="card">
          <h2>Агенты</h2>
          <Loadable query={agents} empty="Агентов пока нет." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <div className="scroll">
                <table>
                  <thead>
                    <tr><th>Идентификатор</th><th>Статус</th><th>Версия</th><th>Был на связи</th><th>Сертификат до</th><th /></tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.id}>
                        <td className="mono">{row.id}</td>
                        <td><span className={`badge ${row.status === "active" ? "ok" : "bad"}`}>{row.status === "active" ? "Активен" : "Отозван"}</span></td>
                        <td className="mono">{row.version}</td>
                        <td className="muted">{dateTime(row.lastSeenAt)}</td>
                        <td className="muted">{dateTime(row.certificateExpires)}</td>
                        <td>
                          {can("revokeAgent") && row.status === "active" && (
                            <button
                              className="danger"
                              disabled={revoke.isPending}
                              onClick={() => { if (window.confirm("Отозвать агента? Он сразу потеряет доступ.")) revoke.mutate(row.id); }}
                            >
                              Отозвать
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Loadable>
        </section>

      </Allowed>

      <Allowed to="createEnrollmentToken">
        <Enrollment />
      </Allowed>
    </Page>
  );
}
