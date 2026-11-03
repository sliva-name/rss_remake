import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { capability, count, coverageReason, dateTime, engine, percent, scanStatus, support } from "../labels";
import { CoverageBadge, Loadable, Page } from "../ui";

const supportTone: Record<string, string> = { SUPPORT_AVAILABLE: "ok", SUPPORT_NOT_CONFIGURED: "warn", SUPPORT_UNKNOWN: "warn" };

function Enrollment() {
  const environments = useQuery({ queryKey: ["environments"], queryFn: api.environments });
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
        <label className="field">
          Новая среда
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Название" />
        </label>
        <button disabled={!name || create.isPending} onClick={() => create.mutate()}>Создать</button>
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
      {token.data && (
        <>
          <p className="muted">Токен показывается один раз и действует до {dateTime(token.data.expiresAt)}.</p>
          <div className="token">{token.data.token}</div>
        </>
      )}
    </section>
  );
}

export function Infrastructure({ roles }: { roles: string[] }) {
  const client = useQueryClient();
  const admin = roles.includes("tenant_admin");
  const canScan = admin || roles.includes("security_analyst");
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24) });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
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
                        {row.reason && <div className="muted">{coverageReason(row.reason)}</div>}
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
                        {canScan && (
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
                              <span className={`badge ${supportTone[item.support] ?? ""}`} title={item.reasonCode}>
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
                      <td className="mono muted">{row.failureCode}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Loadable>
      </section>

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
                        {admin && row.status === "active" && (
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

      {admin && <Enrollment />}
    </Page>
  );
}
