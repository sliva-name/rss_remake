import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { api } from "../api";
import { dateTime, engine, sourceStatus } from "../labels";
import { ObjectLink, paths, Trail } from "../links";
import { Allowed, useCan } from "../permissions";
import { Facts, Loadable } from "../ui";

function Sources({ agentId }: { agentId: string }) {
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  return (
    <section className="card">
      <h2>Источники агента</h2>
      <Loadable query={sources} empty="">
        {(rows) => {
          const own = rows.filter((row) => row.agentId === agentId);
          if (own.length === 0) return <div className="empty">Источников у агента нет.</div>;
          return (
            <table>
              <thead><tr><th>Источник</th><th>СУБД</th><th>Подключение</th></tr></thead>
              <tbody>
                {own.map((row) => {
                  const status = sourceStatus(row.statusCode, row.probedAt);
                  return (
                    <tr key={row.id}>
                      <td><ObjectLink to={paths.source(row.id)} needs="getSource">{row.key}</ObjectLink></td>
                      <td className="muted">{engine(row.engine)} {row.engineVersion}</td>
                      <td><span className={`badge ${status.tone}`}>{status.label}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          );
        }}
      </Loadable>
    </section>
  );
}

export function AgentPage() {
  const { id = "" } = useParams();
  const can = useCan();
  const client = useQueryClient();
  const agent = useQuery({ queryKey: ["agent", id], queryFn: () => api.agent(id) });
  const environments = useQuery({ queryKey: ["environments"], queryFn: api.environments, enabled: can("listEnvironments") });
  const revoke = useMutation({
    mutationFn: api.revokeAgent,
    onSuccess: () => Promise.all([client.invalidateQueries({ queryKey: ["agent", id] }), client.invalidateQueries({ queryKey: ["agents"] })]),
  });
  return (
    <>
      <Trail>{[<ObjectLink key="infra" to="/infrastructure" needs="listAgents">Инфраструктура</ObjectLink>, "Агент"]}</Trail>
      <Loadable query={agent} empty="">
        {(data) => (
          <>
            <h1 className="mono">{data.id}</h1>
            <p className="lead">Агент работает в контуре заказчика и открывает только источники из своего локального списка разрешённых.</p>
            <section className="card">
              <div className="card-head">
                <h2>Агент</h2>
                {can("revokeAgent") && data.status === "active" && (
                  <button
                    className="danger"
                    disabled={revoke.isPending}
                    onClick={() => { if (window.confirm("Отозвать агента? Он сразу потеряет доступ.")) revoke.mutate(data.id); }}
                  >
                    Отозвать
                  </button>
                )}
              </div>
              <Facts
                items={[
                  ["Статус", <span className={`badge ${data.status === "active" ? "ok" : "bad"}`}>{data.status === "active" ? "Активен" : "Отозван"}</span>],
                  ["Среда", environments.data?.find((item) => item.id === data.environmentId)?.name ?? <span className="mono muted">{data.environmentId}</span>],
                  ["Версия", <span className="mono">{data.version}</span>],
                  ["Был на связи", dateTime(data.lastSeenAt)],
                  ["Сертификат до", dateTime(data.certificateExpires)],
                  ["Зарегистрирован", dateTime(data.createdAt)],
                ]}
              />
              {revoke.isError && <div className="error">{revoke.error.message}</div>}
            </section>
            <Allowed to="listSources"><Sources agentId={data.id} /></Allowed>
          </>
        )}
      </Loadable>
    </>
  );
}
