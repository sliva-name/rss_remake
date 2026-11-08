import { useQuery } from "@tanstack/react-query";
import { Ban } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { AgentState, Mono, SourceState } from "../components/domain";
import { Button } from "../components/ui/button";
import { PageHeader } from "../components/ui/page";
import { Facts, Panel } from "../components/ui/panel";
import { EmptyState, ErrorState, Loadable, Loading } from "../components/ui/state";
import { ago, dateTime, engine, shortId } from "../labels";
import { ObjectLink, paths } from "../links";
import { useCan } from "../permissions";
import { useRevokeAgent } from "./AgentsList";

export function AgentPage() {
  const { id = "" } = useParams();
  const can = useCan();
  const revoke = useRevokeAgent();
  const agent = useQuery({ queryKey: ["agent", id], queryFn: () => api.agent(id), refetchInterval: 10_000 });
  const environments = useQuery({ queryKey: ["environments"], queryFn: api.environments, enabled: can("listEnvironments") });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });

  if (agent.isPending) return <Loading rows={6} />;
  if (agent.isError) return <ErrorState error={agent.error} />;
  const data = agent.data;
  const environment = environments.data?.find((item) => item.id === data.environmentId);

  return (
    <>
      <PageHeader
        breadcrumbs={[<Link key="agents" to="/agents">Агенты</Link>, shortId(data.id)]}
        title={<>Агент <span className="font-mono">{shortId(data.id)}</span></>}
        description="Работает в контуре заказчика и открывает только источники из своего локального списка разрешённых."
        meta={<AgentState agent={data} />}
        actions={can("revokeAgent") && data.status === "active" ? <Button variant="danger" onClick={() => void revoke(data)}><Ban /> Отозвать</Button> : undefined}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Panel title="Агент">
          <Facts
            items={[
              ["Идентификатор", <Mono key="id" className="break-all">{data.id}</Mono>],
              ["Среда", environment?.name ?? <Mono key="environment" className="text-fg-3">{data.environmentId}</Mono>],
              ["Версия", <Mono key="version">{data.version}</Mono>],
              ["Был на связи", data.lastSeenAt ? `${ago(data.lastSeenAt)} · ${dateTime(data.lastSeenAt)}` : "ещё не выходил на связь"],
              ["Сертификат до", dateTime(data.certificateExpires)],
              ["Зарегистрирован", dateTime(data.createdAt)],
              ["Ключ для паролей", data.sealingPublicKey ? "Есть: принимает запечатанные пароли" : "Нет: зарегистрируйте агента заново, чтобы добавлять источники"],
            ]}
          />
        </Panel>
        {can("listSources") && (
          <Panel title="Источники агента" flush>
            <Loadable query={sources} isEmpty={(rows) => !rows.some((row) => row.agentId === data.id)} empty={<EmptyState title="Источников у агента нет">Источники добавляются в разделе «Источники».</EmptyState>}>
              {(rows) => (
                <ul className="divide-y divide-border">
                  {rows.filter((row) => row.agentId === data.id).map((source) => (
                    <li key={source.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                      <div>
                        <ObjectLink to={paths.source(source.id)} needs="getSource" className="font-medium">{source.key}</ObjectLink>
                        <div className="text-xs text-fg-2">{engine(source.engine)} {source.engineVersion} · <Mono>{source.host}:{source.port}/{source.database}</Mono></div>
                      </div>
                      <SourceState statusCode={source.statusCode} probedAt={source.probedAt} />
                    </li>
                  ))}
                </ul>
              )}
            </Loadable>
          </Panel>
        )}
      </div>
    </>
  );
}
