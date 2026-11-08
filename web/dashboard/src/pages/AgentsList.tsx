import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Copy, MoreHorizontal, Plus } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router";

import { api, type Schemas } from "../api";
import { AgentState, Mono } from "../components/domain";
import { Button } from "../components/ui/button";
import { Dialog, useConfirm } from "../components/ui/dialog";
import { Field, Select } from "../components/ui/form";
import { Menu, MenuItem } from "../components/ui/menu";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { useNotify } from "../components/ui/toast";
import { ago, count, dateTime, shortId } from "../labels";
import { ObjectLink, paths } from "../links";
import { useCan } from "../permissions";
import { queries } from "../queries";

type Agent = Schemas["Agent"];

export function useRevokeAgent() {
  const client = useQueryClient();
  const confirm = useConfirm();
  const notify = useNotify();
  const revoke = useMutation({
    mutationFn: (agent: Agent) => api.revokeAgent(agent.id),
    onSuccess: (_, agent) => {
      notify({ tone: "ok", title: `Агент ${shortId(agent.id)} отозван`, description: "Его сертификат больше не принимается." });
      return client.invalidateQueries({ queryKey: queries.agents().queryKey });
    },
    onError: (error) => notify({ tone: "bad", title: "Агент не отозван", description: error.message }),
  });
  return async (agent: Agent) => {
    const yes = await confirm({
      title: `Отозвать агента ${shortId(agent.id)}?`,
      description: "Агент сразу потеряет доступ к центру, его источники перестанут сканироваться и присылать события. Вернуть агента можно только новой регистрацией.",
      confirm: "Отозвать",
      danger: true,
    });
    if (yes) revoke.mutate(agent);
  };
}

export const environmentKinds: Record<Schemas["EnvironmentKind"], string> = {
  production: "Производственная",
  testing: "Тестовая",
  development: "Разработка",
};

function Enrollment({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const can = useCan();
  const notify = useNotify();
  const environments = useQuery({ ...queries.environments(), enabled: open && can("listEnvironments") });
  const [environmentId, setEnvironmentId] = useState("");
  const token = useMutation({ mutationFn: api.createToken });
  const selected = environmentId || environments.data?.[0]?.id || "";
  const close = (next: boolean) => {
    onOpenChange(next);
    if (!next) token.reset();
  };
  const copy = (value: string) => navigator.clipboard.writeText(value).then(
    () => notify({ tone: "ok", title: "Токен скопирован" }),
    () => notify({ tone: "bad", title: "Не удалось скопировать" }),
  );
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title="Подключить агента"
      description="Агент устанавливается в контуре заказчика и регистрируется одноразовым токеном."
      footer={token.data ? <Button onClick={() => close(false)}>Готово</Button> : (
        <>
          <Button onClick={() => close(false)}>Отмена</Button>
          <Button variant="primary" disabled={!selected || token.isPending} onClick={() => token.mutate(selected)}>Выпустить токен</Button>
        </>
      )}
    >
      {token.data ? (
        <div className="flex flex-col gap-3 text-sm">
          <p className="text-fg-2">Токен показывается один раз, годится для одной регистрации и действует до {dateTime(token.data.expiresAt)}.</p>
          <div className="flex items-start gap-2">
            <code className="min-w-0 flex-1 rounded-md bg-surface-2 px-3 py-2 font-mono text-xs break-all text-fg">{token.data.token}</code>
            <Button size="icon" aria-label="Скопировать токен" onClick={() => void copy(token.data.token)}><Copy /></Button>
          </div>
          <p className="text-fg-2">
            Агент читает токен со стандартного ввода, поэтому он не попадёт в историю команд. На стенде выполните <code className="font-mono text-fg">make agent-enroll</code>, вставьте токен, затем <code className="font-mono text-fg">make agent-up</code>.
          </p>
        </div>
      ) : environments.data?.length === 0 ? (
        <p className="text-sm text-fg-2">
          Сначала создайте среду: агент принадлежит одной среде.{" "}
          {can("createEnvironment") && <Link to="/environments" className="text-accent hover:underline" onClick={() => close(false)}>Создать среду</Link>}
        </p>
      ) : (
        <Field label="Среда" hint="Среда группирует агентов: производственная, тестовая, разработки">
          <Select
            value={selected}
            onValueChange={setEnvironmentId}
            placeholder="Загрузка…"
            options={(environments.data ?? []).map((item) => ({ value: item.id, label: item.name, hint: environmentKinds[item.kind] }))}
          />
        </Field>
      )}
      {token.isError && <p role="alert" className="mt-3 text-sm text-bad">{token.error.message}</p>}
    </Dialog>
  );
}

const certificateSoonMs = 3 * 24 * 3_600_000;

export function AgentsList() {
  const can = useCan();
  const revoke = useRevokeAgent();
  const [enrolling, setEnrolling] = useState(false);
  const agents = useQuery({ ...queries.agents(), enabled: can("listAgents") });
  const environments = useQuery({ ...queries.environments(), enabled: can("listEnvironments") });
  const sources = useQuery({ ...queries.sources(), enabled: can("listSources") });

  const columns = useMemo<TableColumn<Agent>[]>(() => [
    { id: "agent", header: "Агент", enableHiding: false, accessorFn: (row) => row.id, cell: ({ row }) => <ObjectLink to={paths.agent(row.original.id)} needs="getAgent" className="font-mono text-[13px]">{row.original.id}</ObjectLink> },
    { id: "state", header: "Состояние", accessorFn: (row) => row.status, cell: ({ row }) => <AgentState agent={row.original} /> },
    { id: "environment", header: "Среда", accessorFn: (row) => environments.data?.find((item) => item.id === row.environmentId)?.name ?? "", cell: ({ getValue }) => (getValue() as string) || <span className="text-fg-3">—</span> },
    { id: "version", header: "Версия", accessorFn: (row) => row.version, cell: ({ row }) => <Mono>{row.original.version}</Mono> },
    ...(can("listSources") ? [{ id: "sources", header: "Источников", accessorFn: (row: Agent) => sources.data?.filter((source) => source.agentId === row.id).length ?? 0, meta: { align: "right" as const }, cell: ({ getValue }: { getValue: () => unknown }) => count(getValue() as number) }] : []),
    { id: "seen", header: "Был на связи", accessorFn: (row) => row.lastSeenAt ?? "", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastSeenAt)}</span> },
    {
      id: "certificate", header: "Сертификат до", accessorFn: (row) => row.certificateExpires,
      cell: ({ row }) => {
        const soon = row.original.status === "active" && new Date(row.original.certificateExpires).getTime() - Date.now() < certificateSoonMs;
        return <span className={soon ? "whitespace-nowrap text-warn" : "whitespace-nowrap text-fg-2"}>{dateTime(row.original.certificateExpires)}</span>;
      },
    },
    {
      id: "actions", header: "", enableHiding: false, enableSorting: false, meta: { className: "w-10 text-right" },
      cell: ({ row }) => (can("revokeAgent") && row.original.status === "active" ? (
        <Menu trigger={<Button variant="ghost" size="icon-sm" aria-label={`Действия с агентом ${shortId(row.original.id)}`}><MoreHorizontal /></Button>}>
          <MenuItem icon={<Ban />} className="text-bad [&_svg]:text-bad" onSelect={() => void revoke(row.original)}>Отозвать</MenuItem>
        </Menu>
      ) : null),
    },
  ], [can, environments.data, sources.data, revoke]);

  return (
    <>
      <PageHeader
        title="Агенты"
        description="Агенты работают в контуре заказчика, сканируют источники и читают журналы аудита. Исходные значения не покидают контур."
        actions={can("createEnrollmentToken") ? <Button variant="primary" onClick={() => setEnrolling(true)}><Plus /> Подключить агента</Button> : undefined}
      />
      {can("listAgents") && (
        <Panel flush>
          <DataTable
            id="agents"
            columns={columns}
            data={agents.data}
            getRowId={(agent) => agent.id}
            loading={agents.isPending}
            error={agents.error}
            sortable
            empty={<EmptyState title="Агентов пока нет" action={can("createEnrollmentToken") ? <Button variant="primary" onClick={() => setEnrolling(true)}><Plus /> Подключить агента</Button> : undefined}>Агент нужен, чтобы сканировать базы и собирать аудит.</EmptyState>}
          />
        </Panel>
      )}
      <Enrollment open={enrolling} onOpenChange={setEnrolling} />
    </>
  );
}
