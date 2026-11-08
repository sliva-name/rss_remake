import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus } from "lucide-react";
import { type FormEvent, type ReactNode, useMemo, useState } from "react";

import { api, type Schemas } from "../api";
import { Mono } from "../components/domain";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable } from "../components/ui/table";
import { useNotify } from "../components/ui/toast";
import { count, dateTime } from "../labels";
import { useCan } from "../permissions";

const kinds: { id: Schemas["EnvironmentKind"]; label: string }[] = [
  { id: "production", label: "Производственная" },
  { id: "testing", label: "Тестовая" },
  { id: "development", label: "Разработка" },
];

function CreateDialog({ open, onOpenChange, title, description, label, children, onSubmit, pending, error }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  label: string;
  children: ReactNode;
  onSubmit: () => void;
  pending: boolean;
  error: Error | null;
}) {
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSubmit();
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={title} description={description}>
      <form onSubmit={submit} aria-label={title} className="flex flex-col gap-4">
        {children}
        {error && <p role="alert" className="text-sm text-bad">{error.message}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Отмена</Button>
          <Button type="submit" variant="primary" disabled={pending}>{label}</Button>
        </div>
      </form>
    </Dialog>
  );
}

export function Environments() {
  const can = useCan();
  const client = useQueryClient();
  const notify = useNotify();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Schemas["EnvironmentKind"]>("production");
  const environments = useQuery({ queryKey: ["environments"], queryFn: api.environments });
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents, enabled: can("listAgents") });
  const create = useMutation({
    mutationFn: () => api.createEnvironment({ name: name.trim(), kind }),
    onSuccess: async (created) => {
      notify({ tone: "ok", title: `Среда «${created.name}» создана`, description: "В неё можно регистрировать агентов." });
      setOpen(false);
      setName("");
      await client.invalidateQueries({ queryKey: ["environments"] });
    },
  });
  const columns = useMemo<ColumnDef<Schemas["Environment"], unknown>[]>(() => [
    { id: "name", header: "Среда", enableHiding: false, accessorFn: (row) => row.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: "kind", header: "Вид", accessorFn: (row) => row.kind, cell: ({ row }) => <Badge tone={row.original.kind === "production" ? "accent" : "neutral"}>{kinds.find((item) => item.id === row.original.kind)?.label ?? row.original.kind}</Badge> },
    ...(can("listAgents") ? [{ id: "agents", header: "Агентов", meta: { align: "right" as const }, accessorFn: (row: Schemas["Environment"]) => agents.data?.filter((agent) => agent.environmentId === row.id && agent.status === "active").length ?? 0, cell: ({ getValue }: { getValue: () => unknown }) => count(getValue() as number) }] : []),
    { id: "created", header: "Создана", accessorFn: (row) => row.createdAt, cell: ({ row }) => <span className="text-fg-2">{dateTime(row.original.createdAt)}</span> },
    { id: "id", header: "Идентификатор", cell: ({ row }) => <Mono className="text-fg-3">{row.original.id}</Mono> },
  ], [can, agents.data]);
  return (
    <>
      <PageHeader
        title="Среды"
        description="Агенты регистрируются в среде: производственной, тестовой или разработки."
        actions={can("createEnvironment") ? <Button variant="primary" onClick={() => setOpen(true)}><Plus /> Новая среда</Button> : undefined}
      />
      <Panel flush>
        <DataTable id="environments" columns={columns} data={environments.data} getRowId={(row) => row.id} loading={environments.isPending} error={environments.error} sortable empty={<EmptyState title="Сред пока нет">Создайте среду, чтобы подключить первого агента.</EmptyState>} />
      </Panel>
      <CreateDialog open={open} onOpenChange={setOpen} title="Новая среда" description="Имя видно в списках агентов и источников." label="Создать" onSubmit={() => create.mutate()} pending={create.isPending} error={create.error}>
        <Field label="Название"><Input required maxLength={100} value={name} onChange={(event) => setName(event.target.value)} placeholder="Основной ЦОД" /></Field>
        <Field label="Вид">
          <Select value={kind} onValueChange={(value) => setKind(value as Schemas["EnvironmentKind"])} options={kinds.map((item) => ({ value: item.id, label: item.label }))} />
        </Field>
      </CreateDialog>
    </>
  );
}

export function Tenants() {
  const can = useCan();
  const client = useQueryClient();
  const notify = useNotify();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: api.tenants });
  const create = useMutation({
    mutationFn: () => api.createTenant(name.trim()),
    onSuccess: async (created) => {
      notify({ tone: "ok", title: `Организация «${created.name}» создана` });
      setOpen(false);
      setName("");
      await client.invalidateQueries({ queryKey: ["tenants"] });
    },
  });
  const columns = useMemo<ColumnDef<Schemas["Tenant"], unknown>[]>(() => [
    { id: "name", header: "Организация", enableHiding: false, accessorFn: (row) => row.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: "id", header: "Идентификатор", cell: ({ row }) => <Mono className="text-fg-2">{row.original.id}</Mono> },
    { id: "created", header: "Создана", accessorFn: (row) => row.createdAt, cell: ({ row }) => <span className="text-fg-2">{dateTime(row.original.createdAt)}</span> },
  ], []);
  return (
    <>
      <PageHeader
        title="Организации"
        description="Администратор платформы управляет организациями, но не видит их данных."
        actions={can("createTenant") ? <Button variant="primary" onClick={() => setOpen(true)}><Plus /> Новая организация</Button> : undefined}
      />
      <Panel flush>
        <DataTable id="tenants" columns={columns} data={tenants.data} getRowId={(row) => row.id} loading={tenants.isPending} error={tenants.error} sortable empty={<EmptyState title="Организаций пока нет" />} />
      </Panel>
      <CreateDialog open={open} onOpenChange={setOpen} title="Новая организация" description="Учётные записи организации заводятся в провайдере входа с её идентификатором." label="Создать" onSubmit={() => create.mutate()} pending={create.isPending} error={create.error}>
        <Field label="Название"><Input required maxLength={200} value={name} onChange={(event) => setName(event.target.value)} /></Field>
      </CreateDialog>
    </>
  );
}
