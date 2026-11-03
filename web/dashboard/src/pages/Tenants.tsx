import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { dateTime } from "../labels";
import { Loadable, Page } from "../ui";

export function Tenants() {
  const client = useQueryClient();
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: api.tenants });
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => api.createTenant(name),
    onSuccess: () => {
      setName("");
      return client.invalidateQueries({ queryKey: ["tenants"] });
    },
  });
  return (
    <Page title="Организации" lead="Администратор платформы управляет организациями, но не видит их данных.">
      <div className="filters">
        <label className="field">
          Новая организация
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Название" />
        </label>
        <button className="primary" disabled={!name || create.isPending} onClick={() => create.mutate()}>Создать</button>
      </div>
      {create.isError && <div className="error">{create.error.message}</div>}
      <section className="card">
        <Loadable query={tenants} empty="Организаций пока нет." isEmpty={(rows) => rows.length === 0}>
          {(rows) => (
            <table>
              <thead><tr><th>Название</th><th>Идентификатор</th><th>Создана</th></tr></thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.name}</td>
                    <td className="mono muted">{row.id}</td>
                    <td className="muted">{dateTime(row.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Loadable>
      </section>
    </Page>
  );
}
