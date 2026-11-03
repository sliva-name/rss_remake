import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { api } from "../api";
import { category, categoryIds, count, samplingMethod } from "../labels";
import { Confidence, Loadable, Page } from "../ui";

const pageSize = 50;

export function Catalog() {
  const [selected, setSelected] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [offset, setOffset] = useState(0);
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  const columns = useQuery({
    queryKey: ["catalog", selected, sourceId, offset],
    queryFn: () => api.catalog({ category: selected, sourceId, limit: pageSize, offset }),
  });

  return (
    <Page title="Каталог данных" lead="Колонки с обнаруженными чувствительными данными. Значения в платформу не передаются.">
      <div className="filters">
        <label className="field">
          Источник
          <select value={sourceId} onChange={(event) => { setSourceId(event.target.value); setOffset(0); }}>
            <option value="">Все</option>
            {sources.data?.map((source) => (
              <option key={source.id} value={source.id}>{source.key}</option>
            ))}
          </select>
        </label>
        <label className="field">
          Категория
          <select value={selected} onChange={(event) => { setSelected(event.target.value); setOffset(0); }}>
            <option value="">Все</option>
            {categoryIds.map((id) => (
              <option key={id} value={id}>{category(id)}</option>
            ))}
          </select>
        </label>
      </div>
      <section className="card">
        <Loadable query={columns} empty="Ничего не найдено. Запустите сканирование в разделе «Инфраструктура»." isEmpty={(page) => page.items.length === 0}>
          {(page) => (
            <>
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Источник</th>
                      <th>Колонка</th>
                      <th>Тип</th>
                      <th>Категория</th>
                      <th>Уверенность</th>
                      <th>Основание</th>
                      <th className="num">Совпало строк</th>
                      <th className="num">Уникальных ≈</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.items.map((item) => (
                      <tr key={`${item.columnId}-${item.categoryId}`}>
                        <td>{sources.data?.find((source) => source.id === item.sourceId)?.key ?? "—"}</td>
                        <td className="mono">{item.schema}.{item.table}.{item.column}</td>
                        <td className="mono muted">{item.nativeType}</td>
                        <td>{category(item.categoryId)}</td>
                        <td><Confidence value={item.confidence} /></td>
                        <td className="muted">{samplingMethod(item.samplingMethod)}</td>
                        <td className="num">
                          {count(item.rowsMatched)}
                          <span className="muted"> из {count(item.rowsInspected)}</span>
                        </td>
                        <td className="num">{count(item.uniqueEstimate)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="pager">
                <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>Назад</button>
                <button disabled={offset + pageSize >= page.total} onClick={() => setOffset(offset + pageSize)}>Дальше</button>
                <span>Всего: {count(page.total)}</span>
              </div>
            </>
          )}
        </Loadable>
      </section>
    </Page>
  );
}
