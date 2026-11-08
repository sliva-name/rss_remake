import { useQuery } from "@tanstack/react-query";

import { api } from "../api";
import { category, categoryIds, count, samplingMethod } from "../labels";
import { CategoryLink, ObjectLink, paths, useUrlFilters } from "../links";
import { useCan } from "../permissions";
import { Confidence, Loadable, Page } from "../ui";

const pageSize = 50;

export function Catalog() {
  const [filters, update] = useUrlFilters(["sourceId", "category"]);
  const { sourceId, category: selected } = filters;
  const offset = Number(filters.offset) || 0;
  const can = useCan();
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  const columns = useQuery({
    queryKey: ["catalog", selected, sourceId, offset],
    queryFn: () => api.catalog({ category: selected, sourceId, limit: pageSize, offset }),
  });

  return (
    <Page title="Каталог данных" lead="Колонки с обнаруженными чувствительными данными. Значения в платформу не передаются.">
      <div className="filters">
        <label className="field">
          Источник
          <select value={sourceId} onChange={(event) => update({ sourceId: event.target.value })}>
            <option value="">Все</option>
            {sources.data?.map((source) => (
              <option key={source.id} value={source.id}>{source.key}</option>
            ))}
          </select>
        </label>
        <label className="field">
          Категория
          <select value={selected} onChange={(event) => update({ category: event.target.value })}>
            <option value="">Все</option>
            {categoryIds.map((id) => (
              <option key={id} value={id}>{category(id)}</option>
            ))}
          </select>
        </label>
      </div>
      <section className="card">
        <Loadable query={columns} empty="Ничего не найдено. Запустите сканирование в разделе «Источники и агенты»." isEmpty={(page) => page.items.length === 0}>
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
                        <td>
                          <ObjectLink to={paths.source(item.sourceId)} needs="getSource">
                            {sources.data?.find((source) => source.id === item.sourceId)?.key ?? "Источник"}
                          </ObjectLink>
                        </td>
                        <td className="mono">
                          <ObjectLink to={paths.table(item.tableId)} needs="getCatalogTable">{item.schema}.{item.table}</ObjectLink>.
                          <ObjectLink to={paths.column(item.columnId)} needs="getCatalogColumn">{item.column}</ObjectLink>
                        </td>
                        <td className="mono muted">{item.nativeType}</td>
                        <td><CategoryLink id={item.categoryId}>{category(item.categoryId)}</CategoryLink></td>
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
                <button disabled={offset === 0} onClick={() => update({ offset: String(Math.max(0, offset - pageSize)) })}>Назад</button>
                <button disabled={offset + pageSize >= page.total} onClick={() => update({ offset: String(offset + pageSize) })}>Дальше</button>
                <span>Всего: {count(page.total)}</span>
              </div>
            </>
          )}
        </Loadable>
      </section>
    </Page>
  );
}
