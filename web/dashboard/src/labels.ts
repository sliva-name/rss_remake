// Display names only. Decisions such as a coverage status come from the backend;
// this file never derives one.

import failures from "./failures.json";

const categories: Record<string, string> = {
  "PERSONAL.EMAIL": "Email",
  "PERSONAL.PHONE": "Телефон",
  "PERSONAL.NAME": "ФИО",
  "PERSONAL.DATE_OF_BIRTH": "Дата рождения",
  "PERSONAL.ADDRESS": "Адрес",
  "GOVERNMENT.TAX_ID": "ИНН",
  "GOVERNMENT.SNILS": "СНИЛС",
  "GOVERNMENT.PASSPORT": "Паспорт",
  "FINANCIAL.PAYMENT_CARD": "Платёжная карта",
  "FINANCIAL.BANK_ACCOUNT": "Банковский счёт",
  "AUTHENTICATION.PASSWORD": "Пароль",
  "AUTHENTICATION.SECRET": "Секрет",
  "MEDICAL.RECORD": "Медицинские данные",
};

export const category = (id: string): string => categories[id] ?? id;
export const categoryIds = Object.keys(categories);

const sampling: Record<string, string> = {
  SAMPLING_METHOD_METADATA_ONLY: "По имени колонки",
  SAMPLING_METHOD_ENGINE_SAMPLE: "Выборка СУБД",
  SAMPLING_METHOD_BOUNDED_PREFIX: "Первые строки",
  SAMPLING_METHOD_FULL_SCAN: "Вся таблица",
};

export const samplingMethod = (id: string): string => sampling[id] ?? id;

const eventTypes: Record<string, string> = {
  EVENT_TYPE_DATA_ACCESS: "Чтение",
  EVENT_TYPE_DATA_MODIFICATION: "Изменение",
  EVENT_TYPE_DATA_DELETION: "Удаление",
  EVENT_TYPE_SCHEMA_CHANGE: "Схема",
  EVENT_TYPE_PERMISSION_CHANGE: "Права",
  EVENT_TYPE_AUTHENTICATION: "Вход",
  EVENT_TYPE_FAILED_ACCESS: "Отказ",
  EVENT_TYPE_AUDIT_GAP: "Потеря аудита",
};

export const eventType = (id: string): string => eventTypes[id] ?? id;
export const eventTypeIds = Object.keys(eventTypes);

// Wording matters here: a statement that names a column is not proof of a read.
const evidence: Record<string, string> = {
  EVIDENCE_LEVEL_REFERENCED: "Упомянуто в запросе",
  EVIDENCE_LEVEL_EXECUTED: "Запрос выполнен",
  EVIDENCE_LEVEL_ROWS_CONFIRMED: "Строки возвращены",
  EVIDENCE_LEVEL_DELIVERED: "Данные получены",
};

export const evidenceLevel = (id: string): string => evidence[id] ?? "Не определено";

const identities: Record<string, string> = {
  IDENTITY_CONFIDENCE_VERIFIED: "Подтверждено приложением",
  IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY: "Только учётная запись СУБД",
  IDENTITY_CONFIDENCE_UNVERIFIED_CLAIM: "Заявлено, подпись неверна",
  IDENTITY_CONFIDENCE_UNKNOWN: "Не идентифицирован",
};

export const identity = (id: string): string => identities[id] ?? "Не идентифицирован";

const resolutions: Record<string, string> = {
  OBJECT_RESOLUTION_RESOLVED: "До колонок",
  OBJECT_RESOLUTION_PARTIAL: "Частично",
  OBJECT_RESOLUTION_UNRESOLVED: "Не разобрано",
  OBJECT_RESOLUTION_UNSPECIFIED: "—",
};

export const resolution = (id: string): string => resolutions[id] ?? "—";

const statuses: Record<string, string> = {
  EXECUTION_STATUS_SUCCESS: "Успех",
  EXECUTION_STATUS_FAILURE: "Ошибка",
  EXECUTION_STATUS_UNKNOWN: "Неизвестно",
  EXECUTION_STATUS_UNSPECIFIED: "Неизвестно",
};

export const executionStatus = (id: string): string => statuses[id] ?? id;

const coverage: Record<string, string> = {
  OBSERVING: "Наблюдается",
  DEGRADED: "С ограничениями",
  BLIND: "Нет наблюдения",
  NOT_CONFIGURED: "Аудит не настроен",
};

export const coverageStatus = (id: string): string => coverage[id] ?? id;

// What happened and what to do about it, for every code the agent or the center
// reports. A Go test checks that each code produced has an entry here.
export type Failure = { problem: string; action: string };

const explained: Record<string, Failure> = failures;

export const failure = (code: string): Failure => explained[code] ?? { problem: code, action: "" };

// Both parts in one line, for a tooltip.
export const explain = (code: string): string => {
  const { problem, action } = failure(code);
  return action ? `${problem}. ${action}` : problem;
};

const engines: Record<string, string> = {
  ENGINE_POSTGRESQL: "PostgreSQL",
  ENGINE_MYSQL: "MySQL",
  ENGINE_MARIADB: "MariaDB",
  ENGINE_MSSQL: "SQL Server",
};

export const engine = (id: string): string => engines[id] ?? id;

const capabilities: Record<string, string> = {
  CAPABILITY_SCHEMA_DISCOVERY: "Обнаружение структуры",
  CAPABILITY_COLUMN_PROFILING: "Анализ значений",
  CAPABILITY_NATIVE_AUDIT: "Нативный аудит",
  CAPABILITY_READ_AUDIT: "Аудит чтения",
  CAPABILITY_TABLE_LEVEL_AUDIT: "Таблицы",
  CAPABILITY_COLUMN_LEVEL_AUDIT: "Колонки",
  CAPABILITY_QUERY_TEXT: "Текст запроса",
  CAPABILITY_EXECUTION_STATUS: "Исход запроса",
  CAPABILITY_RETURNED_ROWS: "Число строк",
  CAPABILITY_APPLICATION_CONTEXT: "Пользователь приложения",
};

export const capability = (id: string): string => capabilities[id] ?? id;

const supports: Record<string, string> = {
  SUPPORT_AVAILABLE: "Есть",
  SUPPORT_NOT_CONFIGURED: "Не настроено",
  SUPPORT_UNAVAILABLE: "Нет в СУБД",
  SUPPORT_UNKNOWN: "Неизвестно",
};

export const support = (id: string): string => supports[id] ?? id;

const changes: Record<string, string> = {
  TABLE_ADDED: "Новая таблица",
  TABLE_REMOVED: "Таблица удалена",
  TABLE_RENAMED: "Таблица переименована",
  COLUMN_ADDED: "Новая колонка",
  COLUMN_REMOVED: "Колонка удалена",
  COLUMN_RENAMED: "Колонка переименована",
  SENSITIVE_COLUMN_ADDED: "Новые чувствительные данные",
  SENSITIVE_COLUMN_REMOVED: "Чувствительные данные не найдены",
  SCHEMA_DRIFT_DETECTED: "Изменилась структура",
};

export const change = (id: string): string => changes[id] ?? id;

const scans: Record<string, string> = {
  pending: "В очереди",
  running: "Идёт",
  completed: "Завершён",
  partial: "Частично",
  failed: "Ошибка",
  cancelled: "Отменён",
};

export const scanStatus = (id: string): string => scans[id] ?? id;

export const sourceStatus = (code: string, probedAt: string | undefined): { label: string; tone: string } => {
  if (!probedAt) return { label: "Ожидает агента", tone: "warn" };
  if (!code) return { label: "Подключено", tone: "ok" };
  return { label: failure(code).problem, tone: "bad" };
};

export const percent = (share: number | undefined): string =>
  share === undefined ? "нет данных" : `${Math.round(share * 100)}%`;

export const dateTime = (value: string | undefined): string =>
  value ? new Date(value).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "medium" }) : "—";

export const count = (value: number): string => value.toLocaleString("ru-RU");

const tableKinds: Record<string, string> = {
  TABLE_KIND_TABLE: "Таблица",
  TABLE_KIND_VIEW: "Представление",
  TABLE_KIND_MATERIALIZED_VIEW: "Материализованное представление",
};

export const tableKind = (id: string): string => tableKinds[id] ?? id;
