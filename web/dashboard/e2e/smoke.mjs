// Walks the dashboard in a real browser against a running platform. The Go
// end-to-end test starts it in the browser-check container with an account it created.
import { chromium } from "playwright";

const credentials = { api: process.env.DG_UI_URL, user: process.env.DG_UI_USER, password: process.env.DG_UI_PASSWORD };
const sourcePassword = process.env.DG_UI_SOURCE_PASSWORD;
if (!credentials.api || !credentials.user || !credentials.password || !sourcePassword) {
  throw new Error("DG_UI_URL, DG_UI_USER, DG_UI_PASSWORD and DG_UI_SOURCE_PASSWORD are required");
}
const output = process.argv[2];

const pages = [
  { path: "/overview", heading: "Обзор", expect: ["Активность", "Требует внимания", "Что читают", "Изменения в инвентаре"] },
  { path: "/inventory", heading: "Инвентаризация", expect: ["dg_users", "Чувствительных", "Все источники"] },
  { path: "/classification", heading: "Классификация", expect: ["ИНН", "Платёжная карта", "Колонок"] },
  { path: "/classification?tab=findings", heading: "Классификация", expect: ["Уверенность", "ИНН", "dg_users"] },
  { path: "/audit", heading: "Журнал событий", expect: ["Доказательство", "Запрос выполнен", "dg_app"] },
  { path: "/principals", heading: "Пользователи СУБД", expect: ["employee-123", "Подтверждено приложением", "Не идентифицирован"] },
  { path: "/sources", heading: "Источники", expect: ["Подключено", "Наблюдается", "Добавить источник", "Каждый день", "Вручную"] },
  { path: "/sources?tab=coverage", heading: "Источники", expect: ["Аудит чтения", "До колонок"] },
  { path: "/sources?tab=capabilities", heading: "Источники", expect: ["Нет в СУБД", "Аудит чтения"] },
  { path: "/agents", heading: "Агенты", expect: ["На связи", "Подключить агента"] },
  { path: "/policy", heading: "Политика", expect: ["Собственные детекторы", "Бюджет сканирования"] },
  { path: "/signals", heading: "Сигналы риска", expect: ["Правила", "Новая категория"] },
  { path: "/environments", heading: "Среды", expect: ["Производственная"] },
  // The source added through the form above is in the journal under its name,
  // and so is its schedule.
  { path: "/journal", heading: "Журнал действий", expect: ["Добавление источника", "ui-postgres", "Настройка расписания сканирования", "Сканировать каждый день", "Выпуск токена регистрации", "Регистрация агента"] },
];

const failures = [];
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1360, height: 900 }, locale: "ru-RU" });
const page = await context.newPage();
// A failed request is judged by its address: the browser's own console line
// does not say which request failed. An unpublished policy answers 404 by
// contract, and the page says so; any other failure is a defect.
const expectedFailures = [{ path: "/api/v1/policy", status: 404 }];
page.on("console", (message) => {
  if (message.type() === "error" && !message.text().startsWith("Failed to load resource")) failures.push(`console: ${message.text()}`);
});
page.on("response", (response) => {
  const url = new URL(response.url());
  if (response.status() < 400 || !url.pathname.startsWith("/api/")) return;
  if (expectedFailures.some((item) => item.path === url.pathname && item.status === response.status())) return;
  failures.push(`request: ${response.request().method()} ${url.pathname} answered ${response.status()}`);
});
page.on("pageerror", (error) => failures.push(`page error: ${error.message}`));

// Links navigate inside the page, so the load state stays idle from the first
// load: each expected text is waited for instead.
async function expectOnPage(step, expected) {
  for (const item of expected) {
    try {
      await page.locator("main").getByText(item, { exact: false }).filter({ visible: true }).first().waitFor({ timeout: 30_000 });
    } catch {
      failures.push(`${step}: no "${item}"`);
    }
  }
  const text = await page.locator("body").innerText();
  if (text.includes("undefined") || text.includes("NaN")) failures.push(`${step}: broken value on screen`);
  if (text.includes("dgcanary")) failures.push(`${step}: a source value is on screen`);
  if (text.includes(sourcePassword)) failures.push(`${step}: a database password is on screen`);
}

async function heading(name) {
  await page.getByRole("heading", { level: 1, name, exact: true }).waitFor();
}

async function noSidewaysScroll(step) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 0) failures.push(`${step}: page scrolls sideways by ${overflow}px`);
}

// A link opened while signed out goes straight to the sign-in form and, after
// it, back to the same page with its filter, even from an address of the
// previous navigation.
try {
  await page.goto(`${credentials.api}/catalog?category=GOVERNMENT.TAX_ID`);
  await page.locator("#username").fill(credentials.user);
  await page.locator("#password").fill(credentials.password);
  await page.locator("#kc-login").click();
  await heading("Классификация");
  const landed = new URL(page.url());
  if (landed.pathname !== "/classification" || landed.searchParams.get("category") !== "GOVERNMENT.TAX_ID" || landed.searchParams.get("tab") !== "findings") {
    failures.push(`sign-in returned to ${page.url()}`);
  }
} catch (error) {
  await page.screenshot({ path: `${output}/login-failure.png`, fullPage: true });
  process.stderr.write(`login failed at ${page.url()}\n${failures.join("\n")}\n${(await page.locator("body").innerText()).slice(0, 500)}\n`);
  throw error;
}

// Scenario: an administrator connects a source. The browser seals the
// password; the panel stays open and shows whether the agent connected.
try {
  await page.goto(`${credentials.api}/sources`);
  await page.getByRole("button", { name: "Добавить источник" }).first().click();
  const form = page.getByRole("form", { name: "Новый источник" });
  await form.getByLabel("Имя", { exact: true }).fill("ui-postgres");
  await form.getByLabel("Хост", { exact: true }).fill("source-postgres");
  await form.getByLabel("База данных", { exact: true }).fill("crm");
  await form.getByLabel("Пользователь", { exact: true }).fill("dg_scanner");
  await form.getByLabel("Пароль", { exact: true }).fill(sourcePassword);
  await form.getByRole("combobox", { name: /^TLS/ }).click();
  await page.getByRole("option", { name: "Без шифрования" }).click();
  // The check runs on a draft before anything is saved.
  await form.getByRole("button", { name: "Проверить подключение" }).click();
  const check = form.getByRole("region", { name: "Проверка подключения" });
  await check.getByText("Подключено", { exact: true }).waitFor({ timeout: 90_000 });
  await page.screenshot({ path: `${output}/source-checked.png`, fullPage: true });
  await form.getByRole("button", { name: "Сохранить" }).click();
  await page.getByRole("dialog").getByText("Подключено", { exact: true }).waitFor({ timeout: 90_000 });
  await page.screenshot({ path: `${output}/source-added.png`, fullPage: true });
  await page.getByRole("dialog").getByRole("button", { name: "Закрыть", exact: true }).last().click();
} catch (error) {
  await page.screenshot({ path: `${output}/source-failure.png`, fullPage: true });
  throw error;
}

// Scenario: the administrator has the new source scanned every night; the
// dialog suggests the coming 02:00 and every day.
try {
  await page.getByRole("link", { name: "ui-postgres", exact: true }).first().click();
  await heading("ui-postgres");
  await page.getByRole("tab", { name: "Сканирования" }).click();
  await page.getByRole("button", { name: "Настроить" }).click();
  await page.getByRole("form", { name: "Расписание сканирования" }).getByRole("button", { name: "Сохранить" }).click();
  await expectOnPage("scan schedule", ["Сканировать каждый день", "Следующий скан"]);
  await page.screenshot({ path: `${output}/source-schedule.png`, fullPage: true });
} catch (error) {
  await page.screenshot({ path: `${output}/schedule-failure.png`, fullPage: true });
  throw error;
}

for (const scheme of ["light", "dark"]) {
  await page.emulateMedia({ colorScheme: scheme });
  for (const item of pages) {
    await page.goto(credentials.api + item.path);
    await heading(item.heading);
    await expectOnPage(`${scheme} ${item.path}`, item.expect);
    await noSidewaysScroll(`${scheme} ${item.path}`);
    await page.screenshot({ path: `${output}/${scheme}${item.path.replace(/[/?=]/g, "-")}.png`, fullPage: true });
  }
}

await page.emulateMedia({ colorScheme: "light" });
try {
  // Scenario: from a source to the events of one column, by links alone.
  await page.goto(`${credentials.api}/sources`);
  const row = page.getByRole("row").filter({ hasText: "PostgreSQL" }).filter({ hasText: "Подключено" }).filter({ hasNotText: "ui-postgres" }).first();
  const sourceName = await row.getByRole("link").first().innerText();
  await row.getByRole("link").first().click();
  await heading(sourceName);
  await expectOnPage("source", ["Подключение", "Аудит за сутки", "Что источник позволяет видеть"]);
  await page.screenshot({ path: `${output}/object-source.png`, fullPage: true });

  await page.locator("main dl").getByRole("link").first().click();
  await page.getByRole("heading", { level: 1, name: /^Агент/ }).waitFor();
  await expectOnPage("agent", ["На связи", "Источники агента", sourceName]);
  await page.goBack();

  await heading(sourceName);
  await page.getByRole("tab", { name: "Таблицы" }).click();
  await page.getByRole("link", { name: "dg_users", exact: true }).click();
  await heading("dg_users");
  await expectOnPage("table", ["Колонки", "email", "Email", sourceName]);
  await page.screenshot({ path: `${output}/object-table.png`, fullPage: true });

  await page.getByRole("link", { name: "email", exact: true }).click();
  await heading("email");
  await expectOnPage("column", ["Классификация", "Найдено", "Email", "Кто читал колонку", "dg_app", "Последние обращения"]);
  await page.screenshot({ path: `${output}/object-column.png`, fullPage: true });

  // A favourite is kept in the center and shows in the side panel.
  await page.getByRole("button", { name: "В избранное" }).click();
  await page.getByRole("button", { name: "В избранном" }).waitFor();
  await page.locator("nav[aria-label='Разделы']").getByRole("link", { name: "email" }).waitFor();

  await page.getByRole("link", { name: "Обращения к колонке" }).click();
  await heading("Журнал событий");
  await expectOnPage("events of the column", ["Колонка:", "dg_app"]);
  if (!new URL(page.url()).searchParams.get("columnId")) failures.push("events of the column: the filter is not in the address");

  // Scenario: from an event to its source and database objects.
  await page.locator("main tbody tr").first().click();
  const details = page.getByRole("dialog");
  await details.getByText("К чему").waitFor();
  await details.getByRole("link", { name: /dg_users\.email$/ }).first().waitFor({ timeout: 15_000 }).catch(() => failures.push("event details: the column is not a link"));
  await details.getByText("Сессия СУБД").waitFor().catch(() => failures.push("event details: no session"));
  await page.screenshot({ path: `${output}/object-event.png`, fullPage: true });
  await details.getByRole("button", { name: "Все события этой сессии" }).click();
  await expectOnPage("events of a session", ["Сессия:"]);
  if (!new URL(page.url()).searchParams.get("sessionId")) failures.push("session filter is not in the address");

  // The selection exports as CSV and saves as a view.
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "CSV" }).click();
  if (!(await download).suggestedFilename().endsWith(".csv")) failures.push("export: not a CSV file");
  await page.getByRole("button", { name: "Представления" }).click();
  await page.getByRole("menuitem", { name: "Сохранить текущую выборку…" }).click();
  await page.getByRole("form", { name: "Сохранить представление" }).getByLabel("Название", { exact: true }).fill("Сессия из проверки");
  await page.getByRole("form", { name: "Сохранить представление" }).getByRole("button", { name: "Сохранить" }).click();
  await page.locator("nav[aria-label='Разделы']").getByRole("link", { name: "Сессия из проверки" }).waitFor();

  // Scenario: a kind of data, then where it lies, who read it and what they did.
  await page.goto(`${credentials.api}/classification`);
  await page.locator("main").getByRole("link", { name: "ИНН", exact: true }).first().click();
  await heading("ИНН");
  await expectOnPage("category", ["Где хранятся", "dg_users", "Кто обращался", "dg_app", "Последние обращения"]);
  await page.screenshot({ path: `${output}/object-category.png`, fullPage: true });
  await page.locator("section").filter({ hasText: "Кто обращался" }).getByRole("link", { name: "dg_app", exact: true }).first().click();
  await heading("Журнал событий");
  const filtered = new URL(page.url()).searchParams;
  if (filtered.get("principal") !== "dg_app" || filtered.get("category") !== "GOVERNMENT.TAX_ID") failures.push(`category reader: landed on ${page.url()}`);

  // Scenario: tables with personal data, by one filter.
  await page.goto(`${credentials.api}/inventory?sensitive=1`);
  await heading("Инвентаризация");
  await expectOnPage("sensitive tables", ["dg_users"]);
  if (await page.locator("main tbody").getByText("dg_orders", { exact: true }).count() > 0) failures.push("sensitive tables: dg_orders has no sensitive columns but is listed");

  // Global search opens a table by part of its name.
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Что найти" }).fill("dg_us");
  await page.getByRole("option").filter({ hasText: "dg_users" }).first().waitFor();
  await page.screenshot({ path: `${output}/search.png` });
  await page.getByRole("option").filter({ hasText: "dg_users" }).first().click();
  await heading("dg_users");

  // Database principals are searchable too, and lead to their events.
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Что найти" }).fill("dg_ap");
  await page.getByRole("option").filter({ hasText: "обращений за 30 дней" }).first().click();
  await heading("Журнал событий");
  if (new URL(page.url()).searchParams.get("principal") !== "dg_app") failures.push(`principal search: landed on ${page.url()}`);

  // Personal settings follow the account to another browser.
  const other = await browser.newContext({ viewport: { width: 1360, height: 900 }, locale: "ru-RU" });
  const second = await other.newPage();
  await second.goto(`${credentials.api}/overview`);
  await second.locator("#username").fill(credentials.user);
  await second.locator("#password").fill(credentials.password);
  await second.locator("#kc-login").click();
  await second.getByRole("heading", { level: 1, name: "Обзор" }).waitFor();
  const sidebar = second.locator("nav[aria-label='Разделы']");
  await sidebar.getByRole("link", { name: "Сессия из проверки" }).waitFor({ timeout: 15_000 }).catch(() => failures.push("saved view is not in another browser"));
  await sidebar.getByRole("link", { name: "email" }).waitFor({ timeout: 15_000 }).catch(() => failures.push("favourite is not in another browser"));
  await second.screenshot({ path: `${output}/second-browser.png`, fullPage: true });
  await other.close();
} catch (error) {
  await page.screenshot({ path: `${output}/object-failure.png`, fullPage: true });
  throw error;
}

for (const [width, name] of [[380, "phone"], [900, "tablet"]]) {
  await page.setViewportSize({ width, height: 800 });
  for (const path of ["/overview", "/sources", "/audit"]) {
    await page.goto(credentials.api + path);
    await page.getByRole("heading", { level: 1 }).waitFor();
    await page.waitForTimeout(500);
    await noSidewaysScroll(`${name} ${path}`);
  }
  await page.screenshot({ path: `${output}/${name}-audit.png`, fullPage: true });
}

await browser.close();
if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}
process.stdout.write(`checked ${pages.length} pages in 2 themes, the main scenarios, phone and tablet width\n`);
