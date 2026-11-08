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
  { path: "/overview", heading: "Обзор", expect: ["Покрытие за сутки", "Изменения в инвентаре", "Наблюдается"] },
  { path: "/catalog", heading: "Каталог данных", expect: ["ИНН", "Платёжная карта", "Уверенность"] },
  { path: "/access", heading: "Обращения", expect: ["Доказательство", "Запрос выполнен", "Упомянуто в запросе", "dg_app"] },
  { path: "/identities", heading: "Пользователи", expect: ["employee-123", "Подтверждено приложением", "Не идентифицирован"] },
  { path: "/compliance", heading: "Отчёты", expect: ["Инвентарь по категориям", "Доступ по категориям"] },
  { path: "/infrastructure", heading: "Инфраструктура", expect: ["Источники", "Подключено", "Покрытие аудита", "Возможности источников", "Нет в СУБД", "Сканировать"] },
];

const failures = [];
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1360, height: 900 }, locale: "ru-RU" });
const page = await context.newPage();
page.on("console", (message) => {
  if (message.type() === "error") failures.push(`console: ${message.text()}`);
});
page.on("pageerror", (error) => failures.push(`page error: ${error.message}`));

try {
  await page.goto(credentials.api);
  await page.getByRole("button", { name: "Войти" }).click();
  await page.locator("#username").fill(credentials.user);
  await page.locator("#password").fill(credentials.password);
  await page.locator("#kc-login").click();
  await page.getByRole("heading", { name: "Обзор" }).waitFor();
} catch (error) {
  await page.screenshot({ path: `${output}/login-failure.png`, fullPage: true });
  process.stderr.write(`login failed at ${page.url()}\n${failures.join("\n")}\n${(await page.locator("body").innerText()).slice(0, 500)}\n`);
  throw error;
}

// A source added through the form: the browser seals the password, the agent
// opens it and connects. The source has no audit directory, so it adds no events.
try {
  await page.goto(`${credentials.api}/infrastructure`);
  await page.getByRole("button", { name: "Добавить источник" }).click();
  const form = page.getByRole("form", { name: "Новый источник" });
  await form.getByLabel("Имя", { exact: true }).fill("ui-postgres");
  await form.getByLabel("Хост", { exact: true }).fill("source-postgres");
  await form.getByLabel("База данных", { exact: true }).fill("crm");
  await form.getByLabel("Пользователь", { exact: true }).fill("dg_scanner");
  await form.getByLabel("Пароль", { exact: true }).fill(sourcePassword);
  // A select's accessible name includes its chosen option, so the match is by prefix.
  await form.getByRole("combobox", { name: /^TLS/ }).selectOption("disable");
  await form.getByRole("button", { name: "Сохранить" }).click();
  await page.getByRole("row", { name: /ui-postgres/ }).getByText("Подключено").waitFor({ timeout: 90_000 });
  await page.screenshot({ path: `${output}/source-added.png`, fullPage: true });
} catch (error) {
  await page.screenshot({ path: `${output}/source-failure.png`, fullPage: true });
  throw error;
}

for (const scheme of ["light", "dark"]) {
  await page.emulateMedia({ colorScheme: scheme });
  for (const item of pages) {
    await page.goto(credentials.api + item.path);
    await page.getByRole("heading", { name: item.heading, exact: true }).waitFor();
    await page.waitForLoadState("networkidle");
    const text = await page.locator("main").innerText();
    for (const expected of item.expect) {
      if (!text.includes(expected)) failures.push(`${item.path}: no "${expected}"`);
    }
    if (text.includes("dgcanary")) failures.push(`${item.path}: a source value is on screen`);
    if (text.includes(sourcePassword)) failures.push(`${item.path}: a database password is on screen`);
    if (text.includes("undefined") || text.includes("NaN")) failures.push(`${item.path}: broken value on screen`);
    await page.screenshot({ path: `${output}/${scheme}${item.path.replace("/", "-")}.png`, fullPage: true });
  }
}

// The chain from a source to the events of one column, by links alone (ADR-0010).
// Links navigate inside the page, so the load state stays idle from the first
// load: each expected text is waited for instead.
async function expectOnPage(step, expected) {
  for (const item of expected) {
    try {
      await page.locator("main").getByText(item, { exact: false }).first().waitFor({ timeout: 30_000 });
    } catch {
      failures.push(`${step}: no "${item}"`);
    }
  }
  const text = await page.locator("main").innerText();
  if (text.includes("undefined") || text.includes("NaN")) failures.push(`${step}: broken value on screen`);
  if (text.includes("dgcanary")) failures.push(`${step}: a source value is on screen`);
}

await page.emulateMedia({ colorScheme: "light" });
try {
  await page.goto(`${credentials.api}/infrastructure`);
  const sources = page.locator("section").filter({ has: page.getByRole("heading", { name: "Источники", exact: true }) });
  const source = sources.getByRole("row").filter({ hasText: "PostgreSQL" }).filter({ hasText: "Подключено" }).filter({ hasNotText: "ui-postgres" }).first().getByRole("link").first();
  const sourceName = await source.innerText();
  await source.click();
  await page.getByRole("heading", { name: sourceName, exact: true }).waitFor();
  await expectOnPage("source", ["Подключение", "Агент", "Базы, схемы и таблицы", "Аудит за сутки"]);
  await page.screenshot({ path: `${output}/object-source.png`, fullPage: true });

  await page.locator("main dl").getByRole("link").first().click();
  await page.getByRole("heading", { name: "Агент", exact: true }).waitFor();
  await expectOnPage("agent", ["Активен", "Источники агента", sourceName]);
  await page.goBack();

  await page.getByRole("link", { name: "dg_users", exact: true }).click();
  await page.getByRole("heading", { name: "dg_users", exact: true }).waitFor();
  await expectOnPage("table", ["Колонки", "email", "Email", sourceName]);
  await page.screenshot({ path: `${output}/object-table.png`, fullPage: true });

  await page.getByRole("link", { name: "email", exact: true }).click();
  await page.getByRole("heading", { name: "email", exact: true }).waitFor();
  await expectOnPage("column", ["Классификация", "Найдено", "Email", "Последние обращения", "dg_app"]);
  await page.screenshot({ path: `${output}/object-column.png`, fullPage: true });

  await page.getByRole("link", { name: "Все обращения к колонке" }).click();
  await page.getByRole("heading", { name: "Обращения", exact: true }).waitFor();
  await expectOnPage("events of the column", ["Колонка:", "dg_app"]);
  if (!new URL(page.url()).searchParams.get("columnId")) failures.push("events of the column: the filter is not in the address");
  await page.screenshot({ path: `${output}/object-events.png`, fullPage: true });
} catch (error) {
  await page.screenshot({ path: `${output}/object-failure.png`, fullPage: true });
  throw error;
}

await page.setViewportSize({ width: 380, height: 800 });
await page.goto(`${credentials.api}/infrastructure`);
await page.getByRole("heading", { name: "Инфраструктура", exact: true }).waitFor();
await page.waitForLoadState("networkidle");
const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
if (overflow > 0) failures.push(`phone width: page scrolls sideways by ${overflow}px`);
await page.screenshot({ path: `${output}/phone-infrastructure.png`, fullPage: true });

await browser.close();
if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}
process.stdout.write(`checked ${pages.length} pages in 2 themes, the object chain and phone width\n`);
