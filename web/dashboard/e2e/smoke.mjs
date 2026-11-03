// Walks the dashboard in a real browser against a running platform. The Go
// end-to-end test starts it in the browser-check container with an account it created.
import { chromium } from "playwright";

const credentials = { api: process.env.DG_UI_URL, user: process.env.DG_UI_USER, password: process.env.DG_UI_PASSWORD };
if (!credentials.api || !credentials.user || !credentials.password) {
  throw new Error("DG_UI_URL, DG_UI_USER and DG_UI_PASSWORD are required");
}
const output = process.argv[2];

const pages = [
  { path: "/overview", heading: "Обзор", expect: ["Покрытие за сутки", "Изменения в инвентаре", "Наблюдается"] },
  { path: "/catalog", heading: "Каталог данных", expect: ["ИНН", "Платёжная карта", "Уверенность"] },
  { path: "/access", heading: "Обращения", expect: ["Доказательство", "Запрос выполнен", "Упомянуто в запросе", "dg_app"] },
  { path: "/identities", heading: "Пользователи", expect: ["employee-123", "Подтверждено приложением", "Не идентифицирован"] },
  { path: "/compliance", heading: "Отчёты", expect: ["Инвентарь по категориям", "Доступ по категориям"] },
  { path: "/infrastructure", heading: "Инфраструктура", expect: ["Покрытие аудита", "Возможности источников", "Нет в СУБД", "Сканировать"] },
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
    if (text.includes("undefined") || text.includes("NaN")) failures.push(`${item.path}: broken value on screen`);
    await page.screenshot({ path: `${output}/${scheme}${item.path.replace("/", "-")}.png`, fullPage: true });
  }
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
process.stdout.write(`checked ${pages.length} pages in 2 themes and phone width\n`);
