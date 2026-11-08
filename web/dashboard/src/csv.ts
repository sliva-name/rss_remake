import { saveFile } from "./api";

// A cell a spreadsheet will not read as a formula: names come from databases
// the platform does not control. The server's export applies the same rule.
export function cell(value: string | number): string {
  const text = String(value);
  const guarded = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n\r]/.test(guarded) ? `"${guarded.replaceAll('"', '""')}"` : guarded;
}

export function toCsv(header: string[], rows: (string | number)[][]): string {
  return [header, ...rows].map((row) => row.map(cell).join(",")).join("\r\n");
}

const byteOrderMark = String.fromCharCode(0xfeff);

// Saves a report the page already holds. The byte order mark makes
// spreadsheet programs read Cyrillic as UTF-8.
export function downloadCsv(filename: string, header: string[], rows: (string | number)[][]) {
  saveFile(new Blob([byteOrderMark, toCsv(header, rows)], { type: "text/csv;charset=utf-8" }), filename);
}

export function stamp(date = new Date()): string {
  return date.toISOString().slice(0, 16).replace(/[:T]/g, "-");
}
