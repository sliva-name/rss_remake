import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CalendarClock } from "lucide-react";
import { type SubmitEvent, useState } from "react";

import { api, type Schemas } from "../api";
import { ago, capitalized, dateTime, schedulePeriod } from "../labels";
import { useCan } from "../permissions";
import { queries } from "../queries";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Field, Input, Select } from "./ui/form";
import { Panel } from "./ui/panel";
import { useNotify } from "./ui/toast";

const periods = [6, 12, 24, 168];

// A moment as a datetime-local field holds it: local time to the minute.
export function localMinute(moment: Date): string {
  const shifted = new Date(moment.getTime() - moment.getTimezoneOffset() * 60_000);
  return shifted.toISOString().slice(0, 16);
}

// The coming 02:00 by the browser's clock: at night a scan bothers the
// database least.
export function nextNight(now = new Date()): Date {
  const night = new Date(now);
  night.setHours(2, 0, 0, 0);
  if (night <= now) night.setDate(night.getDate() + 1);
  return night;
}

function ScheduleDialog({ source, open, onOpenChange }: { source: Schemas["Source"]; open: boolean; onOpenChange: (open: boolean) => void }) {
  const client = useQueryClient();
  const notify = useNotify();
  const current = source.scanSchedule;
  const [everyHours, setEveryHours] = useState(String(current?.everyHours ?? 24));
  const [firstRun, setFirstRun] = useState(localMinute(current ? new Date(current.nextRunAt) : nextNight()));
  const options = [...new Set([...periods, Number(everyHours)])]
    .sort((a, b) => a - b)
    .map((hours) => ({ value: String(hours), label: capitalized(schedulePeriod(hours)) }));
  const save = useMutation({
    // A datetime-local value without an offset is read as local time.
    mutationFn: () => api.setScanSchedule(source.id, { everyHours: Number(everyHours), firstRunAt: new Date(firstRun).toISOString() }),
    onSuccess: async (schedule) => {
      notify({ tone: "ok", title: "Расписание сохранено", description: `Следующий скан ${source.key} — ${dateTime(schedule.nextRunAt)}.` });
      onOpenChange(false);
      await client.invalidateQueries({ queryKey: queries.sources().queryKey });
    },
  });
  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    save.mutate();
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={`Расписание сканирования ${source.key}`} description="Центр сам ставит скан в очередь, агент берёт его со следующим сигналом.">
      <form onSubmit={submit} aria-label="Расписание сканирования" className="flex flex-col gap-4">
        <Field label="Как часто">
          <Select aria-label="Как часто" value={everyHours} onValueChange={setEveryHours} options={options} />
        </Field>
        <Field label="Первый запуск" hint="По часам вашего компьютера. Если время уже прошло, скан начнётся в следующий раз по тому же расписанию.">
          <Input type="datetime-local" required value={firstRun} onChange={(event) => setFirstRun(event.target.value)} />
        </Field>
        <p className="text-xs text-fg-2">Пока предыдущий скан ждёт агента или идёт, новый не ставится. Если центр был выключен, пропущенные запуски заменяет один скан.</p>
        {save.error && <p role="alert" className="text-sm text-bad">{save.error.message}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Отмена</Button>
          <Button type="submit" variant="primary" disabled={save.isPending || !firstRun}>Сохранить</Button>
        </div>
      </form>
    </Dialog>
  );
}

// When the center scans the source by itself, and the controls to change it.
export function ScanSchedulePanel({ source }: { source: Schemas["Source"] }) {
  const can = useCan();
  const client = useQueryClient();
  const notify = useNotify();
  const [open, setOpen] = useState(false);
  const schedule = source.scanSchedule;
  const stop = useMutation({
    mutationFn: () => api.deleteScanSchedule(source.id),
    onSuccess: async () => {
      notify({ tone: "ok", title: "Расписание отключено", description: "Сканы этого источника теперь запускаются вручную." });
      await client.invalidateQueries({ queryKey: queries.sources().queryKey });
    },
    onError: (error) => notify({ tone: "bad", title: "Расписание не отключено", description: error.message }),
  });
  return (
    <Panel
      title="Расписание"
      actions={
        <>
          {can("setScanSchedule") && <Button size="sm" onClick={() => setOpen(true)}><CalendarClock /> {schedule ? "Изменить" : "Настроить"}</Button>}
          {can("deleteScanSchedule") && schedule && <Button size="sm" disabled={stop.isPending} onClick={() => stop.mutate()}>Отключить</Button>}
        </>
      }
    >
      {schedule ? (
        <p className="text-sm text-fg">
          Сканировать {schedulePeriod(schedule.everyHours)}. Следующий скан — {dateTime(schedule.nextRunAt)}
          <span className="text-fg-2"> ({ago(schedule.nextRunAt)})</span>.
        </p>
      ) : (
        <p className="text-sm text-fg-2">Сканы этого источника запускаются только вручную.</p>
      )}
      {open && <ScheduleDialog source={source} open={open} onOpenChange={setOpen} />}
    </Panel>
  );
}
