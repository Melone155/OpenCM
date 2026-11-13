import { CronExpressionParser } from 'cron-parser';
import type { MaintenanceWindow } from '../db/schema.ts';

export function isValidTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** Throws a readable error for invalid expressions. Standard 5-field cron. */
export function assertCron(expr: string, tz: string): void {
  if (expr.trim().split(/\s+/).length !== 5) throw new Error('cron must have 5 fields (minute hour day month weekday)');
  CronExpressionParser.parse(expr, { tz });
}

export function nextCronRun(expr: string, tz: string, after: Date): Date {
  return CronExpressionParser.parse(expr, { currentDate: after, tz }).next().toDate();
}

const WEEKDAYS: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

/** Local weekday (0 = Sunday) and minute of day in the given time zone. */
export function localTime(now: Date, tz: string): { day: number; minute: number } {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(now);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '0';
  return { day: WEEKDAYS[get('weekday')] ?? 0, minute: Number(get('hour')) * 60 + Number(get('minute')) };
}

const toMinutes = (hhmm: string) => {
  const [h, m] = hhmm.split(':').map(Number);
  return (h ?? 0) * 60 + (m ?? 0);
};

/**
 * True if `now` lies within the window. `days` are the days on which the window
 * starts; a window with end <= start crosses midnight into the next day.
 */
export function inMaintenanceWindow(now: Date, window: MaintenanceWindow | null, tz: string): boolean {
  if (!window) return true;
  const { day, minute } = localTime(now, tz);
  const start = toMinutes(window.start);
  const end = toMinutes(window.end);
  if (start < end) return window.days.includes(day) && minute >= start && minute < end;
  const yesterday = (day + 6) % 7;
  return (window.days.includes(day) && minute >= start) || (window.days.includes(yesterday) && minute < end);
}
