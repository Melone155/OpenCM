export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n) || n <= 0) return '–';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtRelative(v: string | null | undefined): string {
  if (!v) return 'nie';
  const s = Math.round((Date.now() - new Date(v).getTime()) / 1000);
  if (s < 60) return 'gerade eben';
  if (s < 3600) return `vor ${Math.floor(s / 60)} Min.`;
  if (s < 86400) return `vor ${Math.floor(s / 3600)} Std.`;
  return `vor ${Math.floor(s / 86400)} Tagen`;
}

export const OS_LABEL: Record<string, string> = { windows: 'Windows', linux: 'Linux', macos: 'macOS' };

export function val(v: unknown): string {
  if (v === null || v === undefined || v === '') return '–';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
