/**
 * Assets without an agent (M7): monitors, printers, phones, network gear, spare devices …
 * Field definitions, value normalisation and the CSV import mapping.
 */
import { isIP } from 'node:net';

export const ASSET_TYPES = ['computer', 'notebook', 'server', 'monitor', 'printer', 'phone', 'tablet', 'network', 'peripheral', 'other'] as const;
export const ASSET_STATUSES = ['in_stock', 'in_use', 'repair', 'retired'] as const;
export type AssetType = (typeof ASSET_TYPES)[number];
export type AssetStatus = (typeof ASSET_STATUSES)[number];

export const TYPE_LABELS: Record<AssetType, string> = {
  computer: 'Computer',
  notebook: 'Notebook',
  server: 'Server',
  monitor: 'Monitor',
  printer: 'Drucker',
  phone: 'Telefon',
  tablet: 'Tablet',
  network: 'Netzwerkgerät',
  peripheral: 'Peripherie',
  other: 'Sonstiges',
};
export const STATUS_LABELS: Record<AssetStatus, string> = { in_stock: 'Lager', in_use: 'In Benutzung', repair: 'Reparatur', retired: 'Ausgemustert' };

const lc = (s: string) => s.trim().toLowerCase();

/** Accepts the key, the German label and a few common synonyms. */
export function parseAssetType(v: string): AssetType | null {
  const s = lc(v);
  if (!s) return null;
  const syn: Record<string, AssetType> = { pc: 'computer', desktop: 'computer', laptop: 'notebook', bildschirm: 'monitor', display: 'monitor', handy: 'phone', smartphone: 'phone', telefon: 'phone', switch: 'network', router: 'network', 'access point': 'network', firewall: 'network', scanner: 'peripheral', dockingstation: 'peripheral' };
  if (syn[s]) return syn[s]!;
  for (const t of ASSET_TYPES) if (t === s || lc(TYPE_LABELS[t]) === s) return t;
  return null;
}

export function parseAssetStatus(v: string): AssetStatus | null {
  const s = lc(v).replace(/\s+/g, '_');
  if (!s) return null;
  const syn: Record<string, AssetStatus> = { lager: 'in_stock', aktiv: 'in_use', in_benutzung: 'in_use', defekt: 'repair', reparatur: 'repair', ausgemustert: 'retired', entsorgt: 'retired' };
  if (syn[s]) return syn[s]!;
  return (ASSET_STATUSES as readonly string[]).includes(s) ? (s as AssetStatus) : null;
}

/** "00-11-22-aa-bb-cc" / "001122AABBCC" → "00:11:22:AA:BB:CC"; null if invalid. */
export function normalizeMac(v: string): string | null {
  const hex = v.replace(/[^0-9a-f]/gi, '');
  if (hex.length !== 12 || !/^[0-9a-f:\-. ]+$/i.test(v.trim())) return null;
  return hex.toUpperCase().match(/.{2}/g)!.join(':');
}

export const validIp = (v: string) => isIP(v.trim()) !== 0;

/** YYYY-MM-DD or DD.MM.YYYY → YYYY-MM-DD; null if invalid. */
export function parseDay(v: string): string | null {
  const s = v.trim();
  let y: number, m: number, d: number;
  let mm = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (mm) [y, m, d] = [Number(mm[1]), Number(mm[2]), Number(mm[3])];
  else if ((mm = s.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/))) [d, m, y] = [Number(mm[1]), Number(mm[2]), Number(mm[3])];
  else return null;
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  return dt.toISOString().slice(0, 10);
}

/** "1.234,56" / "1234.56" / "1234,5 €" → 1234.56; null if invalid. */
export function parseMoney(v: string): number | null {
  let s = v.replace(/[€\s]|EUR/gi, '');
  if (!s) return null;
  if (/,\d{1,2}$/.test(s)) s = s.replace(/\./g, '').replace(',', '.');
  else s = s.replace(/,/g, '');
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? Math.round(n * 100) / 100 : null;
}

/** CSV columns: key → accepted header names (lower case). */
export const CSV_COLUMNS = {
  name: ['name', 'bezeichnung'],
  type: ['type', 'typ', 'art'],
  status: ['status'],
  manufacturer: ['manufacturer', 'hersteller'],
  model: ['model', 'modell'],
  serialNumber: ['serialnumber', 'serial', 'seriennummer', 'sn'],
  inventoryNumber: ['inventorynumber', 'inventarnummer', 'inventar-nr', 'inventar-nr.', 'asset tag', 'assettag'],
  location: ['location', 'standort', 'raum'],
  assignedTo: ['assignedto', 'zugeordnet', 'benutzer', 'mitarbeiter', 'person'],
  ipAddress: ['ipaddress', 'ip', 'ip-adresse'],
  macAddress: ['macaddress', 'mac', 'mac-adresse'],
  purchaseDate: ['purchasedate', 'kaufdatum', 'angeschafft'],
  warrantyUntil: ['warrantyuntil', 'garantie bis', 'garantie', 'gewährleistung bis'],
  cost: ['cost', 'kosten', 'preis'],
  notes: ['notes', 'notizen', 'bemerkung'],
  deviceHostname: ['devicehostname', 'gerät', 'geraet', 'hostname', 'verwaltetes gerät'],
} as const;
export type CsvKey = keyof typeof CSV_COLUMNS;
export const CSV_EXPORT_ORDER: CsvKey[] = Object.keys(CSV_COLUMNS) as CsvKey[];

export function mapCsvHeader(header: string[]): { index: Partial<Record<CsvKey, number>>; unknown: string[] } {
  const index: Partial<Record<CsvKey, number>> = {};
  const unknown: string[] = [];
  header.forEach((h, i) => {
    const n = lc(h).replace(/\s+/g, ' ');
    const key = (Object.keys(CSV_COLUMNS) as CsvKey[]).find((k) => (CSV_COLUMNS[k] as readonly string[]).includes(n));
    if (key && index[key] === undefined) index[key] = i;
    else if (n) unknown.push(h);
  });
  return { index, unknown };
}

/** Undo the formula-injection guard of our own CSV export ('=… → =…). */
export const unguard = (v: string) => (/^'[=+\-@]/.test(v) ? v.slice(1) : v);
