/**
 * Minimal RFC 4180 CSV parser (quoted fields, "" escapes, CRLF/LF, BOM).
 * The delimiter is detected from the header line: German Excel writes ";", most other tools ",".
 */
export function detectDelimiter(text: string): ';' | ',' | '\t' {
  const firstLine = text.replace(/^﻿/, '').split(/\r?\n/, 1)[0] ?? '';
  const count = (c: string) => firstLine.split(c).length - 1;
  const counts: [';' | ',' | '\t', number][] = [
    [';', count(';')],
    [',', count(',')],
    ['\t', count('\t')],
  ];
  counts.sort((a, b) => b[1] - a[1]);
  return counts[0]![1] > 0 ? counts[0]![0] : ';';
}

export function parseCsv(text: string, delimiter = detectDelimiter(text)): string[][] {
  const s = text.replace(/^﻿/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
      continue;
    }
    if (c === '"' && field === '') quoted = true;
    else if (c === delimiter) {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i++;
      row.push(field);
      field = '';
      if (row.some((f) => f !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((f) => f !== '')) rows.push(row);
  return rows;
}
