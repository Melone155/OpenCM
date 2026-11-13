/** CPE 2.3 formatted string: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other */
export interface Cpe23 {
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  targetSw: string;
}

/** Splits on unescaped ':' and removes CPE escaping (\+ → +, \: → :). */
function splitCpe(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '\\' && i + 1 < s.length) {
      cur += s[++i];
    } else if (ch === ':') {
      out.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

export function parseCpe23(s: string): Cpe23 | null {
  const f = splitCpe(s);
  if (f.length < 13 || f[0] !== 'cpe' || f[1] !== '2.3') return null;
  return { part: f[2]!, vendor: f[3]!, product: f[4]!, version: f[5]!, update: f[6]!, targetSw: f[10]! };
}
