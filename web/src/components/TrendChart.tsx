import { useState, type MouseEvent } from 'react';

export interface TrendPoint {
  day: string;
  value: number;
}

const W = 320;
const H = 110;
const PAD = { l: 34, r: 12, t: 12, b: 20 };
const fmtDay = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', timeZone: 'UTC' });
const fmtNum = (n: number) => n.toLocaleString('de-DE', { maximumFractionDigits: 1 });

/**
 * Single-series trend line: the title names the series (no legend), 2px line,
 * recessive axis, last value labelled directly, crosshair + tooltip on hover,
 * and a hidden table as text alternative.
 */
export function TrendChart({ title, points, unit = '' }: { title: string; points: TrendPoint[]; unit?: string }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length < 2) {
    return (
      <figure className="trend">
        <figcaption>{title}</figcaption>
        <p className="muted small">Verlauf erscheint ab dem zweiten Tag mit Messwerten.</p>
      </figure>
    );
  }
  const values = points.map((p) => p.value);
  const max = Math.max(...values, 1);
  const min = Math.min(0, ...values);
  const x = (i: number) => PAD.l + (i / (points.length - 1)) * (W - PAD.l - PAD.r);
  const y = (v: number) => PAD.t + (1 - (v - min) / (max - min || 1)) * (H - PAD.t - PAD.b);
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(' ');
  const last = points[points.length - 1]!;

  function onMove(e: MouseEvent<SVGRectElement>) {
    const box = e.currentTarget.getBoundingClientRect();
    const rel = ((e.clientX - box.left) / box.width) * W;
    const i = Math.round(((rel - PAD.l) / (W - PAD.l - PAD.r)) * (points.length - 1));
    setHover(Math.max(0, Math.min(points.length - 1, i)));
  }
  const h = hover !== null ? points[hover]! : null;

  return (
    <figure className="trend">
      <figcaption>
        {title} <span className="trend-value">{fmtNum(last.value)}{unit}</span>
      </figcaption>
      <div className="trend-plot">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${title}: zuletzt ${fmtNum(last.value)}${unit}`}>
          <line className="trend-axis" x1={PAD.l} x2={W - PAD.r} y1={y(min)} y2={y(min)} />
          <line className="trend-grid" x1={PAD.l} x2={W - PAD.r} y1={y(max)} y2={y(max)} />
          <text className="trend-tick" x={PAD.l - 6} y={y(max) + 4} textAnchor="end">
            {fmtNum(max)}
          </text>
          <text className="trend-tick" x={PAD.l - 6} y={y(min) + 4} textAnchor="end">
            {fmtNum(min)}
          </text>
          <text className="trend-tick" x={PAD.l} y={H - 4}>
            {fmtDay(points[0]!.day)}
          </text>
          <text className="trend-tick" x={W - PAD.r} y={H - 4} textAnchor="end">
            {fmtDay(last.day)}
          </text>
          <path className="trend-line" d={d} />
          <circle className="trend-dot" cx={x(points.length - 1)} cy={y(last.value)} r={4} />
          {h && hover !== null && (
            <>
              <line className="trend-cross" x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={y(min)} />
              <circle className="trend-dot" cx={x(hover)} cy={y(h.value)} r={4} />
            </>
          )}
          <rect x={PAD.l} y={0} width={W - PAD.l - PAD.r} height={H} fill="transparent" onMouseMove={onMove} onMouseLeave={() => setHover(null)} />
        </svg>
        {h && hover !== null && (
          <div className="trend-tip" style={{ left: `${(x(hover) / W) * 100}%` }}>
            <strong>{fmtNum(h.value)}{unit}</strong>
            <span>{fmtDay(h.day)}</span>
          </div>
        )}
      </div>
      <table className="sr-only">
        <caption>{title}</caption>
        <tbody>
          {points.map((p) => (
            <tr key={p.day}>
              <th>{p.day}</th>
              <td>{p.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
