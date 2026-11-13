import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';

interface Line {
  id: number;
  stream: string;
  data: string;
}

/** Live task output: polls /tasks/{id}/output with a cursor until the task is done. */
export function TaskOutput({ taskId, onStatus }: { taskId: string; onStatus?: (status: string) => void }) {
  const [lines, setLines] = useState<Line[]>([]);
  const [status, setStatus] = useState<string>('…');
  const [error, setError] = useState<string | null>(null);
  const box = useRef<HTMLPreElement>(null);
  const follow = useRef(true);
  const onStatusRef = useRef(onStatus);
  onStatusRef.current = onStatus;

  useEffect(() => {
    let cursor = 0;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    setLines([]);
    const poll = async () => {
      const { data, error: err } = await api.GET('/tasks/{id}/output', { params: { path: { id: taskId }, query: { after: cursor, limit: 2000 } } });
      if (stopped) return;
      if (err || !data) {
        setError('Ausgabe konnte nicht geladen werden');
        timer = setTimeout(poll, 3000);
        return;
      }
      setError(null);
      if (data.items.length) {
        cursor = data.nextCursor;
        setLines((prev) => [...prev, ...data.items]);
      }
      setStatus(data.status);
      onStatusRef.current?.(data.status);
      if (!data.done) timer = setTimeout(poll, data.items.length >= 2000 ? 0 : 1000);
    };
    void poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [taskId]);

  useEffect(() => {
    if (follow.current && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines]);

  return (
    <div>
      <div className="muted">
        Status: <strong>{status}</strong> {['pending', 'dispatched', 'running'].includes(status) && <span className="spinner" aria-hidden />}
      </div>
      {error && <div className="error">{error}</div>}
      <pre
        ref={box}
        className="terminal"
        onScroll={(e) => {
          const el = e.currentTarget;
          follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
      >
        {lines.length === 0 && <span className="muted">Noch keine Ausgabe …</span>}
        {lines.map((l) => (
          <span key={l.id} className={`out-${l.stream}`}>
            {l.data}
          </span>
        ))}
      </pre>
    </div>
  );
}
