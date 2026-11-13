import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
import { bracketMatching, defaultHighlightStyle, indentOnInput, StreamLanguage, syntaxHighlighting } from '@codemirror/language';
import { powerShell } from '@codemirror/legacy-modes/mode/powershell';
import { python } from '@codemirror/legacy-modes/mode/python';
import { shell } from '@codemirror/legacy-modes/mode/shell';
import { highlightSelectionMatches, search, searchKeymap } from '@codemirror/search';
import { Compartment, EditorState } from '@codemirror/state';
import { drawSelection, EditorView, highlightActiveLine, keymap, lineNumbers } from '@codemirror/view';
import { useEffect, useRef } from 'react';

/**
 * Script editor (CodeMirror 6). Chosen over Monaco: no web workers (fits the strict CSP),
 * ~10x smaller, and no vendored DOMPurify (Monaco 0.57 ships a version with critical CVEs).
 */
const LANGUAGES: Record<string, () => StreamLanguage<unknown>> = {
  powershell: () => StreamLanguage.define(powerShell) as StreamLanguage<unknown>,
  bash: () => StreamLanguage.define(shell) as StreamLanguage<unknown>,
  zsh: () => StreamLanguage.define(shell) as StreamLanguage<unknown>,
  python: () => StreamLanguage.define(python) as StreamLanguage<unknown>,
};

const theme = EditorView.theme({
  '&': { fontSize: '13px', border: '1px solid var(--border)', borderRadius: '6px', background: 'var(--panel)', color: 'var(--text)' },
  '.cm-content': { fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace', minHeight: '320px', caretColor: 'var(--text)' },
  '.cm-gutters': { background: 'var(--bg)', color: 'var(--muted)', border: 'none' },
  '.cm-activeLine': { background: 'color-mix(in srgb, var(--accent) 8%, transparent)' },
  '&.cm-focused': { outline: '2px solid color-mix(in srgb, var(--accent) 40%, transparent)' },
  '.cm-scroller': { maxHeight: '70vh', overflow: 'auto' },
});

interface Props {
  value: string;
  onChange?: (v: string) => void;
  interpreter: string;
  readOnly?: boolean;
}

export function CodeEditor({ value, onChange, interpreter, readOnly = false }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const lang = useRef(new Compartment());
  const ro = useRef(new Compartment());
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    const v = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: value,
        extensions: [
          lineNumbers(),
          history(),
          drawSelection(),
          highlightActiveLine(),
          indentOnInput(),
          bracketMatching(),
          search(),
          highlightSelectionMatches(),
          syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
          keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, indentWithTab]),
          theme,
          lang.current.of(LANGUAGES[interpreter]?.() ?? []),
          ro.current.of([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) onChangeRef.current?.(u.state.doc.toString());
          }),
        ],
      }),
    });
    view.current = v;
    return () => v.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // external value changes (e.g. switching versions)
  useEffect(() => {
    const v = view.current;
    if (v && v.state.doc.toString() !== value) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } });
  }, [value]);

  useEffect(() => {
    view.current?.dispatch({ effects: lang.current.reconfigure(LANGUAGES[interpreter]?.() ?? []) });
  }, [interpreter]);

  useEffect(() => {
    view.current?.dispatch({ effects: ro.current.reconfigure([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]) });
  }, [readOnly]);

  return <div ref={host} className="code-editor" />;
}
