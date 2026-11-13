export const INTERPRETERS = {
  powershell: { label: 'PowerShell', os: ['windows'], monaco: 'powershell' },
  cmd: { label: 'CMD (Batch)', os: ['windows'], monaco: 'bat' },
  bash: { label: 'Bash', os: ['linux', 'macos'], monaco: 'shell' },
  zsh: { label: 'zsh', os: ['linux', 'macos'], monaco: 'shell' },
  python: { label: 'Python 3', os: ['windows', 'linux', 'macos'], monaco: 'python' },
} as const;

export type Interpreter = keyof typeof INTERPRETERS;
export const INTERPRETER_NAMES = Object.keys(INTERPRETERS) as Interpreter[];

export function supportsOs(interpreter: string, os: string): boolean {
  const i = INTERPRETERS[interpreter as Interpreter];
  return !!i && (i.os as readonly string[]).includes(os);
}
