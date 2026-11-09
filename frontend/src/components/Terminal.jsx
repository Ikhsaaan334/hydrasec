import { useEffect, useRef } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

// Pembungkus xterm.js: menerima chunk teks mentah (termasuk \r progress-bar)
// dan menulisnya apa adanya — pengalaman CLI asli di browser.
export default function TerminalView({ chunks, status }) {
  const hostRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const writtenRef = useRef(0);

  useEffect(() => {
    const term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      disableStdin: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, "Cascadia Code", Consolas, monospace',
      theme: {
        background: '#060a08',
        foreground: '#c9d8d1',
        cursor: '#4ade80',
        selectionBackground: 'rgba(74,222,128,.25)',
        black: '#0a0e0c',
        green: '#4ade80',
        white: '#e9f2ee',
      },
      scrollback: 8000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const onResize = () => fit.fit();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      term.dispose();
      termRef.current = null;
    };
  }, []);

  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    // tulis hanya chunk yang belum pernah ditulis (replay + live stream)
    const written = writtenRef.current;
    if (chunks.length > written) {
      for (const c of chunks.slice(written)) term.write(c);
      writtenRef.current = chunks.length;
    }
  }, [chunks]);

  return (
    <div className="terminal-box" ref={hostRef} aria-label="Terminal streaming" role="log" />
  );
}
