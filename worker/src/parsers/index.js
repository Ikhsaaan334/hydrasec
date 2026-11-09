import { parseNmap } from './nmap.js';
import { parseNuclei } from './nuclei.js';
import { parseXsstrike } from './xsstrike.js';
import { parseXray } from './xray.js';
import { parseSqlmap } from './sqlmap.js';
import { parseFfuf } from './ffuf.js';

const PARSERS = {
  nmap: parseNmap,
  nuclei: parseNuclei,
  xsstrike: parseXsstrike,
  xray: parseXray,
  sqlmap: parseSqlmap,
  ffuf: parseFfuf,
};

// Titik masuk parser: output mentah tool → Unified Vulnerability Schema.
// Selalu mengembalikan minimal satu temuan ringkasan agar scan "completed"
// tetap bermakna di UI.
export function parseResults(tool, ctx) {
  const fn = PARSERS[tool];
  if (!fn) return [];
  try {
    return fn(ctx) ?? [];
  } catch (err) {
    return [
      {
        title: 'Parser failed to process ' + tool + ' output',
        severity: 'info',
        url: ctx?.target ?? null,
        description: 'Raw output remains available (console.log on the worker server).',
        metadata: { parserError: err.message },
      },
    ];
  }
}
