import type { LogFormat } from '../../types/events';
import type { FormatCandidate, FormatDetection } from '../../types/ingestion';
import { detectDelimiter, splitCsvRecord } from './parsers/csv';
import { looksBinary } from './validation/fileChecks';

const SYSLOG_LINE =
  /^(?:<\d{1,3}>(?:1 )?)?(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+\S+\s+[A-Za-z0-9_./@-]{1,64}(?:\[\d+\])?:\s/;
const CLF_LINE =
  /^(?:\S+:\d+ )?\S+ \S+ \S+ \[[^\]]{1,64}\] "(?:[^"\\]|\\.)*" (?:\d{3}|-) (?:\d+|-)/;
const COMBINED_EXTRA = /"(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*"\s*$/;

function jsonObjectLine(line: string): boolean {
  const t = line.trim();
  if (!t.startsWith('{')) return false;
  try {
    const v: unknown = JSON.parse(t);
    return typeof v === 'object' && v !== null && !Array.isArray(v);
  } catch {
    return false;
  }
}

/** Score how CSV-like the sample is: consistent column counts and a header-like first row. */
function csvScore(lines: string[]): number {
  if (lines.length < 2) return 0;
  const first = lines[0]!;
  if (first.trim().startsWith('{') || SYSLOG_LINE.test(first) || CLF_LINE.test(first)) return 0;
  const delimiter = detectDelimiter(first);
  const header = splitCsvRecord(first, delimiter);
  if (!header || header.length < 2) return 0;
  const headerLike = header.every((h) => h.trim() !== '' && !/^-?\d+(?:\.\d+)?$/.test(h.trim()));
  const rows = lines.slice(1);
  const consistent = rows.filter((l) => {
    const cells = splitCsvRecord(l, delimiter);
    return cells !== null && cells.length === header.length;
  }).length;
  const fraction = consistent / rows.length;
  return headerLike ? fraction : fraction * 0.5;
}

const PRIORITY: LogFormat[] = ['jsonl', 'linux-auth', 'apache', 'nginx', 'csv'];

/**
 * Detect the likely format from a sample of non-blank lines. Detection is a
 * heuristic: the analyst can always override it. Apache and Nginx share the
 * same default format, so hints (file name, extra trailing fields) decide the
 * label and the result is marked ambiguous when no hint is present.
 */
export function detectFormat(sampleLines: string[], fileName = ''): FormatDetection {
  const lines = sampleLines.filter((l) => l.trim() !== '').slice(0, 200);
  const joined = lines.join('\n');
  if (looksBinary(joined)) {
    return {
      format: null,
      confidence: 0,
      ambiguous: false,
      candidates: [],
      reason: 'The content looks binary or compressed.',
      unsupportedReason:
        'The content looks binary or compressed. LogLens analyzes plain-text logs only.',
    };
  }
  if (lines.length === 0) {
    return {
      format: null,
      confidence: 0,
      ambiguous: false,
      candidates: [],
      reason: 'The sample contains no non-blank lines.',
    };
  }
  const frac = (test: (l: string) => boolean): number => lines.filter(test).length / lines.length;
  const clf = frac((l) => CLF_LINE.test(l));
  const scores: Record<LogFormat, number> = {
    jsonl: frac(jsonObjectLine),
    'linux-auth': frac((l) => SYSLOG_LINE.test(l)),
    apache: clf,
    nginx: clf,
    csv: csvScore(lines),
  };

  let webLabel: 'apache' | 'nginx' = 'apache';
  let webHint = false;
  if (/nginx/i.test(fileName)) {
    webLabel = 'nginx';
    webHint = true;
  } else if (/apache|httpd/i.test(fileName)) {
    webHint = true;
  } else if (clf > 0 && frac((l) => CLF_LINE.test(l) && COMBINED_EXTRA.test(l)) / clf > 0.5) {
    webLabel = 'nginx';
    webHint = true;
  }
  scores[webLabel === 'apache' ? 'nginx' : 'apache'] -= 0.001;

  const candidates: FormatCandidate[] = PRIORITY.map((format) => ({
    format,
    score: Math.max(0, scores[format]),
  }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score || PRIORITY.indexOf(a.format) - PRIORITY.indexOf(b.format));

  const best = candidates[0];
  if (!best || best.score < 0.2) {
    return {
      format: null,
      confidence: best?.score ?? 0,
      ambiguous: true,
      candidates,
      reason: 'No supported format matched most of the sampled lines. Choose a format manually.',
    };
  }
  const isWeb = best.format === 'apache' || best.format === 'nginx';
  const rival = candidates.find(
    (c) => c.format !== best.format && !(isWeb && (c.format === 'apache' || c.format === 'nginx')),
  );
  const close = rival !== undefined && best.score - rival.score < 0.15;
  const weak = best.score < 0.5;
  const webAmbiguous = isWeb && !webHint;
  const pct = Math.round(best.score * 100);
  let reason = `${pct}% of ${lines.length} sampled lines match this format.`;
  if (webAmbiguous) {
    reason += ' Apache and Nginx use the same access-log format; confirm which server produced it.';
  }
  if (close && rival)
    reason += ` The sample also resembles ${rival.format} (${Math.round(rival.score * 100)}%).`;
  return {
    format: best.format,
    confidence: best.score,
    ambiguous: close || weak || webAmbiguous,
    candidates,
    reason,
  };
}
