import { useRef, useState, type DragEvent } from 'react';
import { useApp } from '../../app/AppContext';
import { parseTimezoneSetting } from '../../features/log-ingestion/normalization/timestamp';
import {
  PREFLIGHT_SAMPLE_BYTES,
  runPreflight,
  type Preflight,
} from '../../features/log-ingestion/preflight';
import {
  checkInputFile,
  checkPastedText,
} from '../../features/log-ingestion/validation/fileChecks';
import { SAMPLES } from '../../features/sample-data/samples';
import { LOG_FORMATS, LOG_FORMAT_LABELS, type LogFormat } from '../../types/events';
import type { FieldMapping, ParseOptions } from '../../types/ingestion';
import { formatBytes, formatOffset } from '../../utils/format';
import { toSingleLine, truncate } from '../../utils/text';
import { Icon } from '../common/Icon';
import { Callout, PageHeader } from '../common/Misc';
import { FieldMappingEditor } from './FieldMappingEditor';
import { ParseReport } from './ParseReport';

type Pending = { kind: 'file'; file: File } | { kind: 'text'; text: string };

interface Draft {
  pending: Pending;
  preflight: Preflight;
  format: LogFormat | '';
  /** Kept as typed; validated before analysis so typing is never fought by clamping. */
  assumedYear: string;
  timezone: string;
  mapping: FieldMapping;
  warnings: string[];
}

const nameOf = (p: Pending): string => (p.kind === 'file' ? p.file.name : 'pasted text');

export function DataSourceView() {
  const { state, actions } = useApp();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [pasted, setPasted] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const scanning = state.scan.phase === 'scanning';

  const prepare = (pending: Pending, sample: string, truncated: boolean, warnings: string[]) => {
    const preflight = runPreflight(sample, {
      fileName: pending.kind === 'file' ? pending.file.name : '',
      truncated,
    });
    if (preflight.detection.unsupportedReason) {
      setDraft(null);
      setError(preflight.detection.unsupportedReason);
      return;
    }
    const format = preflight.detection.format ?? '';
    const lastModified =
      pending.kind === 'file' && pending.file.lastModified
        ? new Date(pending.file.lastModified).getUTCFullYear()
        : new Date().getUTCFullYear();
    setError(null);
    setDraft({
      pending,
      preflight,
      format,
      assumedYear: String(lastModified),
      timezone: 'UTC',
      mapping:
        (format === 'csv' ? preflight.csv?.suggestedMapping : preflight.jsonl?.suggestedMapping) ??
        {},
      warnings,
    });
  };

  const onFile = async (file: File | undefined, extraWarnings: string[] = []) => {
    if (!file) return;
    const check = checkInputFile(file, state.limits.maxFileSizeBytes);
    if (!check.ok) {
      setDraft(null);
      setError(check.error ?? 'This file cannot be analyzed.');
      return;
    }
    try {
      const sample = await file.slice(0, PREFLIGHT_SAMPLE_BYTES).text();
      prepare({ kind: 'file', file }, sample, file.size > PREFLIGHT_SAMPLE_BYTES, [
        ...extraWarnings,
        ...check.warnings,
      ]);
    } catch {
      setError('The file could not be read. Check that it is a readable text file.');
    }
  };

  const onPasteInspect = () => {
    const check = checkPastedText(pasted, state.limits.maxFileSizeBytes);
    if (!check.ok) {
      setError(check.error ?? 'Nothing to analyze.');
      return;
    }
    prepare(
      { kind: 'text', text: pasted },
      pasted.slice(0, PREFLIGHT_SAMPLE_BYTES),
      pasted.length > PREFLIGHT_SAMPLE_BYTES,
      [],
    );
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const extra =
      e.dataTransfer.files.length > 1
        ? [`${e.dataTransfer.files.length} files were dropped; only the first one is analyzed.`]
        : [];
    void onFile(e.dataTransfer.files[0], extra);
  };

  const offset = draft ? parseTimezoneSetting(draft.timezone) : 0;
  const year = draft && /^\d{4}$/.test(draft.assumedYear.trim()) ? Number(draft.assumedYear) : NaN;
  const yearValid = draft?.format !== 'linux-auth' || (year >= 1970 && year <= 2100);
  const structured =
    draft?.format === 'csv'
      ? draft.preflight.csv
      : draft?.format === 'jsonl'
        ? draft.preflight.jsonl
        : undefined;
  const canAnalyze =
    draft !== null && draft.format !== '' && offset !== null && yearValid && !scanning;

  const analyze = () => {
    if (!draft || draft.format === '' || offset === null || !yearValid) return;
    const parse: ParseOptions = {
      format: draft.format,
      timestamps: {
        assumedYear: Number.isFinite(year) ? year : new Date().getUTCFullYear(),
        sourceOffsetMinutes: offset,
      },
      ...(draft.format === 'csv' || draft.format === 'jsonl' ? { mapping: draft.mapping } : {}),
      ...(draft.format === 'csv' && draft.preflight.csv?.delimiter
        ? { csvDelimiter: draft.preflight.csv.delimiter }
        : {}),
    };
    const source =
      draft.pending.kind === 'file'
        ? { kind: 'file' as const, file: draft.pending.file, name: draft.pending.file.name }
        : { kind: 'text' as const, text: draft.pending.text, name: 'pasted text' };
    // The draft stays: if the scan fails, the format, mapping and options are still here.
    void actions.startScan(source, parse);
  };

  const runSample = (id: (typeof SAMPLES)[number]['id']) => {
    const info = SAMPLES.find((s) => s.id === id)!;
    setDraft(null);
    setError(null);
    void actions.startScan(
      { kind: 'sample', sampleId: id },
      { format: info.format, timestamps: { assumedYear: 2026, sourceOffsetMinutes: 0 } },
    );
  };

  const progress = state.scan.progress;
  const pct =
    progress && progress.totalBytes > 0
      ? Math.min(100, Math.round((progress.bytesProcessed / progress.totalBytes) * 100))
      : 0;

  return (
    <div className="view">
      <PageHeader
        title="Data source"
        description="Load a log file, paste log lines, or explore a clearly labelled synthetic sample. Everything is analyzed locally in this browser tab."
      />

      {state.scan.notice && <Callout tone="info">{state.scan.notice}</Callout>}
      {state.scan.phase === 'error' && state.scan.error && (
        <Callout tone="danger" title="Analysis failed.">
          {state.scan.error}
        </Callout>
      )}
      {error && <Callout tone="danger">{error}</Callout>}

      {scanning && (
        <section className="card scan-progress" aria-labelledby="scan-title" aria-busy="true">
          <h2 className="card-title" id="scan-title">
            Analyzing {truncate(toSingleLine(state.scan.sourceName ?? 'input'), 60)}
          </h2>
          <div
            className="progress"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={pct}
            aria-label="Scan progress"
          >
            <span style={{ width: `${pct}%` }} />
          </div>
          <p className="muted" aria-live="polite">
            {progress
              ? `${progress.phase === 'reading' ? 'Reading and parsing' : progress.phase === 'detecting' ? 'Running detection rules' : progress.phase === 'indexing' ? 'Building indexes' : 'Finishing'} · ${progress.linesProcessed.toLocaleString('en-US')} lines · ${progress.eventsCreated.toLocaleString('en-US')} events · ${formatBytes(progress.bytesProcessed)} of ${formatBytes(progress.totalBytes)}`
              : 'Starting worker…'}
          </p>
          <button type="button" className="btn btn-danger" onClick={actions.cancelScan}>
            Cancel scan
          </button>
        </section>
      )}

      {state.scan.phase === 'ready' && state.summary && (
        <>
          <Callout tone="success" title="Analysis complete.">
            {state.summary.detections.length} detection(s) from{' '}
            {state.summary.stats.eventsCreated.toLocaleString('en-US')} events. Load another input
            with “New scan”; the current dataset and investigation notes will be discarded.
          </Callout>
          <ParseReport
            stats={state.summary.stats}
            rejected={state.summary.rejected}
            timingMs={state.summary.timing.totalMs}
          />
        </>
      )}

      {!scanning && state.scan.phase !== 'ready' && !draft && (
        <div className="grid grid-2">
          <section className="card" aria-labelledby="upload-title">
            <h2 className="card-title" id="upload-title">
              Upload a log file
            </h2>
            <div
              className={`dropzone${dragging ? ' dragging' : ''}`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
            >
              <Icon name="upload" size={28} />
              <p>
                Drag and drop a log file here, or{' '}
                <button
                  type="button"
                  className="link-button"
                  onClick={() => inputRef.current?.click()}
                >
                  choose a file
                </button>
              </p>
              <p className="muted small">
                Linux auth.log / secure, Apache &amp; Nginx access logs, JSON Lines, CSV with
                header. Limit {formatBytes(state.limits.maxFileSizeBytes)} (adjustable in Detection
                rules → Resource limits).
              </p>
              <input
                ref={inputRef}
                type="file"
                className="visually-hidden"
                aria-label="Choose a log file"
                accept=".log,.txt,.jsonl,.ndjson,.json,.csv,.tsv,text/plain,text/csv,application/json"
                onChange={(e) => {
                  void onFile(e.target.files?.[0]);
                  e.target.value = '';
                }}
              />
            </div>
          </section>

          <section className="card" aria-labelledby="paste-title">
            <h2 className="card-title" id="paste-title">
              Paste log lines
            </h2>
            <label className="visually-hidden" htmlFor="paste-input">
              Log lines to analyze
            </label>
            <textarea
              id="paste-input"
              className="textarea mono"
              rows={7}
              spellCheck={false}
              placeholder="Oct 27 10:00:01 host sshd[123]: Failed password for root from 203.0.113.5 port 52211 ssh2"
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
            />
            <button
              type="button"
              className="btn btn-primary"
              onClick={onPasteInspect}
              disabled={pasted.trim() === ''}
            >
              Inspect pasted text
            </button>
          </section>

          <section className="card span-2" aria-labelledby="samples-title">
            <h2 className="card-title" id="samples-title">
              Synthetic sample data
            </h2>
            <p className="card-sub">
              Generated, fictional logs using only documentation IP ranges (RFC 5737). They contain
              planted scenarios so you can see how detections and investigations work.{' '}
              <strong>Not real data.</strong>
            </p>
            <div className="sample-grid">
              {SAMPLES.map((s) => (
                <article className="sample" key={s.id}>
                  <header>
                    <span className="tag">SAMPLE</span> <strong>{s.name}</strong>
                  </header>
                  <p className="small">{s.description}</p>
                  <ul className="small muted">
                    {s.scenarios.map((sc) => (
                      <li key={sc}>{sc}</li>
                    ))}
                  </ul>
                  <button type="button" className="btn" onClick={() => runSample(s.id)}>
                    Analyze sample
                  </button>
                </article>
              ))}
            </div>
          </section>
        </div>
      )}

      {draft && !scanning && (
        <section className="card" aria-labelledby="preflight-title">
          <header className="card-header">
            <div>
              <h2 className="card-title" id="preflight-title">
                Confirm format: {truncate(toSingleLine(nameOf(draft.pending)), 60)}
              </h2>
              <p className="card-sub">
                {draft.pending.kind === 'file' ? `${formatBytes(draft.pending.file.size)} · ` : ''}
                Sampled {draft.preflight.sampleLineCount.toLocaleString('en-US')} lines.{' '}
                {draft.preflight.detection.reason}
              </p>
            </div>
            <button type="button" className="btn btn-ghost" onClick={() => setDraft(null)}>
              Choose different input
            </button>
          </header>
          {draft.warnings.map((w) => (
            <Callout key={w} tone="warn">
              {w}
            </Callout>
          ))}
          {draft.preflight.detection.ambiguous && (
            <Callout tone="warn" title="Format detection is not certain.">
              Choose the format that matches the source below.
            </Callout>
          )}
          <div className="form-row">
            <div className="field">
              <label className="field-label" htmlFor="format-select">
                Log format
              </label>
              <select
                id="format-select"
                className="select"
                value={draft.format}
                onChange={(e) => {
                  const format = e.target.value as LogFormat | '';
                  const mapping =
                    (format === 'csv'
                      ? draft.preflight.csv?.suggestedMapping
                      : format === 'jsonl'
                        ? draft.preflight.jsonl?.suggestedMapping
                        : undefined) ?? {};
                  setDraft({ ...draft, format, mapping });
                }}
              >
                <option value="">— choose a format —</option>
                {LOG_FORMATS.map((f) => {
                  const score = draft.preflight.detection.candidates.find(
                    (c) => c.format === f,
                  )?.score;
                  return (
                    <option key={f} value={f}>
                      {LOG_FORMAT_LABELS[f]}
                      {score !== undefined ? ` (${Math.round(score * 100)}% match)` : ''}
                    </option>
                  );
                })}
              </select>
            </div>
            {draft.format === 'linux-auth' && (
              <div className="field">
                <label className="field-label" htmlFor="year-input">
                  Assumed year
                </label>
                <input
                  id="year-input"
                  className="input"
                  inputMode="numeric"
                  maxLength={4}
                  value={draft.assumedYear}
                  aria-invalid={!yearValid}
                  aria-describedby="year-hint"
                  onChange={(e) => setDraft({ ...draft, assumedYear: e.target.value })}
                />
                <span id="year-hint" className={`field-hint${yearValid ? '' : ' text-danger'}`}>
                  {yearValid
                    ? 'Syslog timestamps have no year. Applied to the first record; Dec→Jan rollovers are detected.'
                    : 'Enter a four-digit year between 1970 and 2100.'}
                </span>
              </div>
            )}
            <div className="field">
              <label className="field-label" htmlFor="tz-input">
                Source time zone (for timestamps without a zone)
              </label>
              <input
                id="tz-input"
                className="input"
                value={draft.timezone}
                maxLength={9}
                aria-invalid={offset === null}
                onChange={(e) => setDraft({ ...draft, timezone: e.target.value })}
              />
              <span className={`field-hint${offset === null ? ' text-danger' : ''}`}>
                {offset === null
                  ? 'Use UTC or an offset such as +05:30 or -07:00.'
                  : `Interpreted as ${formatOffset(offset)}. Timestamps with an explicit zone are unaffected.`}
              </span>
            </div>
          </div>
          {structured && (
            <FieldMappingEditor
              sample={structured}
              mapping={draft.mapping}
              onChange={(mapping) => setDraft({ ...draft, mapping })}
            />
          )}
          {(draft.format === 'csv' || draft.format === 'jsonl') && !structured && (
            <Callout tone="warn">
              No {draft.format === 'csv' ? 'CSV header' : 'JSON objects'} could be read from the
              sample; most records will likely be rejected.
            </Callout>
          )}
          <div className="form-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={analyze}
              disabled={!canAnalyze}
            >
              Analyze locally
            </button>
            <span className="muted small">
              The file is read inside a Web Worker in this tab. Nothing is uploaded.
            </span>
          </div>
        </section>
      )}
    </div>
  );
}
