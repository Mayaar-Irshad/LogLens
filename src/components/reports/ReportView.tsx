import { useState } from 'react';
import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import { assessPosture } from '../../features/detection/risk/risk';
import { hasActiveFilters, statusOf } from '../../features/investigation/filters';
import { EVENT_CSV_COLUMNS } from '../../features/reporting/csv';
import {
  buildReport,
  REPORT_EVENTS_PER_DETECTION,
  serializeReport,
} from '../../features/reporting/report';
import type { NormalizedEvent } from '../../types/events';
import { buildFilename, downloadText } from '../../utils/download';
import { Icon } from '../common/Icon';
import { Callout, PageHeader } from '../common/Misc';
import { ExportEventsButton } from './ExportEventsButton';

const BATCH = 200;

export function ReportView() {
  const { state, actions, client } = useApp();
  const data = useData();
  const [scope, setScope] = useState<'all' | 'filtered'>('all');
  const [includeNotes, setIncludeNotes] = useState(true);
  const [includeRaw, setIncludeRaw] = useState(false);
  const [includeRawCsv, setIncludeRawCsv] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const filtered = hasActiveFilters(state.filters);
  const useFiltered = scope === 'filtered' && filtered;
  // Never write a "filtered" report from figures that are still loading or failed.
  const notReady = useFiltered && (data.loading || data.error !== null);
  const detections = useFiltered ? data.detections : state.detections;
  const reviewed = detections.filter((d) => statusOf(state.statuses, d.id) === 'reviewed').length;

  const generate = async () => {
    const summary = state.summary;
    const metrics = useFiltered ? data.metrics : state.baseMetrics;
    if (!summary || !metrics || !state.posture || notReady) return;
    setBusy(true);
    setMessage(null);
    try {
      const wanted = detections.map(
        (d) => [d.id, d.eventIds.slice(0, REPORT_EVENTS_PER_DETECTION)] as const,
      );
      const ids = [...new Set(wanted.flatMap(([, list]) => list))];
      const byId = new Map<number, NormalizedEvent>();
      for (let i = 0; i < ids.length; i += BATCH) {
        for (const e of await client.query({ type: 'eventsById', ids: ids.slice(i, i + BATCH) }))
          byId.set(e.id, e);
      }
      const evidence = new Map(
        wanted.map(([id, list]) => [
          id,
          list.map((n) => byId.get(n)).filter((e): e is NormalizedEvent => e !== undefined),
        ]),
      );
      const visible = new Set(detections.map((d) => d.id));
      const now = Date.now();
      const report = buildReport({
        appVersion: __APP_VERSION__,
        generatedAt: now,
        timeZone: state.timeZone,
        summary,
        detections,
        ruleRuns: state.ruleRuns,
        entities: useFiltered
          ? state.entities.filter((e) => e.detectionIds.some((id) => visible.has(id)))
          : state.entities,
        // A filtered report describes only the detections it contains.
        posture: useFiltered ? assessPosture(detections) : state.posture,
        metrics,
        detectionConfig: state.detectionConfig,
        filters: useFiltered ? state.filters : null,
        statuses: state.statuses,
        notes: state.notes,
        caseNote: state.caseNote,
        evidence,
        options: { includeNotes, includeRawEvidence: includeRaw },
      });
      downloadText(
        buildFilename('report', summary.source.name, now, 'json'),
        serializeReport(report),
        'application/json',
      );
      setMessage(`Report generated with ${detections.length} detection(s).`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Report generation failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="view">
      <PageHeader
        title="Report & export"
        description="Generate an investigation report or export events. Files are created in this browser and downloaded only when you click."
      />
      <div className="grid grid-2">
        <section className="card" aria-labelledby="report-title">
          <h2 className="card-title" id="report-title">
            JSON investigation report
          </h2>
          <p className="card-sub">
            Includes application version, scan time, format and parsing statistics, time range,
            aggregated metrics, detections with evidence summaries and event references, rule
            configuration, and assessment limitations.
          </p>
          <fieldset className="radio-group">
            <legend>Scope</legend>
            <label>
              <input
                type="radio"
                name="scope"
                checked={!useFiltered}
                onChange={() => setScope('all')}
              />{' '}
              Full dataset ({state.detections.length} detections)
            </label>
            <label className={filtered ? '' : 'muted'}>
              <input
                type="radio"
                name="scope"
                checked={useFiltered}
                disabled={!filtered}
                onChange={() => setScope('filtered')}
              />{' '}
              Current filtered view
              {filtered ? ` (${data.detections.length} detections)` : ' (no filters active)'}
            </label>
          </fieldset>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={includeNotes}
              onChange={(e) => setIncludeNotes(e.target.checked)}
            />{' '}
            Include review status and analyst notes ({reviewed} reviewed)
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={includeRaw}
              onChange={(e) => setIncludeRaw(e.target.checked)}
            />{' '}
            Include original log lines for referenced events
          </label>
          {includeRaw && (
            <Callout tone="warn">
              Original log lines can contain sensitive data (usernames, internal hosts, tokens in
              URLs). Only include them if the report stays within your organisation.
            </Callout>
          )}
          <div className="form-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void generate()}
              disabled={busy || notReady}
            >
              <Icon name="download" /> {busy ? 'Generating…' : 'Download JSON report'}
            </button>
            {notReady && (
              <span className="muted small" role="status">
                {data.error ? 'The filtered figures failed to load.' : 'Updating filtered figures…'}
              </span>
            )}
            {message && (
              <span className="muted small" role="status">
                {message}
              </span>
            )}
          </div>
        </section>

        <section className="card" aria-labelledby="csv-title">
          <h2 className="card-title" id="csv-title">
            Event export (CSV)
          </h2>
          <p className="card-sub">
            Exports the events matching the current filters (
            {(data.metrics?.totalEvents ?? 0).toLocaleString('en-US')} events). Cells that a
            spreadsheet would interpret as formulas are prefixed with an apostrophe.
          </p>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={includeRawCsv}
              onChange={(e) => setIncludeRawCsv(e.target.checked)}
            />{' '}
            Include original log lines
          </label>
          <div>
            <h3 className="section-title" id="csv-columns">
              Columns
            </h3>
            <ul className="column-list" aria-labelledby="csv-columns">
              {[...EVENT_CSV_COLUMNS, ...(includeRawCsv ? ['raw_log_line'] : [])].map((c) => (
                <li key={c} className="mono">
                  {c}
                </li>
              ))}
            </ul>
          </div>
          <div className="form-actions">
            <ExportEventsButton includeRaw={includeRawCsv} label="Download events CSV" />
          </div>
        </section>

        <section className="card span-2" aria-labelledby="case-note-title">
          <label className="card-title" id="case-note-title" htmlFor="case-note">
            Investigation summary note
          </label>
          <p className="card-sub">
            Optional free-text summary included in the report. Kept in memory for this session only.
          </p>
          <textarea
            id="case-note"
            className="textarea"
            rows={6}
            maxLength={50_000}
            value={state.caseNote}
            onChange={(e) => actions.dispatch({ type: 'setCaseNote', note: e.target.value })}
            placeholder="What happened, what was verified, what remains open…"
          />
        </section>
      </div>
    </div>
  );
}
