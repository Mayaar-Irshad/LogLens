import type { NormalizedEvent, RejectedRecord } from '../../types/events';
import type { IngestResult, ParseOptions, ParseStats, ResourceLimits } from '../../types/ingestion';
import { formatNumber } from '../../utils/format';
import { hash53 } from '../../utils/hash';
import { previewText } from '../../utils/text';
import { createParser } from './createParser';
import { LineSplitter } from './lineSplitter';
import type { ParseOutput, RecordParser } from './parsers/types';

export interface IngestorOptions {
  parse: ParseOptions;
  limits: ResourceLimits;
  /** Reference time for "timestamp in the future" checks (defaults to Date.now()). */
  now?: number;
}

const FUTURE_TOLERANCE_MS = 24 * 3600_000;

/**
 * Orchestrates parsing: enforces resource limits, assigns event identity,
 * counts every line into exactly one bucket (blank, skipped, parsed, partial,
 * rejected, or unprocessed), and keeps bounded samples of rejected records.
 * Nothing is silently discarded.
 */
export class Ingestor {
  private readonly parser: RecordParser;
  private readonly events: NormalizedEvent[] = [];
  private readonly rejected: RejectedRecord[] = [];
  private readonly seen = new Set<number>();
  private lineNumber = 0;
  private limitReached = false;
  private limitLine = 0;
  private readonly stats: ParseStats = {
    totalLines: 0,
    blankLines: 0,
    skippedLines: 0,
    parsedRecords: 0,
    partialRecords: 0,
    rejectedRecords: 0,
    eventsCreated: 0,
    expandedRepeats: 0,
    duplicateLines: 0,
    unprocessedLines: 0,
    eventsWithoutTimestamp: 0,
    bytesRead: 0,
    warnings: [],
  };

  constructor(private readonly options: IngestorOptions) {
    this.parser = createParser(options.parse, options.limits);
  }

  get lines(): number {
    return this.lineNumber;
  }

  get eventCount(): number {
    return this.events.length;
  }

  addBytes(bytes: number): void {
    this.stats.bytesRead += bytes;
  }

  pushLine(input: string): void {
    this.lineNumber++;
    this.stats.totalLines++;
    const text = this.lineNumber === 1 ? input.replace(/^\ufeff/, '') : input;
    if (this.limitReached) {
      if (text.trim() !== '') this.stats.unprocessedLines++;
      return;
    }
    if (text.trim() === '' && !this.parser.isBuffering()) {
      this.stats.blankLines++;
      return;
    }
    if (text.trim() !== '') this.trackDuplicate(text);
    if (text.length > this.options.limits.maxLineLength) {
      this.reject(
        this.lineNumber,
        text,
        'line_too_long',
        `line has ${formatNumber(text.length)} characters`,
        text.length,
      );
      return;
    }
    this.consume(this.parser.push(text, this.lineNumber));
  }

  /** Register a line that the splitter already found to exceed the length limit. */
  pushOverlong(preview: string, length: number): void {
    this.lineNumber++;
    this.stats.totalLines++;
    if (this.limitReached) {
      this.stats.unprocessedLines++;
      return;
    }
    this.reject(
      this.lineNumber,
      preview,
      'line_too_long',
      `line has ${formatNumber(length)} characters`,
      length,
    );
  }

  private trackDuplicate(text: string): void {
    const h = hash53(text);
    if (this.seen.has(h)) this.stats.duplicateLines++;
    else if (this.seen.size < this.options.limits.maxEvents) this.seen.add(h);
  }

  private reject(
    line: number,
    raw: string,
    reason: RejectedRecord['reason'],
    detail: string,
    length = raw.length,
  ): void {
    this.stats.rejectedRecords++;
    if (this.rejected.length < this.options.limits.maxRejectedSamples) {
      this.rejected.push({ line, reason, detail, preview: previewText(raw, 160), length });
    }
  }

  private consume(outputs: ParseOutput[]): void {
    for (const out of outputs) {
      if (out.type === 'skip') {
        this.stats.skippedLines++;
        continue;
      }
      if (out.type === 'reject') {
        this.reject(out.line, out.raw, out.reason, out.detail);
        continue;
      }
      const partial = (out.drafts[0]?.issues?.length ?? 0) > 0;
      if (partial) this.stats.partialRecords++;
      else this.stats.parsedRecords++;
      for (const draft of out.drafts) {
        if (this.events.length >= this.options.limits.maxEvents) {
          this.markLimit(out.line);
          break;
        }
        const event: NormalizedEvent = {
          ...draft,
          id: this.events.length,
          line: out.line,
          format: this.parser.format,
          raw: out.raw,
          status: partial ? 'partial' : 'parsed',
        };
        if (event.timestamp === undefined) this.stats.eventsWithoutTimestamp++;
        this.events.push(event);
        this.stats.eventsCreated++;
      }
      if (out.drafts.length > 1) this.stats.expandedRepeats += out.drafts.length - 1;
      if (this.events.length >= this.options.limits.maxEvents) this.markLimit(out.line);
    }
  }

  private markLimit(line: number): void {
    if (this.limitReached) return;
    this.limitReached = true;
    this.limitLine = line;
  }

  finish(): IngestResult {
    this.consume(this.parser.finish());
    const warnings = [...this.parser.warnings()];
    if (this.limitReached) {
      warnings.push({
        code: 'event_limit',
        message: `The event limit of ${formatNumber(this.options.limits.maxEvents)} was reached at line ${formatNumber(this.limitLine)}. ${formatNumber(this.stats.unprocessedLines)} later non-blank line(s) were counted but not analyzed.`,
        count: 1,
      });
    }
    if (this.stats.duplicateLines > 0) {
      warnings.push({
        code: 'duplicate_lines',
        message: `${formatNumber(this.stats.duplicateLines)} line(s) are exact duplicates of earlier lines. They were kept as separate events.`,
        count: this.stats.duplicateLines,
      });
    }
    if (this.stats.expandedRepeats > 0) {
      warnings.push({
        code: 'expanded_repeats',
        message: `${formatNumber(this.stats.expandedRepeats)} additional event(s) were created from "message repeated N times" lines.`,
        count: this.stats.expandedRepeats,
      });
    }
    if (this.stats.eventsWithoutTimestamp > 0 && this.stats.eventsCreated > 0) {
      warnings.push({
        code: 'missing_timestamps',
        message: `${formatNumber(this.stats.eventsWithoutTimestamp)} event(s) have no valid timestamp. They appear in counts and the event explorer but not in time-based charts or windowed detections.`,
        count: this.stats.eventsWithoutTimestamp,
      });
    }
    const now = this.options.now ?? Date.now();
    const future = this.events.filter(
      (e) => e.timestamp !== undefined && e.timestamp > now + FUTURE_TOLERANCE_MS,
    ).length;
    if (future > 0) {
      warnings.push({
        code: 'future_timestamps',
        message: `${formatNumber(future)} event(s) have timestamps more than a day in the future. Check the assumed year and source time zone.`,
        count: future,
      });
    }
    this.stats.warnings = warnings;
    return {
      format: this.parser.format,
      events: this.events,
      rejected: this.rejected,
      stats: { ...this.stats },
      limitReached: this.limitReached,
    };
  }
}

/** Convenience: ingest an in-memory string (pasted text, tests, samples). */
export function ingestText(text: string, options: IngestorOptions): IngestResult {
  const ingestor = new Ingestor(options);
  const splitter = new LineSplitter(options.limits.maxLineLength);
  const feed = (items: ReturnType<LineSplitter['push']>): void => {
    for (const item of items) {
      if (item.kind === 'line') ingestor.pushLine(item.text);
      else ingestor.pushOverlong(item.preview, item.length);
    }
  };
  feed(splitter.push(text));
  feed(splitter.finish());
  ingestor.addBytes(new TextEncoder().encode(text).byteLength);
  return ingestor.finish();
}
