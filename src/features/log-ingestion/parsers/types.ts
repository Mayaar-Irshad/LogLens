import type { EventDraft, LogFormat, RejectReason, SkipReason } from '../../../types/events';
import type { ParseWarning } from '../../../types/ingestion';

export type ParseOutput =
  | { type: 'event'; line: number; raw: string; drafts: EventDraft[] }
  | { type: 'reject'; line: number; raw: string; reason: RejectReason; detail: string }
  | { type: 'skip'; line: number; reason: SkipReason };

/**
 * A format-specific, stateful record parser. It receives physical lines one at
 * a time (some formats, such as CSV with quoted newlines, assemble a record from
 * several lines) and must never throw for malformed input.
 */
export interface RecordParser {
  readonly format: LogFormat;
  push(line: string, lineNumber: number): ParseOutput[];
  /** Flush any buffered state at end of input. */
  finish(): ParseOutput[];
  /** True while a multi-line record is being assembled (blank lines then belong to it). */
  isBuffering(): boolean;
  /** Parser-level warnings (assumptions made, ambiguous data). */
  warnings(): ParseWarning[];
}

export class WarningCollector {
  private readonly map = new Map<string, ParseWarning>();

  add(code: string, message: string, count = 1): void {
    const existing = this.map.get(code);
    if (existing) existing.count += count;
    else this.map.set(code, { code, message, count });
  }

  list(): ParseWarning[] {
    return [...this.map.values()];
  }
}
