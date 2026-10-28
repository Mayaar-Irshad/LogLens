import { SEVERITY_RANK, SEVERITIES, type Detection, type Severity } from '../../types/detection';

const BY_RANK: Severity[] = [...SEVERITIES].sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]);

/**
 * Reverse index from events to the detections they support. Built once per
 * detection run inside the worker so filters such as "events behind high
 * severity alerts" are evaluated without rescanning detections.
 */
export class DetectionIndex {
  private readonly byEvent = new Map<number, number[]>();
  private readonly maxRank = new Map<number, number>();
  private readonly indexById = new Map<string, number>();

  constructor(readonly detections: readonly Detection[]) {
    detections.forEach((d, i) => {
      this.indexById.set(d.id, i);
      const rank = SEVERITY_RANK[d.severity];
      for (const eventId of d.eventIds) {
        let list = this.byEvent.get(eventId);
        if (!list) {
          list = [];
          this.byEvent.set(eventId, list);
        }
        list.push(i);
        if ((this.maxRank.get(eventId) ?? -1) < rank) this.maxRank.set(eventId, rank);
      }
    });
  }

  detectionsFor(eventId: number): readonly number[] {
    return this.byEvent.get(eventId) ?? [];
  }

  detectionIdsFor(eventId: number): string[] {
    return this.detectionsFor(eventId).map((i) => this.detections[i]!.id);
  }

  maxSeverity(eventId: number): Severity | undefined {
    const rank = this.maxRank.get(eventId);
    return rank === undefined ? undefined : BY_RANK[rank];
  }

  /** Indices for detection ids; unknown ids are ignored. */
  resolve(ids: readonly string[]): Set<number> {
    const out = new Set<number>();
    for (const id of ids) {
      const i = this.indexById.get(id);
      if (i !== undefined) out.add(i);
    }
    return out;
  }

  get(id: string): Detection | undefined {
    const i = this.indexById.get(id);
    return i === undefined ? undefined : this.detections[i];
  }

  get flaggedEventCount(): number {
    return this.byEvent.size;
  }
}
