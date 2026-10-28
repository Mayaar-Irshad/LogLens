export type LineItem =
  { kind: 'line'; text: string } | { kind: 'overlong'; preview: string; length: number };

/**
 * Incremental line splitter for streamed text. Handles LF, CRLF and CR line
 * endings, including CRLF pairs split across chunks. Memory is bounded: once a
 * line exceeds `maxLineLength`, its remaining content is counted but not
 * buffered, so a single enormous line (or a binary file with no newlines)
 * cannot exhaust memory.
 */
export class LineSplitter {
  private buffer = '';
  private overlong: { preview: string; length: number } | null = null;
  private endedWithCR = false;

  constructor(private readonly maxLineLength: number) {}

  private append(segment: string): void {
    if (segment.length === 0) return;
    if (this.overlong) {
      this.overlong.length += segment.length;
      return;
    }
    if (this.buffer.length + segment.length > this.maxLineLength) {
      const combined = this.buffer + segment.slice(0, 512);
      this.overlong = {
        preview: combined.slice(0, 512),
        length: this.buffer.length + segment.length,
      };
      this.buffer = '';
      return;
    }
    this.buffer += segment;
  }

  private take(): LineItem {
    if (this.overlong) {
      const item: LineItem = { kind: 'overlong', ...this.overlong };
      this.overlong = null;
      return item;
    }
    const item: LineItem = { kind: 'line', text: this.buffer };
    this.buffer = '';
    return item;
  }

  push(chunk: string): LineItem[] {
    const out: LineItem[] = [];
    let pos = 0;
    if (this.endedWithCR && chunk.startsWith('\n')) pos = 1;
    this.endedWithCR = false;
    const re = /\r\n|\r|\n/g;
    re.lastIndex = pos;
    let m: RegExpExecArray | null;
    while ((m = re.exec(chunk)) !== null) {
      this.append(chunk.slice(pos, m.index));
      out.push(this.take());
      pos = m.index + m[0].length;
    }
    this.append(chunk.slice(pos));
    if (chunk.endsWith('\r')) this.endedWithCR = true;
    return out;
  }

  finish(): LineItem[] {
    if (this.buffer.length > 0 || this.overlong) return [this.take()];
    return [];
  }
}

/**
 * Read a Blob as UTF-8 text in chunks, reporting the number of bytes consumed.
 * Invalid byte sequences become U+FFFD instead of aborting the read. A leading
 * byte-order mark is removed by the decoder.
 */
export async function* readBlobChunks(blob: Blob): AsyncGenerator<{ text: string; bytes: number }> {
  const reader = blob.stream().getReader();
  const decoder = new TextDecoder('utf-8', { fatal: false });
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      yield { text: decoder.decode(value, { stream: true }), bytes: value.byteLength };
    }
    const tail = decoder.decode();
    if (tail) yield { text: tail, bytes: 0 };
  } finally {
    reader.releaseLock();
  }
}
