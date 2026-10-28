/**
 * Turn an untrusted name (for example an uploaded file name) into a safe
 * filename fragment: ASCII letters, digits, dot, dash and underscore only,
 * no leading dots, bounded length.
 */
export function safeFilenamePart(name: string, max = 40): string {
  const cleaned = name
    .normalize('NFKD')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '');
  return cleaned.slice(0, max) || 'logs';
}

export function timestampForFilename(ms: number): string {
  return new Date(ms)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z')
    .replace('T', '-');
}

export function buildFilename(
  kind: 'report' | 'events',
  sourceName: string,
  ms: number,
  extension: 'json' | 'csv',
): string {
  return `loglens-${kind}-${safeFilenamePart(sourceName.replace(/\.[A-Za-z0-9]{1,8}$/, ''))}-${timestampForFilename(ms)}.${extension}`;
}

/**
 * Trigger a download of locally generated content. Only called from an
 * explicit user action. The object URL is revoked after the click so the
 * Blob can be garbage-collected.
 */
export function downloadText(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: `${mimeType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
