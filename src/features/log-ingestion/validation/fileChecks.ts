import { formatBytes } from '../../../utils/format';

export interface InputCheck {
  ok: boolean;
  error?: string;
  warnings: string[];
}

const ARCHIVE_EXTENSIONS = /\.(gz|tgz|zip|7z|bz2|xz|zst|rar|tar)$/i;
const BINARY_EXTENSIONS = /\.(exe|dll|so|bin|png|jpe?g|gif|pdf|docx?|xlsx?|pcap|pcapng|evtx)$/i;

/** Pre-scan checks on file metadata. The file content is not read here. */
export function checkInputFile(file: { name: string; size: number }, maxBytes: number): InputCheck {
  const warnings: string[] = [];
  if (file.size === 0)
    return {
      ok: false,
      error: 'The file is empty (0 bytes). There is nothing to analyze.',
      warnings,
    };
  if (file.size > maxBytes) {
    return {
      ok: false,
      error: `The file is ${formatBytes(file.size)}, which exceeds the ${formatBytes(maxBytes)} limit. Split the file or raise the limit in Settings (memory use grows with file size).`,
      warnings,
    };
  }
  if (ARCHIVE_EXTENSIONS.test(file.name)) {
    return {
      ok: false,
      error:
        'Compressed archives are not supported. Decompress the file and select the plain-text log.',
      warnings,
    };
  }
  if (/\.evtx$/i.test(file.name)) {
    return {
      ok: false,
      error:
        'Windows .evtx files are binary and not supported. Export events to CSV or JSON first.',
      warnings,
    };
  }
  if (BINARY_EXTENSIONS.test(file.name)) {
    warnings.push('The file extension suggests a non-text file; analysis may reject most lines.');
  }
  return { ok: true, warnings };
}

/** Check a pasted text input against the size limit. */
export function checkPastedText(text: string, maxBytes: number): InputCheck {
  if (text.trim() === '')
    return { ok: false, error: 'Paste some log lines to analyze.', warnings: [] };
  const bytes = new TextEncoder().encode(text).byteLength;
  if (bytes > maxBytes) {
    return {
      ok: false,
      error: `The pasted text is ${formatBytes(bytes)}, which exceeds the ${formatBytes(maxBytes)} limit.`,
      warnings: [],
    };
  }
  return { ok: true, warnings: [] };
}

/**
 * Heuristic binary-content check on a decoded text sample. NUL characters or a
 * high share of control / replacement characters indicate a non-text file.
 */
export function looksBinary(sample: string): boolean {
  if (sample.length === 0) return false;
  let suspicious = 0;
  let nul = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    if (c === 0) nul++;
    if (c === 0xfffd || (c < 32 && c !== 9 && c !== 10 && c !== 13)) suspicious++;
  }
  return nul > 0 || suspicious / sample.length > 0.05;
}
