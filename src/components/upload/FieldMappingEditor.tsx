import { useId } from 'react';
import {
  MAPPABLE_FIELDS,
  MAPPABLE_FIELD_LABELS,
  type FieldMapping,
  type MappableField,
  type StructuredSample,
} from '../../types/ingestion';
import { truncate } from '../../utils/text';

const PRIMARY: MappableField[] = [
  'timestamp',
  'eventType',
  'sourceIp',
  'username',
  'action',
  'outcome',
  'httpMethod',
  'path',
  'statusCode',
];

export function FieldMappingEditor({
  sample,
  mapping,
  onChange,
}: {
  sample: StructuredSample;
  mapping: FieldMapping;
  onChange: (mapping: FieldMapping) => void;
}) {
  const id = useId();
  const keys = sample.keys;
  const examplesFor = (key: string | undefined): string[] =>
    keys.find((k) => k.key === key)?.examples ?? [];
  const ordered = [...PRIMARY, ...MAPPABLE_FIELDS.filter((f) => !PRIMARY.includes(f))];
  const update = (field: MappableField, key: string) => {
    const next: FieldMapping = { ...mapping };
    if (key === '') delete next[field];
    else next[field] = key;
    onChange(next);
  };
  return (
    <fieldset className="mapping">
      <legend>Field mapping</legend>
      <p className="muted small">
        LogLens suggested a mapping from the column names and sample values. Confirm or change it;
        unmapped fields are kept as additional fields. Only the timestamp is treated as required.
      </p>
      <div className="mapping-grid">
        {ordered.map((field) => {
          const selected = mapping[field] ?? '';
          const ex = examplesFor(selected);
          return (
            <div className="field" key={field}>
              <label htmlFor={`${id}-${field}`} className="field-label">
                {MAPPABLE_FIELD_LABELS[field]}
              </label>
              <select
                id={`${id}-${field}`}
                className="select"
                value={selected}
                onChange={(e) => update(field, e.target.value)}
              >
                <option value="">— not mapped —</option>
                {keys.map((k) => (
                  <option key={k.key} value={k.key}>
                    {truncate(k.key, 60)}
                  </option>
                ))}
              </select>
              {ex.length > 0 && (
                <span className="field-hint mono" title={ex.join(' | ')}>
                  e.g. {truncate(ex.join(' | '), 70)}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}
