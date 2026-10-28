import { useApp } from '../../app/AppContext';
import { useData } from '../../app/DataContext';
import type { View } from '../../app/state';
import { Icon, type IconName } from '../common/Icon';

interface NavEntry {
  view: View;
  label: string;
  icon: IconName;
  needsData: boolean;
}

const GROUPS: Array<{ label: string; items: NavEntry[] }> = [
  {
    label: 'Investigate',
    items: [
      { view: 'overview', label: 'Overview', icon: 'overview', needsData: true },
      { view: 'alerts', label: 'Detections', icon: 'alert', needsData: true },
      { view: 'events', label: 'Event explorer', icon: 'list', needsData: true },
      { view: 'auth', label: 'Authentication', icon: 'key', needsData: true },
      { view: 'web', label: 'Web activity', icon: 'globe', needsData: true },
    ],
  },
  {
    label: 'Data and output',
    items: [
      { view: 'data', label: 'Data source', icon: 'upload', needsData: false },
      { view: 'rules', label: 'Detection rules', icon: 'sliders', needsData: false },
      { view: 'report', label: 'Report & export', icon: 'file', needsData: true },
    ],
  },
];

export function LogLensMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="14" fill="#0e0e10" />
      <circle cx="28" cy="28" r="15" fill="none" stroke="#38bdf8" strokeWidth="5" />
      <path d="M39 39l13 13" stroke="#38bdf8" strokeWidth="6" strokeLinecap="round" />
      <path
        d="M19 31h5l3-7 4 11 3-6h5"
        fill="none"
        stroke="#f2f2f3"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Sidebar() {
  const { state, actions } = useApp();
  const { openCount } = useData();
  const ready = state.scan.phase === 'ready';
  return (
    <aside className="sidebar">
      <div className="brand">
        <LogLensMark />
        <div>
          <div className="brand-title">LogLens</div>
          <div className="brand-sub">Security Log Analyzer &amp; Mini SIEM</div>
        </div>
      </div>
      <nav aria-label="Main" className="nav-groups">
        {GROUPS.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-group-label" aria-hidden="true">
              {group.label}
            </div>
            <ul className="nav">
              {group.items.map((item) => {
                const disabled = item.needsData && !ready;
                const active = state.view === item.view;
                return (
                  <li key={item.view}>
                    <button
                      type="button"
                      className={`nav-item${active ? ' active' : ''}`}
                      aria-current={active ? 'page' : undefined}
                      disabled={disabled}
                      title={disabled ? 'Load a log file first' : undefined}
                      onClick={() => actions.navigate(item.view)}
                    >
                      <Icon name={item.icon} />
                      <span className="nav-label">{item.label}</span>
                      {item.view === 'alerts' && ready && openCount > 0 && (
                        <span className="nav-count" aria-label={`${openCount} not yet reviewed`}>
                          {openCount}
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="sidebar-footer">
        <Icon name="shield" size={14} />
        <p>Runs entirely in this browser. Logs are never uploaded, stored or sent anywhere.</p>
      </div>
    </aside>
  );
}
