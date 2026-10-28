import { useEffect, useRef } from 'react';
import { useApp } from '../../app/AppContext';
import { DataProvider } from '../../app/DataContext';
import type { View } from '../../app/state';
import { AlertsView } from '../alerts/AlertsView';
import { AuthDashboard } from '../dashboard/AuthDashboard';
import { OverviewDashboard } from '../dashboard/OverviewDashboard';
import { WebDashboard } from '../dashboard/WebDashboard';
import { EventExplorer } from '../events/EventExplorer';
import { ReportView } from '../reports/ReportView';
import { RulesView } from '../settings/RulesView';
import { DataSourceView } from '../upload/DataSourceView';
import { FilterBar } from './FilterBar';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

const FILTERED_VIEWS: View[] = ['overview', 'auth', 'web', 'alerts', 'events', 'report'];

function CurrentView({ view, ready }: { view: View; ready: boolean }) {
  if (!ready && view !== 'rules') return <DataSourceView />;
  switch (view) {
    case 'data':
      return <DataSourceView />;
    case 'overview':
      return <OverviewDashboard />;
    case 'auth':
      return <AuthDashboard />;
    case 'web':
      return <WebDashboard />;
    case 'alerts':
      return <AlertsView />;
    case 'events':
      return <EventExplorer />;
    case 'rules':
      return <RulesView />;
    case 'report':
      return <ReportView />;
  }
}

export function AppShell() {
  const { state } = useApp();
  const ready = state.scan.phase === 'ready' && state.summary !== null;
  const mainRef = useRef<HTMLElement>(null);

  // Move focus to the main region on navigation so keyboard and screen-reader users land on the new view.
  useEffect(() => {
    mainRef.current?.focus({ preventScroll: true });
    mainRef.current?.scrollTo?.({ top: 0 });
  }, [state.view]);

  return (
    <DataProvider>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <div className="app">
        <Sidebar />
        <div className="main-col">
          <TopBar />
          {ready && FILTERED_VIEWS.includes(state.view) && <FilterBar />}
          <main id="main" ref={mainRef} tabIndex={-1} className="content">
            <CurrentView view={state.view} ready={ready} />
          </main>
        </div>
      </div>
    </DataProvider>
  );
}
