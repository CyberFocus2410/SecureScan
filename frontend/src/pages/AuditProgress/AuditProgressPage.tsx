import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { CheckCircle2, Clock } from 'lucide-react';
import { getAudit, getAuditEvents, getScannerRuns } from '../../services/api';
import { Audit, AuditEvent, ScannerRun } from '../../types/contracts';

export const AuditProgressPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [audit, setAudit] = useState<Audit | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [scannerRuns, setScannerRuns] = useState<ScannerRun[]>([]);

  useEffect(() => {
    if (!auditId) return;

    const fetchData = async () => {
      try {
        const [auditData, eventsData, runsData] = await Promise.all([
          getAudit(auditId),
          getAuditEvents(auditId),
          getScannerRuns(auditId)
        ]);
        setAudit(auditData);
        setEvents(eventsData);
        setScannerRuns(runsData);
      } catch {
        // silent retry
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 1500);

    return () => clearInterval(interval);
  }, [auditId]);

  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-3.5">
          <img
            src="/logo.jpg"
            alt="SecureScan AI Logo"
            className="w-11 h-11 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 object-cover"
          />
          <div>
            <h1 className="text-2xl font-bold mb-0.5">
              {['COMPLETED', 'PARTIAL', 'REPORT_READY'].includes(audit?.status || '')
                ? 'Audit Complete'
                : audit?.status === 'FAILED'
                ? 'Audit Interrupted'
                : 'Audit in Progress'}
            </h1>
            <p className="text-xs font-mono text-slate-500">ID: {auditId}</p>
          </div>
        </div>
        {audit && ['COMPLETED', 'PARTIAL', 'REPORT_READY'].includes(audit.status) && (
          <div className="flex flex-wrap gap-3">
            <Link to={`/audits/${auditId}/security`} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition">
              View Security Findings
            </Link>
            <Link to={`/audits/${auditId}/dpdp`} className="px-4 py-2 bg-emerald-600 text-white rounded-lg text-sm font-medium hover:bg-emerald-700 transition">
              View DPDP Readiness
            </Link>
            <Link to={`/audits/${auditId}/report`} className="px-4 py-2 bg-slate-800 text-white rounded-lg text-sm font-medium hover:bg-slate-900 transition">
              View Report
            </Link>
          </div>
        )}
        {audit && audit.status === 'FAILED' && (
          <div className="flex flex-wrap gap-3">
            <Link to={`/audits/${auditId}/security`} className="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm font-medium hover:bg-slate-800 transition">
              View Partial Findings
            </Link>
            <Link to="/" className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition">
              New Audit
            </Link>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {scannerRuns.map((run) => (
          <div key={run.id} className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl">
            <div className="flex items-center justify-between mb-3">
              <span className="font-semibold capitalize">{run.scanner}</span>
              <span className="text-xs font-mono text-slate-500">v{run.version}</span>
            </div>
            <div className="flex items-center gap-2 text-sm text-emerald-600 mb-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>{run.status}</span>
            </div>
            <p className="text-xs text-slate-500">{run.findings_count} findings discovered</p>
          </div>
        ))}
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6" role="region" aria-label="Audit Pipeline Events">
        <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-500" aria-hidden="true" />
          <span>Audit Pipeline Events</span>
        </h2>
        <div className="space-y-4 font-mono text-xs" role="status" aria-live="polite" aria-relevant="additions text">
          {events.map((evt, idx) => (
            <div key={idx} className="flex items-start gap-4 pb-3 border-b border-slate-100 dark:border-slate-800 last:border-0">
              <span className="text-slate-400">{evt.timestamp}</span>
              <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 rounded text-slate-700 dark:text-slate-300 font-semibold">{evt.stage}</span>
              <span className="text-slate-600 dark:text-slate-400">{evt.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

