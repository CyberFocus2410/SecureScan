import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { CheckCircle2, Clock, ArrowRight } from 'lucide-react';
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

  const isFinished = ['COMPLETED', 'PARTIAL', 'REPORT_READY'].includes(audit?.status || '');

  return (
    <div className="max-w-4xl mx-auto px-4 py-6 sm:py-10">
      {/* Top Header Card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 mb-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <img
              src="/logo.jpg"
              alt="SecureScan AI Logo"
              className="w-12 h-12 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 object-cover flex-shrink-0"
            />
            <div className="min-w-0">
              <h1 className="text-xl sm:text-2xl font-bold mb-0.5 truncate text-slate-900 dark:text-white">
                {isFinished
                  ? 'Audit Complete'
                  : audit?.status === 'FAILED'
                  ? 'Audit Interrupted'
                  : 'Audit in Progress'}
              </h1>
              <p className="text-xs font-mono text-slate-500 truncate">ID: {auditId}</p>
            </div>
          </div>

          {/* Action Links */}
          {audit && isFinished && (
            <div className="flex flex-col sm:flex-row gap-2 sm:gap-2.5 w-full sm:w-auto">
              <Link
                to={`/audits/${auditId}/security`}
                className="w-full sm:w-auto px-4 py-2.5 bg-blue-600 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-blue-700 active:bg-blue-800 transition text-center shadow-xs flex items-center justify-center gap-1.5"
              >
                <span>View Security</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
              <Link
                to={`/audits/${auditId}/dpdp`}
                className="w-full sm:w-auto px-4 py-2.5 bg-emerald-600 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-emerald-700 active:bg-emerald-800 transition text-center shadow-xs flex items-center justify-center gap-1.5"
              >
                <span>View DPDP</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
              <Link
                to={`/audits/${auditId}/report`}
                className="w-full sm:w-auto px-4 py-2.5 bg-slate-800 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-slate-700 active:bg-slate-900 transition text-center shadow-xs"
              >
                Report
              </Link>
            </div>
          )}

          {audit && audit.status === 'FAILED' && (
            <div className="flex flex-col sm:flex-row gap-2 sm:gap-2.5 w-full sm:w-auto">
              <Link
                to={`/audits/${auditId}/security`}
                className="w-full sm:w-auto px-4 py-2.5 bg-slate-700 text-white rounded-xl text-xs sm:text-sm font-medium hover:bg-slate-800 transition text-center"
              >
                View Partial Findings
              </Link>
              <Link
                to="/"
                className="w-full sm:w-auto px-4 py-2.5 bg-blue-600 text-white rounded-xl text-xs sm:text-sm font-medium hover:bg-blue-700 transition text-center"
              >
                New Audit
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Scanner Runs Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 sm:gap-4 mb-6">
        {scannerRuns.map((run) => (
          <div key={run.id} className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
            <div className="flex items-center justify-between mb-2">
              <span className="font-semibold text-sm capitalize text-slate-900 dark:text-white">{run.scanner}</span>
              <span className="text-[11px] font-mono text-slate-500">v{run.version}</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 mb-1 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{run.status}</span>
            </div>
            <p className="text-xs text-slate-500">{run.findings_count} findings discovered</p>
          </div>
        ))}
      </div>

      {/* Pipeline Events Log */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xs" role="region" aria-label="Audit Pipeline Events">
        <h2 className="text-sm sm:text-base font-bold mb-4 flex items-center gap-2 text-slate-900 dark:text-white">
          <Clock className="w-4 h-4 text-blue-500" aria-hidden="true" />
          <span>Audit Pipeline Events</span>
        </h2>
        <div className="space-y-3 font-mono text-xs">
          {events.length === 0 ? (
            <div className="text-slate-400 py-4 text-center">Waiting for pipeline events...</div>
          ) : (
            events.map((event, idx) => (
              <div
                key={`${event.timestamp}-${idx}`}
                className="flex flex-col sm:flex-row sm:items-start gap-1.5 sm:gap-3 p-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200/70 dark:border-slate-800"
              >
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-[11px] text-slate-400">
                    {new Date(event.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                    event.stage === 'ERROR' || event.stage === 'FAILED'
                      ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                      : event.stage === 'COMPLETED'
                      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      : 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                  }`}>
                    {event.stage}
                  </span>
                </div>
                <p className="text-slate-700 dark:text-slate-300 break-words flex-1 leading-relaxed">
                  {event.message}
                </p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
export default AuditProgressPage;
