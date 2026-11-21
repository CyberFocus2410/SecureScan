import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  CheckCircle2,
  Clock,
  ArrowRight,
  StopCircle,
  Cpu,
  Globe,
  KeyRound,
  FileCheck2,
  Layers
} from 'lucide-react';
import { getAudit, getAuditEvents, getScannerRuns, cancelAudit } from '../../services/api';
import { Audit, AuditEvent, ScannerRun } from '../../types/contracts';

export const AuditProgressPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [audit, setAudit] = useState<Audit | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [scannerRuns, setScannerRuns] = useState<ScannerRun[]>([]);
  const [cancelling, setCancelling] = useState(false);

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
        // silent retry on network hiccup
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 1500);

    return () => clearInterval(interval);
  }, [auditId]);

  const handleCancelAudit = async () => {
    if (!auditId) return;
    if (!confirm('Are you sure you want to abort the active security scan pipeline?')) return;
    try {
      setCancelling(true);
      await cancelAudit(auditId);
      const auditData = await getAudit(auditId);
      setAudit(auditData);
    } catch (err: any) {
      alert(`Failed to cancel audit: ${err.message || 'Unknown error'}`);
    } finally {
      setCancelling(false);
    }
  };

  const isFinished = ['COMPLETED', 'PARTIAL', 'REPORT_READY'].includes(audit?.status || '');
  const isFailed = audit?.status === 'FAILED';

  // Multi-engine stages status indicator
  const stages = [
    { id: 'STATIC', name: 'Static Worker', icon: Cpu, desc: 'SAST, Secrets, IaC, DB & AI' },
    { id: 'DAST', name: 'DAST Worker', icon: Globe, desc: 'Crawler, TLS, Headers, CORS' },
    { id: 'AUTHZ', name: 'API & Auth Matrix', icon: KeyRound, desc: 'BOLA, BFLA, Multi-Account' },
    { id: 'DPDP', name: 'DPDP Engine', icon: FileCheck2, desc: 'PII, Processors, S.33 Ceilings' },
    { id: 'RISK', name: 'Risk & Fix Pack', icon: Layers, desc: 'Attack Chains, SARIF, Fix Pack' },
  ];

  return (
    <div className="max-w-5xl mx-auto px-4 py-6 sm:py-10">
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
              <div className="flex items-center gap-2 mb-0.5">
                <h1 className="text-xl sm:text-2xl font-bold truncate text-slate-900 dark:text-white">
                  {isFinished
                    ? 'Audit Complete'
                    : isFailed
                    ? 'Audit Aborted / Interrupted'
                    : 'Security Audit in Progress'}
                </h1>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                  isFinished
                    ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                    : isFailed
                    ? 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300'
                    : 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 animate-pulse'
                }`}>
                  {audit?.status || 'QUEUED'}
                </span>
              </div>
              <p className="text-xs font-mono text-slate-500 truncate">Scan ID: {auditId}</p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 sm:gap-2.5">
            {!isFinished && !isFailed && (
              <button
                onClick={handleCancelAudit}
                disabled={cancelling}
                className="px-3.5 py-2 bg-red-50 hover:bg-red-100 dark:bg-red-950/40 dark:hover:bg-red-900/50 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
              >
                <StopCircle className="w-3.5 h-3.5" />
                <span>{cancelling ? 'Aborting...' : 'Kill-Switch / Cancel'}</span>
              </button>
            )}

            {isFinished && (
              <>
                <Link
                  to={`/audits/${auditId}/security`}
                  className="px-4 py-2.5 bg-blue-600 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-blue-700 transition flex items-center gap-1.5 shadow-xs"
                >
                  <span>Results Dashboard</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                <Link
                  to={`/audits/${auditId}/dpdp`}
                  className="px-4 py-2.5 bg-emerald-600 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-emerald-700 transition flex items-center gap-1.5 shadow-xs"
                >
                  <span>DPDP Readiness</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                <Link
                  to={`/audits/${auditId}/report`}
                  className="px-4 py-2.5 bg-slate-800 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-slate-700 transition shadow-xs"
                >
                  Export Report
                </Link>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Multi-Engine Pipeline Stage Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 mb-6">
        {stages.map((st, i) => {
          const Icon = st.icon;
          const completedCount = scannerRuns.filter(r => r.status === 'COMPLETED').length;
          const isDone = isFinished || completedCount >= (i + 1);
          return (
            <div
              key={st.id}
              className={`p-3.5 rounded-xl border transition ${
                isDone
                  ? 'bg-white dark:bg-slate-900 border-emerald-300 dark:border-emerald-800 shadow-2xs'
                  : 'bg-slate-50 dark:bg-slate-800/40 border-slate-200 dark:border-slate-800 opacity-80'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <Icon className={`w-4 h-4 ${isDone ? 'text-emerald-600' : 'text-slate-400'}`} />
                {isDone ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                ) : (
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                )}
              </div>
              <p className="text-xs font-bold text-slate-900 dark:text-white truncate">{st.name}</p>
              <p className="text-[10px] text-slate-500 truncate">{st.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Scanner Runs Detail */}
      {scannerRuns.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 mb-6">
          {scannerRuns.map((run) => (
            <div key={run.id} className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-semibold text-xs sm:text-sm capitalize text-slate-900 dark:text-white truncate">{run.scanner}</span>
                <span className="text-[10px] font-mono text-slate-400">v{run.version}</span>
              </div>
              <div className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 mb-1 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{run.status}</span>
              </div>
              <p className="text-xs text-slate-500">{run.findings_count} findings discovered</p>
            </div>
          ))}
        </div>
      )}

      {/* Real-Time Pipeline Events Log */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xs" role="region" aria-label="Audit Pipeline Events">
        <h2 className="text-sm sm:text-base font-bold mb-4 flex items-center gap-2 text-slate-900 dark:text-white">
          <Clock className="w-4 h-4 text-blue-500" />
          <span>Real-Time Audit Timeline</span>
        </h2>
        <div className="space-y-2.5 font-mono text-xs max-h-96 overflow-y-auto pr-1">
          {events.length === 0 ? (
            <div className="text-slate-400 py-6 text-center text-xs">Waiting for scanner pipeline events...</div>
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
                <p className="text-slate-700 dark:text-slate-300 break-words flex-1 leading-relaxed text-[11px] sm:text-xs">
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
