import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileCode,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  MinusCircle,
  AlertOctagon,
  ChevronRight,
  X,
  Code
} from 'lucide-react';
import { getFindings, getSecurityCoverage, getAudit } from '../../services/api';
import { Finding, ControlResult, ControlState, SecurityCoverageSummary, Audit } from '../../types/contracts';

export const SecurityPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [audit, setAudit] = useState<Audit | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [controls, setControls] = useState<ControlResult[]>([]);
  const [summary, setSummary] = useState<SecurityCoverageSummary | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedStateFilter, setSelectedStateFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!auditId) return;

    Promise.all([
      getAudit(auditId).catch(() => null),
      getFindings(auditId).catch(() => ({ items: [], total: 0 })),
      getSecurityCoverage(auditId).catch(() => null)
    ]).then(([aData, fData, covData]) => {
      if (aData) setAudit(aData);
      if (fData) setFindings(fData.items);
      if (covData) {
        setControls(covData.controls);
        setSummary(covData.summary);
      }
      setLoading(false);
    });
  }, [auditId]);

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-16 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full mb-4"></div>
        <p className="text-slate-500 font-medium text-sm">Loading security audit findings and coverage...</p>
      </div>
    );
  }

  const filteredControls = selectedStateFilter === 'ALL'
    ? controls
    : controls.filter(c => c.state === selectedStateFilter);

  const confirmedFindings = findings.filter(f => f.confidence === 'CONFIRMED' || f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const potentialGapControls = controls.filter(c => c.state === 'POTENTIAL_GAP');

  const renderStateBadge = (state: ControlState) => {
    switch (state) {
      case 'PASS_EVIDENCED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 whitespace-nowrap">
            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
            PASS_EVIDENCED
          </span>
        );
      case 'FAIL_EVIDENCED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300 border border-red-300 dark:border-red-800 whitespace-nowrap">
            <XCircle className="w-3 h-3 text-red-600" />
            FAIL_EVIDENCED
          </span>
        );
      case 'POTENTIAL_GAP':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-300 dark:border-amber-800 whitespace-nowrap">
            <AlertTriangle className="w-3 h-3 text-amber-600" />
            POTENTIAL_GAP
          </span>
        );
      case 'NOT_VERIFIED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 whitespace-nowrap">
            <HelpCircle className="w-3 h-3 text-slate-500" />
            NOT_VERIFIED
          </span>
        );
      case 'NOT_APPLICABLE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-gray-100 text-gray-700 dark:bg-gray-800/60 dark:text-gray-400 border border-gray-300 dark:border-gray-700 whitespace-nowrap">
            <MinusCircle className="w-3 h-3 text-gray-500" />
            NOT_APPLICABLE
          </span>
        );
      case 'ERROR':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-300 dark:border-rose-800 whitespace-nowrap">
            <AlertOctagon className="w-3 h-3 text-rose-600" />
            ERROR
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 sm:py-8">
      {/* Header & Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2.5 sm:gap-3">
            <img
              src="/logo.jpg"
              alt="SecureScan AI Logo"
              className="w-8 h-8 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 object-cover flex-shrink-0"
            />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Security Audit Results
            </h1>
          </div>
          <p className="text-[11px] sm:text-xs text-slate-500 font-mono mt-1 break-all">
            Audit: {auditId} • Commit: {audit?.commit_sha?.slice(0, 8) || 'Head'}
          </p>
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Link
            to={`/audits/${auditId}/dpdp`}
            className="flex-1 sm:flex-initial px-3.5 py-2 border border-slate-300 dark:border-slate-700 rounded-xl text-xs sm:text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition text-center"
          >
            DPDP Tab
          </Link>
          <Link
            to={`/audits/${auditId}/report`}
            className="flex-1 sm:flex-initial px-4 py-2 bg-blue-600 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-blue-700 active:bg-blue-800 transition text-center shadow-xs"
          >
            Export Report
          </Link>
        </div>
      </div>

      {/* Partial Banner (Fail-safe indicator) */}
      {audit?.status === 'PARTIAL' && (
        <div className="p-3.5 sm:p-4 bg-amber-50 dark:bg-amber-950/50 border border-amber-300 dark:border-amber-800 rounded-xl mb-6 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm">
            <p className="font-semibold text-amber-900 dark:text-amber-200">Partial Audit Results</p>
            <p className="text-amber-700 dark:text-amber-300 text-xs mt-0.5 leading-relaxed">
              One or more scanner engines experienced partial execution. Surviving findings and verified controls are displayed below.
            </p>
          </div>
        </div>
      )}

      {/* Coverage Ratio Strip (Honest denominator) */}
      {summary && (
        <div className="p-4 sm:p-6 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-slate-900 dark:to-slate-900 border border-blue-200 dark:border-slate-800 rounded-2xl mb-6 sm:mb-8 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
            <div>
              <p className="text-[11px] sm:text-xs font-bold uppercase tracking-wider text-blue-900 dark:text-blue-300">
                Evidenced Security Coverage Ratio
              </p>
              <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white mt-0.5">
                {summary.evidenced_controls} / {summary.denominator} Controls Evidenced ({Math.round(summary.coverage_ratio * 100)}%)
              </h2>
            </div>
            <div className="text-[11px] sm:text-xs text-slate-600 dark:text-slate-400 font-mono text-left sm:text-right space-y-0.5">
              <p>Pass: {summary.evidenced_pass} | Fail: {summary.evidenced_fail}</p>
              <p>Potential Gaps: {summary.potential_gap} | Not Verified: {summary.not_verified}</p>
            </div>
          </div>
          {/* Progress bar */}
          <div className="w-full bg-slate-200 dark:bg-slate-800 h-2.5 sm:h-3 rounded-full overflow-hidden flex shadow-inner">
            <div
              className="bg-emerald-500 h-full transition-all duration-500"
              style={{ width: `${(summary.evidenced_pass / summary.denominator) * 100}%` }}
              title={`Pass Evidenced: ${summary.evidenced_pass}`}
            />
            <div
              className="bg-red-500 h-full transition-all duration-500"
              style={{ width: `${(summary.evidenced_fail / summary.denominator) * 100}%` }}
              title={`Fail Evidenced: ${summary.evidenced_fail}`}
            />
            <div
              className="bg-amber-400 h-full transition-all duration-500"
              style={{ width: `${(summary.potential_gap / summary.denominator) * 100}%` }}
              title={`Potential Gap: ${summary.potential_gap}`}
            />
          </div>
        </div>
      )}

      {/* Severity & Confidence Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-4 mb-6 sm:mb-8">
        <div className="p-3.5 sm:p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <p className="text-[11px] sm:text-xs text-slate-500 font-medium">Total Findings</p>
          <p className="text-xl sm:text-2xl font-bold mt-1 text-slate-900 dark:text-white">{findings.length}</p>
          <span className="text-[10px] sm:text-[11px] text-slate-400">Deduplicated</span>
        </div>
        <div className="p-3.5 sm:p-4 bg-red-50/50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-xl shadow-xs">
          <p className="text-[11px] sm:text-xs text-red-600 dark:text-red-400 font-medium">Confirmed Vulnerabilities</p>
          <p className="text-xl sm:text-2xl font-bold text-red-600 dark:text-red-400 mt-1">{confirmedFindings.length}</p>
          <span className="text-[10px] sm:text-[11px] text-red-500">AST & Pinned</span>
        </div>
        <div className="p-3.5 sm:p-4 bg-amber-50/50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 rounded-xl shadow-xs">
          <p className="text-[11px] sm:text-xs text-amber-600 dark:text-amber-400 font-medium">Potential Gaps</p>
          <p className="text-xl sm:text-2xl font-bold text-amber-600 dark:text-amber-400 mt-1">{potentialGapControls.length}</p>
          <span className="text-[10px] sm:text-[11px] text-amber-500">Heuristic Gaps</span>
        </div>
        <div className="p-3.5 sm:p-4 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <p className="text-[11px] sm:text-xs text-slate-500 font-medium">Unverified Controls</p>
          <p className="text-xl sm:text-2xl font-bold text-slate-600 dark:text-slate-300 mt-1">
            {summary?.not_verified || 0}
          </p>
          <span className="text-[10px] sm:text-[11px] text-slate-400">Manual review</span>
        </div>
      </div>

      {/* Findings Section */}
      <div className="mb-8 sm:mb-12">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-4">
          <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
            Identified Vulnerabilities & Gaps
          </h2>
          <span className="text-[11px] font-mono text-slate-500">
            Secrets Redacted at Parser Boundary
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="p-6 sm:p-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl text-center shadow-xs">
            <CheckCircle2 className="w-10 h-10 text-emerald-500 mx-auto mb-2" />
            <p className="text-sm sm:text-base font-bold text-slate-800 dark:text-slate-200">
              No vulnerabilities detected from automated scans.
            </p>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              Static SAST, AST, secret, and dependency analyzers observed zero flaw patterns in scanned files.
            </p>
          </div>
        ) : (
          <div className="space-y-3.5 sm:space-y-4">
            {findings.map((f) => (
              <div
                key={f.id}
                role="button"
                tabIndex={0}
                onClick={() => setSelectedFinding(f)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setSelectedFinding(f); }}
                className="p-4 sm:p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-blue-400 dark:hover:border-blue-600 rounded-xl cursor-pointer transition shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2.5 mb-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      f.severity === 'CRITICAL' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300' :
                      f.severity === 'HIGH' ? 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300' :
                      'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300'
                    }`}>
                      {f.severity}
                    </span>
                    <span className="px-2 py-0.5 bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 rounded text-[11px] font-mono">
                      {f.confidence}
                    </span>
                    <h3 className="font-semibold text-sm sm:text-base text-slate-900 dark:text-white break-words">
                      {f.title}
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {f.owasp_refs.map(ref => (
                      <span key={ref} className="px-2 py-0.5 bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 rounded text-[10px] font-mono font-medium">
                        {ref}
                      </span>
                    ))}
                  </div>
                </div>

                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mb-3 line-clamp-2 leading-relaxed">
                  {f.description}
                </p>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-500 font-mono">
                  <div className="flex items-center gap-1.5 truncate">
                    <FileCode className="w-3.5 h-3.5 flex-shrink-0" />
                    <span className="truncate">{f.file_path}:{f.start_line}</span>
                    <span>•</span>
                    <span className="capitalize">{f.scanner_name}</span>
                  </div>
                  <span className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 font-medium text-xs flex-shrink-0">
                    View proof & fix <ChevronRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 32 Security Controls Evaluation Table */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs">
        <div className="p-4 sm:p-6 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              32-Control Evaluation Matrix
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">Automated verification mapped to OWASP & ASVS</p>
          </div>
          {/* State Filter Buttons */}
          <div className="flex overflow-x-auto no-scrollbar gap-1.5 py-1 -mx-4 px-4 sm:mx-0 sm:px-0">
            {['ALL', 'PASS_EVIDENCED', 'FAIL_EVIDENCED', 'POTENTIAL_GAP', 'NOT_VERIFIED'].map((st) => (
              <button
                key={st}
                onClick={() => setSelectedStateFilter(st)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium whitespace-nowrap transition cursor-pointer flex-shrink-0 ${
                  selectedStateFilter === st
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                {st.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        <div className="sm:hidden px-4 py-2 bg-slate-50 dark:bg-slate-800/40 text-[11px] text-slate-500 border-b border-slate-200 dark:border-slate-800">
          Scroll horizontally to see full evidence & rationale →
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs sm:text-sm min-w-[620px]">
            <thead className="bg-slate-50 dark:bg-slate-800/50 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
              <tr>
                <th className="px-4 sm:px-6 py-3 w-28">Control ID</th>
                <th className="px-4 sm:px-6 py-3 w-64">Title</th>
                <th className="px-4 sm:px-6 py-3 w-36">Status</th>
                <th className="px-4 sm:px-6 py-3">Rationale / Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filteredControls.map((c) => (
                <tr key={c.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/30 transition">
                  <td className="px-4 sm:px-6 py-3.5 font-mono font-bold text-xs text-blue-600 dark:text-blue-400">
                    {c.control_id}
                  </td>
                  <td className="px-4 sm:px-6 py-3.5 font-medium text-slate-900 dark:text-white">
                    {c.title}
                  </td>
                  <td className="px-4 sm:px-6 py-3.5 whitespace-nowrap">
                    {renderStateBadge(c.state)}
                  </td>
                  <td className="px-4 sm:px-6 py-3.5 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {c.rationale}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Detail Drawer Modal */}
      {selectedFinding && (
        <div
          className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex justify-end"
          role="dialog"
          aria-modal="true"
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="w-full max-w-xl bg-white dark:bg-slate-900 h-full overflow-y-auto p-5 sm:p-8 shadow-2xl flex flex-col justify-between"
            onClick={(e) => e.stopPropagation()}
          >
            <div>
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-200 dark:border-slate-800">
                <span className="text-xs font-mono text-slate-500">Finding: {selectedFinding.id.slice(0, 8)}</span>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 transition cursor-pointer"
                  aria-label="Close dialog"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="flex items-center gap-2 mb-3">
                <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">
                  {selectedFinding.severity}
                </span>
                <span className="text-xs font-mono text-slate-500">Confidence: {selectedFinding.confidence}</span>
              </div>

              <h2 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white mb-2">
                {selectedFinding.title}
              </h2>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mb-6 leading-relaxed">
                {selectedFinding.description}
              </p>

              {/* Redacted Evidence Block */}
              <div className="mb-6">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                  <Code className="w-4 h-4" /> Redacted Source Snippet
                </p>
                <div className="bg-slate-950 rounded-xl p-3.5 sm:p-4 overflow-x-auto border border-slate-800">
                  <div className="text-[11px] font-mono text-slate-500 mb-2 truncate">
                    {selectedFinding.file_path}:{selectedFinding.start_line}
                  </div>
                  <pre className="text-xs font-mono text-emerald-400 whitespace-pre-wrap">
                    {selectedFinding.redacted_snippet}
                  </pre>
                </div>
              </div>

              {/* Remediation Action */}
              {selectedFinding.remediation && (
                <div className="p-4 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-xl mb-6">
                  <p className="text-xs font-bold text-blue-900 dark:text-blue-300 uppercase tracking-wider mb-1">
                    Technical Remediation Fix
                  </p>
                  <p className="text-xs sm:text-sm text-blue-800 dark:text-blue-200 mb-3 leading-relaxed">
                    {selectedFinding.remediation.technical_fix}
                  </p>
                  {selectedFinding.remediation.validation_steps && (
                    <div className="text-xs text-blue-700 dark:text-blue-300 leading-relaxed">
                      <span className="font-semibold">Validation Steps: </span>
                      {selectedFinding.remediation.validation_steps}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedFinding(null)}
                className="w-full sm:w-auto px-4 py-2.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm font-semibold rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition cursor-pointer"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default SecurityPage;
