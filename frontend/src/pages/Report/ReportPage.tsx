import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Download, ArrowLeft, Loader2, ShieldCheck, Scale, CheckCircle2, AlertTriangle } from 'lucide-react';
import { createReport, getSessionId } from '../../services/api';

export const ReportPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [downloadingFormat, setDownloadingFormat] = useState<'pdf' | 'json' | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleDownload = async (format: 'pdf' | 'json') => {
    if (!auditId) return;
    setDownloadingFormat(format);
    setErrorMsg(null);

    try {
      // Create report artifact
      const report = await createReport(auditId, format);
      const downloadUrl = `/api/v1/reports/${report.report_id}/download`;

      // Trigger download via fetch with session header
      const res = await fetch(downloadUrl, {
        headers: {
          'X-Session-ID': getSessionId()
        }
      });

      if (!res.ok) {
        throw new Error(`Download failed with status ${res.status}`);
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securescan_report_${auditId.slice(0, 8)}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err: any) {
      console.error('Report download error:', err);
      setErrorMsg(err.message || 'Failed to download report. Please try again.');
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <Link to={`/audits/${auditId}/security`} className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900 mb-6">
        <ArrowLeft className="w-4 h-4" />
        <span>Back to Security Findings</span>
      </Link>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 mb-8 shadow-sm">
        <div className="flex items-center gap-3.5 mb-4">
          <img
            src="/logo.jpg"
            alt="SecureScan AI Logo"
            className="w-10 h-10 rounded-xl shadow-md border border-slate-200 dark:border-slate-700 object-cover"
          />
          <div>
            <h1 className="text-2xl font-bold">Audit Report Export</h1>
            <p className="text-xs font-mono text-slate-500">Audit ID: {auditId}</p>
          </div>
        </div>

        {/* Mandatory Running Header Banner */}
        <div className="p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-xl mb-6 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold mb-0.5">Mandatory Report Classification</p>
            <p>
              Developer-assistance report — not a security certificate or legal opinion.
              All findings include pinned commit SHA, verified tool versions, and honest coverage counts.
            </p>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 mb-6">
            {errorMsg}
          </div>
        )}

        {/* Included Sections Preview */}
        <div className="space-y-4 mb-8">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">Mandatory Report Sections</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>Cover (Repo, SHA, Timestamp, Pinned Tool Versions)</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>Executive Summary (Counts & Coverage, No Grade)</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>Methodology & Sandbox Exclusions (Safety Rules)</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>Redacted Vulnerability Proofs & Technical Fixes</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>OWASP Top 10:2025 / API 2023 / ASVS 5.0.0 Matrix</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
              <span>DPDP Matrix with Dynamic Effective Dates</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <Scale className="w-4 h-4 text-blue-600 flex-shrink-0" />
              <span>Statutory Penalty Reference (Ceilings + Caveats)</span>
            </div>
            <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-600 flex-shrink-0" />
              <span>Prioritized Remediation (Eng / Docs / Org)</span>
            </div>
          </div>
        </div>

        {/* AI Explanation Disclosure */}
        <div className="p-4 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700 rounded-xl mb-8 text-xs text-slate-600 dark:text-slate-400">
          <p className="font-semibold text-slate-900 dark:text-slate-200 mb-1">AI-Assisted Guidance Note</p>
          <p>
            AI explanations provide contextual root cause and developer tips. AI cannot mutate finding severity,
            control states, or legal classifications. Full deterministic remediation is preserved.
          </p>
        </div>

        {/* Export Buttons */}
        <div className="flex flex-col sm:flex-row gap-4">
          <button
            onClick={() => handleDownload('pdf')}
            disabled={downloadingFormat !== null}
            className="flex-1 py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-xl text-center font-medium text-sm flex items-center justify-center gap-2 transition"
          >
            {downloadingFormat === 'pdf' ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Generating PDF Report...</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                <span>Download Audit Report (PDF)</span>
              </>
            )}
          </button>
          <button
            onClick={() => handleDownload('json')}
            disabled={downloadingFormat !== null}
            className="flex-1 py-3 px-4 bg-slate-800 hover:bg-slate-900 disabled:opacity-50 text-white rounded-xl text-center font-medium text-sm flex items-center justify-center gap-2 transition"
          >
            {downloadingFormat === 'json' ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Exporting JSON...</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                <span>Download Machine-Readable (JSON)</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
