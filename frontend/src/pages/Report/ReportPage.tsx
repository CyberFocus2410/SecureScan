import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Download,
  ArrowLeft,
  AlertTriangle,
  Copy,
  Check,
  Terminal
} from 'lucide-react';
import {
  createReport,
  getSessionId,
  getSarifReport,
  getMarkdownReport,
  getFixPack
} from '../../services/api';

export const ReportPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedFixPack, setCopiedFixPack] = useState(false);

  const handleDownload = async (format: 'pdf' | 'json') => {
    if (!auditId) return;
    setDownloadingFormat(format);
    setErrorMsg(null);

    try {
      const report = await createReport(auditId, format);
      const downloadUrl = `/api/v1/reports/${report.report_id}/download`;

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

  const handleDownloadSarif = async () => {
    if (!auditId) return;
    try {
      setDownloadingFormat('sarif');
      const sarifText = await getSarifReport(auditId);
      const blob = new Blob([sarifText], { type: 'application/sarif+json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securescan_${auditId.slice(0, 8)}.sarif`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to download SARIF report.');
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleDownloadMarkdown = async () => {
    if (!auditId) return;
    try {
      setDownloadingFormat('md');
      const mdText = await getMarkdownReport(auditId);
      const blob = new Blob([mdText], { type: 'text/markdown' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securescan_report_${auditId.slice(0, 8)}.md`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to download Markdown report.');
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleDownloadFixPack = async (format: 'markdown' | 'json') => {
    if (!auditId) return;
    try {
      setDownloadingFormat(`fixpack-${format}`);
      const pack = await getFixPack(auditId, format);
      const content = typeof pack === 'string' ? pack : JSON.stringify(pack, null, 2);
      const mime = format === 'markdown' ? 'text/markdown' : 'application/json';
      const ext = format === 'markdown' ? 'md' : 'json';
      const blob = new Blob([content], { type: mime });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fixpack-${auditId.slice(0, 8)}.${ext}`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to download Fix Pack.');
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleCopyFixPack = async () => {
    if (!auditId) return;
    try {
      const packMd = await getFixPack(auditId, 'markdown');
      await navigator.clipboard.writeText(packMd);
      setCopiedFixPack(true);
      setTimeout(() => setCopiedFixPack(false), 2500);
    } catch (err: any) {
      alert(`Failed to copy Fix Pack: ${err.message}`);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <Link to={`/audits/${auditId}/security`} className="inline-flex items-center gap-1.5 text-xs sm:text-sm font-semibold text-slate-500 hover:text-slate-900 dark:hover:text-white mb-6">
        <ArrowLeft className="w-4 h-4" />
        <span>Back to Security Findings</span>
      </Link>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 mb-8 shadow-xs">
        <div className="flex items-center gap-3.5 mb-4">
          <img
            src="/logo.jpg"
            alt="SecureScan AI Logo"
            className="w-10 h-10 rounded-xl shadow-md border border-slate-200 dark:border-slate-700 object-cover"
          />
          <div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">Multi-Format Report Center</h1>
            <p className="text-xs font-mono text-slate-500">Scan ID: {auditId}</p>
          </div>
        </div>

        {/* Mandatory Running Header Banner */}
        <div className="p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-xl mb-6 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold mb-0.5">Mandatory Report Classification</p>
            <p>
              Developer-assistance report — not a penetration test, legal opinion, or compliance certificate.
              All findings include pinned commit SHA, verified tool versions, and honest coverage counts.
            </p>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 mb-6">
            {errorMsg}
          </div>
        )}

        {/* Fix Pack Hero Section */}
        <div className="p-5 bg-blue-50/60 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900/50 rounded-2xl mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Terminal className="w-5 h-5 text-blue-600" />
                <h2 className="text-sm sm:text-base font-bold text-blue-950 dark:text-blue-100">
                  Agent-Ready Fix Pack (Step 12 & §8.5)
                </h2>
              </div>
              <p className="text-xs text-blue-900/80 dark:text-blue-200/80 max-w-xl leading-relaxed">
                Hand this file directly to Antigravity, Claude Code, Cursor, or your developers. Contains prioritized checklists, verified patches, and acceptance test commands.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={handleCopyFixPack}
                className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition shadow-xs cursor-pointer"
              >
                {copiedFixPack ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-300" />
                    <span>Copied to Clipboard!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Fix Pack</span>
                  </>
                )}
              </button>

              <button
                onClick={() => handleDownloadFixPack('markdown')}
                className="px-3.5 py-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>fixpack.md</span>
              </button>
            </div>
          </div>
        </div>

        {/* Export Formats Grid */}
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
          Available Export Formats
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-8">
          {/* 1. PDF */}
          <button
            onClick={() => handleDownload('pdf')}
            disabled={downloadingFormat !== null}
            className="p-4 bg-slate-50 dark:bg-slate-800/40 hover:bg-blue-50/50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl text-left transition flex items-center justify-between group cursor-pointer"
          >
            <div>
              <p className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white">Audit Report (PDF)</p>
              <p className="text-[11px] text-slate-500">Executive & Technical auditor-grade PDF</p>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-600 transition" />
          </button>

          {/* 2. Developer Markdown */}
          <button
            onClick={handleDownloadMarkdown}
            disabled={downloadingFormat !== null}
            className="p-4 bg-slate-50 dark:bg-slate-800/40 hover:bg-blue-50/50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl text-left transition flex items-center justify-between group cursor-pointer"
          >
            <div>
              <p className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white">Developer Markdown (.md)</p>
              <p className="text-[11px] text-slate-500">Clean markdown for repo check-in & wikis</p>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-600 transition" />
          </button>

          {/* 3. SARIF 2.1.0 */}
          <button
            onClick={handleDownloadSarif}
            disabled={downloadingFormat !== null}
            className="p-4 bg-slate-50 dark:bg-slate-800/40 hover:bg-blue-50/50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl text-left transition flex items-center justify-between group cursor-pointer"
          >
            <div>
              <p className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white">SARIF 2.1.0 (.sarif)</p>
              <p className="text-[11px] text-slate-500">Standard for GitHub Code Scanning upload</p>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-600 transition" />
          </button>

          {/* 4. JSON */}
          <button
            onClick={() => handleDownload('json')}
            disabled={downloadingFormat !== null}
            className="p-4 bg-slate-50 dark:bg-slate-800/40 hover:bg-blue-50/50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl text-left transition flex items-center justify-between group cursor-pointer"
          >
            <div>
              <p className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white">Machine JSON (.json)</p>
              <p className="text-[11px] text-slate-500">Raw structured data for CI/CD pipelines</p>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-600 transition" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReportPage;
