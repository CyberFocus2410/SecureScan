import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  Copy,
  Check,
  GitPullRequest,
  AlertOctagon,
  Clock,
  Sparkles,
  Code2,
  Terminal,
  FileText
} from 'lucide-react';
import { getFindingDetail, createFindingFixPr } from '../../services/api';
import { Finding } from '../../types/contracts';

export const FindingDetailPage: React.FC = () => {
  const { findingId } = useParams<{ findingId: string }>();
  const navigate = useNavigate();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [creatingPr, setCreatingPr] = useState(false);
  const [prResult, setPrResult] = useState<{ branch_name?: string; message?: string } | null>(null);

  useEffect(() => {
    if (!findingId) return;
    setLoading(true);
    getFindingDetail(findingId)
      .then((data) => {
        setFinding(data);
        setError(null);
      })
      .catch((err) => {
        console.error('Failed to load finding details:', err);
        setError('Finding not found or access denied for this session.');
      })
      .finally(() => setLoading(false));
  }, [findingId]);

  const handleCopyPrompt = () => {
    if (!finding) return;
    const promptText = finding.fix_prompt || `You are fixing a security issue found by SecureScan.
Rule: ${finding.rule_id} (${finding.severity})
File: ${finding.file_path} (Lines ${finding.start_line}-${finding.end_line})
Issue: ${finding.plain_summary || finding.description}
Fix Steps:
${finding.how_to_fix || finding.remediation?.technical_fix || 'Apply secure coding best practice.'}
Acceptance Test:
${finding.how_to_verify_fix || finding.remediation?.validation_steps || 'Re-run unit tests.'}

Rules:
1. Make the smallest safe change.
2. Never hardcode secrets.
3. Verify the fix without breaking existing tests.`;

    navigator.clipboard.writeText(promptText);
    setCopiedPrompt(true);
    setTimeout(() => setCopiedPrompt(false), 2500);
  };

  const handleCreatePr = async () => {
    if (!finding) return;
    try {
      setCreatingPr(true);
      const res = await createFindingFixPr(finding.id);
      setPrResult(res);
    } catch (err: any) {
      alert(`Failed to create fix PR: ${err.message || 'Unknown error'}`);
    } finally {
      setCreatingPr(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full mb-4"></div>
        <p className="text-slate-500 font-medium text-sm">Loading verified finding details...</p>
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="p-6 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 rounded-2xl max-w-md mx-auto mb-6">
          <AlertOctagon className="w-8 h-8 text-red-600 mx-auto mb-2" />
          <h2 className="text-base font-bold text-red-900 dark:text-red-200 mb-1">Finding Not Found</h2>
          <p className="text-xs text-red-700 dark:text-red-300">{error || 'Unable to retrieve finding.'}</p>
        </div>
        <button
          onClick={() => navigate(-1)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 text-white rounded-xl text-xs font-semibold hover:bg-slate-700"
        >
          <ArrowLeft className="w-4 h-4" /> Go Back
        </button>
      </div>
    );
  }

  const priorityColor = {
    P0: 'bg-red-100 text-red-800 dark:bg-red-950/70 dark:text-red-300 border-red-300 dark:border-red-800',
    P1: 'bg-orange-100 text-orange-800 dark:bg-orange-950/70 dark:text-orange-300 border-orange-300 dark:border-orange-800',
    P2: 'bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 border-amber-300 dark:border-amber-800',
    P3: 'bg-blue-100 text-blue-800 dark:bg-blue-950/70 dark:text-blue-300 border-blue-300 dark:border-blue-800',
  }[finding.priority || 'P2'];

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      {/* Back button */}
      <button
        onClick={() => navigate(-1)}
        className="inline-flex items-center gap-1.5 text-xs sm:text-sm font-semibold text-slate-500 hover:text-slate-900 dark:hover:text-white mb-6 transition"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Back to Audit Results</span>
      </button>

      {/* Main Finding Card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs mb-8">
        {/* Header badges */}
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-4 border-b border-slate-100 dark:border-slate-800">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold border ${priorityColor}`}>
              {finding.priority || 'P2'} · {finding.severity}
            </span>
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
              <Shield className="w-3 h-3 text-blue-500" />
              {finding.confidence}
            </span>
            {finding.engine && (
              <span className="px-2.5 py-1 rounded-md text-xs font-mono bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                engine: {finding.engine}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>ID: {finding.id.slice(0, 8)}</span>
            <span>·</span>
            <span>rule: {finding.rule_id}</span>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white mb-2 leading-tight">
          {finding.plain_title || finding.title}
        </h1>

        {/* Location Banner */}
        <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl text-xs font-mono mb-6 text-slate-700 dark:text-slate-300 flex items-center justify-between">
          <div className="truncate">
            <span className="text-slate-400">Where: </span>
            <span className="font-semibold">{finding.file_path}</span>
            {finding.start_line && (
              <span className="text-blue-600 dark:text-blue-400"> (lines {finding.start_line} - {finding.end_line})</span>
            )}
          </div>
          {finding.fix_effort && (
            <div className="flex items-center gap-1 text-slate-500 flex-shrink-0 ml-2">
              <Clock className="w-3.5 h-3.5" />
              <span>Effort: {finding.fix_effort}</span>
            </div>
          )}
        </div>

        {/* Plain Language Sections (§8.3) */}
        <div className="space-y-6 text-sm">
          {/* 1. What we found */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-blue-600" />
              What We Found
            </h3>
            <p className="text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-100 dark:border-slate-800">
              {finding.plain_summary || finding.description}
            </p>
          </div>

          {/* 2. Why it matters */}
          {finding.why_it_matters && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400 mb-1.5 flex items-center gap-1.5">
                <AlertOctagon className="w-3.5 h-3.5" />
                Why It Matters & Impact
              </h3>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed bg-amber-50/50 dark:bg-amber-950/20 p-4 rounded-xl border border-amber-200 dark:border-amber-900/50">
                {finding.why_it_matters}
              </p>
            </div>
          )}

          {/* 3. Redacted Evidence Snippet */}
          {finding.redacted_snippet && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-indigo-500" />
                Redacted Technical Evidence
              </h3>
              <div className="relative">
                <pre className="p-4 bg-slate-950 text-slate-200 rounded-xl font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800">
                  {finding.redacted_snippet}
                </pre>
                <div className="absolute top-2 right-2 text-[10px] font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded">
                  parser-level masked
                </div>
              </div>
            </div>
          )}

          {/* 4. How to Fix */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 mb-1.5 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              How to Fix (Ordered Steps)
            </h3>
            <div className="p-4 bg-emerald-50/50 dark:bg-emerald-950/20 rounded-xl border border-emerald-200 dark:border-emerald-900/50 text-emerald-950 dark:text-emerald-200 space-y-2">
              <p className="whitespace-pre-line leading-relaxed text-xs sm:text-sm">
                {finding.how_to_fix || finding.remediation?.technical_fix || 'Review affected code block and apply input validation, authentication checks, or security configuration.'}
              </p>
            </div>
          </div>

          {/* 5. How to Check it is Fixed */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">
              How to Verify It Is Fixed
            </h3>
            <div className="p-4 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-100 dark:border-slate-800 text-slate-700 dark:text-slate-300 text-xs sm:text-sm">
              <p className="leading-relaxed">
                {finding.how_to_verify_fix || finding.remediation?.validation_steps || 'Re-run SecureScan or project automated unit tests. This finding must disappear from results.'}
              </p>
            </div>
          </div>

          {/* Standards & References Badges */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
              Industry Standards & Legal Safeguards
            </h3>
            <div className="flex flex-wrap gap-2">
              {finding.cwe_ids?.map((cwe) => (
                <span key={cwe} className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-md text-xs font-mono border border-slate-200 dark:border-slate-700">
                  {cwe}
                </span>
              ))}
              {finding.owasp_refs?.map((owasp) => (
                <span key={owasp} className="px-2.5 py-1 bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 rounded-md text-xs font-mono border border-blue-200 dark:border-blue-800">
                  {owasp}
                </span>
              ))}
              <span className="px-2.5 py-1 bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 rounded-md text-xs font-mono border border-purple-200 dark:border-purple-800">
                DPDP Act §8(5) Security Safeguard
              </span>
            </div>
          </div>
        </div>

        {/* Fix Pack Actions */}
        <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-center gap-3">
          <button
            onClick={handleCopyPrompt}
            className="w-full sm:w-auto px-5 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs sm:text-sm font-semibold transition flex items-center justify-center gap-2 shadow-xs"
          >
            {copiedPrompt ? (
              <>
                <Check className="w-4 h-4 text-emerald-300" />
                <span>Fix Prompt Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-4 h-4" />
                <span>Copy Fix Prompt for AI Agent</span>
              </>
            )}
          </button>

          <button
            onClick={handleCreatePr}
            disabled={creatingPr}
            className="w-full sm:w-auto px-5 py-3 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 text-white rounded-xl text-xs sm:text-sm font-semibold transition flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {creatingPr ? (
              <>
                <Sparkles className="w-4 h-4 animate-spin text-blue-400" />
                <span>Creating Branch...</span>
              </>
            ) : (
              <>
                <GitPullRequest className="w-4 h-4 text-emerald-400" />
                <span>Create Fix PR (Draft)</span>
              </>
            )}
          </button>
        </div>

        {/* PR Notification Banner */}
        {prResult && (
          <div className="mt-4 p-4 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 rounded-xl text-xs text-emerald-900 dark:text-emerald-200">
            <p className="font-semibold mb-1">Fix Branch Created</p>
            <p className="font-mono">Branch: {prResult.branch_name}</p>
            <p className="mt-1">{prResult.message || 'Draft pull request initiated. Refuses pushing directly to main.'}</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingDetailPage;
