import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { mockFindings } from '../../services/mockData';
import { Finding } from '../../types/contracts';

export const FindingDetailPage: React.FC = () => {
  const { findingId } = useParams<{ findingId: string }>();
  const [finding, setFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const f = mockFindings.find(item => item.id === findingId) || mockFindings[0];
    setFinding(f);
  }, [findingId]);

  if (!finding) return <div className="p-8 text-center text-slate-500">Finding not found</div>;

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900 mb-6">
        <ArrowLeft className="w-4 h-4" />
        <span>Back</span>
      </Link>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 sm:p-8">
        <div className="flex items-center gap-3 mb-4">
          <span className="px-3 py-1 bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300 rounded font-bold text-xs">
            {finding.severity}
          </span>
          <span className="text-xs font-mono text-slate-500">Confidence: {finding.confidence}</span>
        </div>

        <h1 className="text-2xl font-bold mb-3">{finding.title}</h1>
        <p className="text-slate-600 dark:text-slate-400 mb-6">{finding.description}</p>

        <div className="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg font-mono text-xs mb-6 space-y-1">
          <p><span className="text-slate-400">File:</span> {finding.file_path}</p>
          <p><span className="text-slate-400">Line:</span> {finding.start_line} - {finding.end_line}</p>
          <p><span className="text-slate-400">Scanner:</span> {finding.scanner_name} (rule: {finding.rule_id})</p>
        </div>

        {finding.redacted_snippet && (
          <div className="mb-6">
            <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-2">Redacted Evidence Block</h3>
            <pre className="p-4 bg-slate-950 text-slate-200 rounded-lg text-xs font-mono overflow-x-auto">
              {finding.redacted_snippet}
            </pre>
          </div>
        )}

        {finding.remediation && (
          <div className="p-4 bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900 rounded-lg text-sm space-y-2">
            <h3 className="font-semibold text-blue-900 dark:text-blue-300">Actionable Remediation</h3>
            <p className="text-blue-800 dark:text-blue-200 text-xs">{finding.remediation.technical_fix}</p>
            <p className="text-blue-700 dark:text-blue-400 text-xs">Validation: {finding.remediation.validation_steps}</p>
          </div>
        )}
      </div>
    </div>
  );
};

