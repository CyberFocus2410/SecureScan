import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  GitCompare,
  ArrowRight,
  CheckCircle2,
  AlertOctagon
} from 'lucide-react';
import { listAudits, compareAudits } from '../../services/api';
import { AuditListItem, CompareResult } from '../../types/contracts';

export const ComparePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [audits, setAudits] = useState<AuditListItem[]>([]);
  const [baseId, setBaseId] = useState<string>(searchParams.get('base') || '');
  const [currId, setCurrId] = useState<string>(searchParams.get('curr') || '');
  const [compareData, setCompareData] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAudits()
      .then((data) => {
        setAudits(data);
        if (data.length >= 2 && !baseId && !currId) {
          setCurrId(data[0].id);
          setBaseId(data[1].id);
        } else if (data.length === 1 && !currId) {
          setCurrId(data[0].id);
        }
      })
      .catch((err) => console.error('Failed to load audits for comparison:', err));
  }, []);

  const handleRunComparison = async () => {
    if (!baseId || !currId) {
      setError('Please select both a Baseline Scan and a Current Scan to compare.');
      return;
    }
    if (baseId === currId) {
      setError('Baseline Scan and Current Scan must be different audits.');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await compareAudits(currId, baseId);
      setCompareData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to compare scans.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (baseId && currId && baseId !== currId) {
      handleRunComparison();
    }
  }, [baseId, currId]);

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <GitCompare className="w-7 h-7 text-blue-600" />
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
              Scan Comparison & Drift Analysis
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Detect new security flaws, verify resolved issues, and track regression between audit runs.
          </p>
        </div>
        <Link
          to="/"
          className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold transition"
        >
          + New Audit
        </Link>
      </div>

      {/* Selectors Card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xs mb-8">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200">
              Baseline Scan (Earlier / Reference)
            </label>
            <select
              value={baseId}
              onChange={(e) => setBaseId(e.target.value)}
              className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-xs font-mono outline-none"
            >
              <option value="">Select baseline audit...</option>
              {audits.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.target_url} · {a.id.slice(0, 8)} ({new Date(a.created_at || '').toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200">
              Current Scan (Recent / Target)
            </label>
            <select
              value={currId}
              onChange={(e) => setCurrId(e.target.value)}
              className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-xs font-mono outline-none"
            >
              <option value="">Select current audit...</option>
              {audits.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.target_url} · {a.id.slice(0, 8)} ({new Date(a.created_at || '').toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 rounded-xl text-xs text-red-700 dark:text-red-300">
            {error}
          </div>
        )}
      </div>

      {loading && (
        <div className="py-12 text-center text-slate-500 text-sm">
          <div className="inline-block animate-spin w-6 h-6 border-3 border-blue-600 border-t-transparent rounded-full mb-2"></div>
          <p>Computing fingerprint diff and posture deltas...</p>
        </div>
      )}

      {/* Comparison Results */}
      {compareData && !loading && (
        <div className="space-y-6">
          {/* Summary Stat Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 rounded-xl">
              <span className="text-xs font-bold text-emerald-700 dark:text-emerald-300">RESOLVED / FIXED</span>
              <p className="text-2xl font-extrabold text-emerald-600 dark:text-emerald-400 mt-1">
                +{compareData.summary.fixed_count}
              </p>
              <p className="text-[11px] text-emerald-500">Present in baseline, eliminated</p>
            </div>

            <div className="p-4 bg-red-50/60 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-xl">
              <span className="text-xs font-bold text-red-700 dark:text-red-300">NEW FINDINGS</span>
              <p className="text-2xl font-extrabold text-red-600 dark:text-red-400 mt-1">
                {compareData.summary.new_count}
              </p>
              <p className="text-[11px] text-red-500">Introduced since baseline</p>
            </div>

            <div className="p-4 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-xl">
              <span className="text-xs font-bold text-slate-700 dark:text-slate-300">UNCHANGED</span>
              <p className="text-2xl font-extrabold text-slate-600 dark:text-slate-400 mt-1">
                {compareData.summary.unchanged_count}
              </p>
              <p className="text-[11px] text-slate-400">Still active across both runs</p>
            </div>

            <div className="p-4 bg-orange-50/60 dark:bg-orange-950/20 border border-orange-200 dark:border-orange-900/40 rounded-xl">
              <span className="text-xs font-bold text-orange-700 dark:text-orange-300">REGRESSED</span>
              <p className="text-2xl font-extrabold text-orange-600 dark:text-orange-400 mt-1">
                {compareData.summary.regressed_count}
              </p>
              <p className="text-[11px] text-orange-500">Re-introduced vulnerabilities</p>
            </div>
          </div>

          {/* New Findings List */}
          {compareData.new_findings.length > 0 && (
            <div className="bg-white dark:bg-slate-900 border border-red-200 dark:border-red-900/50 rounded-2xl p-6 shadow-xs">
              <h2 className="text-base font-bold text-red-700 dark:text-red-300 mb-3 flex items-center gap-2">
                <AlertOctagon className="w-5 h-5 text-red-600" />
                <span>Newly Introduced Vulnerabilities ({compareData.new_findings.length})</span>
              </h2>
              <div className="space-y-2.5">
                {compareData.new_findings.map((f) => (
                  <Link
                    key={f.id}
                    to={`/findings/${f.id}`}
                    className="p-3 bg-red-50/40 dark:bg-red-950/20 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-xl border border-red-200 dark:border-red-900/40 flex items-center justify-between transition"
                  >
                    <div className="truncate mr-2">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="px-2 py-0.5 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 rounded text-[10px] font-bold">
                          {f.priority} · {f.severity}
                        </span>
                        <span className="text-xs font-semibold text-slate-900 dark:text-white truncate">{f.title}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-mono truncate">{f.file_path}</p>
                    </div>
                    <ArrowRight className="w-4 h-4 text-slate-400 flex-shrink-0" />
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Fixed Findings List */}
          {compareData.fixed_findings.length > 0 && (
            <div className="bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-900/50 rounded-2xl p-6 shadow-xs">
              <h2 className="text-base font-bold text-emerald-700 dark:text-emerald-300 mb-3 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                <span>Resolved Vulnerabilities ({compareData.fixed_findings.length})</span>
              </h2>
              <div className="space-y-2.5">
                {compareData.fixed_findings.map((f) => (
                  <div
                    key={f.id}
                    className="p-3 bg-emerald-50/40 dark:bg-emerald-950/20 rounded-xl border border-emerald-200 dark:border-emerald-900/40 flex items-center justify-between"
                  >
                    <div className="truncate mr-2">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="px-2 py-0.5 bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 rounded text-[10px] font-bold">
                          FIXED
                        </span>
                        <span className="text-xs font-semibold text-slate-900 dark:text-white truncate">{f.title}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-mono truncate">{f.file_path}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ComparePage;
