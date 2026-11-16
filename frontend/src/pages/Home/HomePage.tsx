import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, AlertTriangle, ArrowRight, Sparkles } from 'lucide-react';
import { submitRepository, startAudit } from '../../services/api';

export const HomePage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [scope, setScope] = useState<'SECURITY' | 'DPDP' | 'BOTH'>('BOTH');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!url.startsWith('https://github.com/')) {
      setError('Only public https://github.com/{owner}/{repo} URLs are supported.');
      return;
    }

    try {
      setLoading(true);
      const repo = await submitRepository(url, branch);
      const scopes = scope === 'BOTH' ? ['SECURITY', 'DPDP'] : [scope];
      const audit = await startAudit(repo.id, scopes);
      navigate(`/audits/${audit.audit_id}`);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to initiate audit');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 sm:py-14">
      <div className="text-center mb-8 sm:mb-12">
        <div className="flex justify-center mb-4 sm:mb-6">
          <div className="relative group">
            <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-3xl blur opacity-30 group-hover:opacity-60 transition duration-500"></div>
            <img
              src="/logo.jpg"
              alt="SecureScan AI Shield Logo"
              className="relative w-20 h-20 sm:w-24 sm:h-24 rounded-2xl shadow-xl border-2 border-white/20 dark:border-slate-700/60 object-cover transform group-hover:scale-105 transition-all duration-300"
            />
          </div>
        </div>
        <div className="inline-flex items-center gap-1.5 sm:gap-2 px-3 py-1 sm:px-3.5 sm:py-1.5 bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 text-xs sm:text-sm font-medium rounded-full mb-3 sm:mb-4 border border-blue-200 dark:border-blue-800 shadow-sm max-w-full">
          <Shield className="w-3.5 h-3.5 text-blue-600 flex-shrink-0" />
          <span className="truncate">India DPDP Act 2023 & OWASP Top 10 Security Engine</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight mb-3 sm:mb-4 text-slate-900 dark:text-white">
          SecureScan AI
        </h1>
        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed px-2">
          Audit your public GitHub repositories with zero code execution, parser-level secret redaction, and honest readiness reporting.
        </p>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-8 shadow-sm mb-8">
        <form onSubmit={handleStartScan} className="space-y-5 sm:space-y-6">
          <div>
            <label className="block text-xs sm:text-sm font-semibold mb-2 text-slate-800 dark:text-slate-200">
              GitHub Repository URL
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              className="w-full px-3.5 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none font-mono text-base sm:text-sm transition"
              required
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs sm:text-sm font-semibold mb-2 text-slate-800 dark:text-slate-200">
                Branch (Optional)
              </label>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
                className="w-full px-3.5 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none font-mono text-base sm:text-sm transition"
              />
            </div>

            <div>
              <label className="block text-xs sm:text-sm font-semibold mb-2 text-slate-800 dark:text-slate-200">
                Audit Scope
              </label>
              <select
                value={scope}
                onChange={(e) => setScope(e.target.value as 'SECURITY' | 'DPDP' | 'BOTH')}
                className="w-full px-3.5 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-base sm:text-sm transition cursor-pointer"
              >
                <option value="BOTH">Full Audit (Security + India DPDP)</option>
                <option value="SECURITY">Application Security Only</option>
                <option value="DPDP">India DPDP Readiness Only</option>
              </select>
            </div>
          </div>

          {error && (
            <div className="p-3.5 sm:p-4 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800 rounded-xl text-red-700 dark:text-red-300 text-xs sm:text-sm flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 sm:py-4 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50 shadow-md shadow-blue-600/20 text-sm sm:text-base cursor-pointer"
          >
            {loading ? (
              <>
                <Sparkles className="w-4 h-4 animate-spin" />
                <span>Initializing Safe Fetch...</span>
              </>
            ) : (
              <>
                <span>Start Audit</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6 text-xs sm:text-sm">
        <div className="p-4 sm:p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <Lock className="w-5 h-5 text-blue-600 mb-2" />
          <h3 className="font-semibold mb-1 text-slate-900 dark:text-white">Isolated Static Analysis</h3>
          <p className="text-slate-600 dark:text-slate-400 text-xs leading-relaxed">
            Pure static security analysis (SAST) in an offline sandbox. We never execute repo code, penetration tests, or live exploit simulations.
          </p>
        </div>
        <div className="p-4 sm:p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <Shield className="w-5 h-5 text-emerald-600 mb-2" />
          <h3 className="font-semibold mb-1 text-slate-900 dark:text-white">Automatic Redaction</h3>
          <p className="text-slate-600 dark:text-slate-400 text-xs leading-relaxed">
            Tokens and credentials are masked at the parser boundary. No raw secrets enter logs, databases, or reports.
          </p>
        </div>
        <div className="p-4 sm:p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <AlertTriangle className="w-5 h-5 text-amber-600 mb-2" />
          <h3 className="font-semibold mb-1 text-slate-900 dark:text-white">Honest Verification</h3>
          <p className="text-slate-600 dark:text-slate-400 text-xs leading-relaxed">
            Unknown is never marked Pass. Phased DPDP effective dates are computed dynamically, not guessed.
          </p>
        </div>
      </div>
    </div>
  );
};
export default HomePage;
