import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileCode,
  AlertTriangle,
  CheckCircle2,
  AlertOctagon,
  ChevronRight,
  Package,
  Sparkles,
  Flame,
  Layers,
  Code2,
  Briefcase,
  Scale
} from 'lucide-react';
import {
  getFindings,
  getSecurityCoverage,
  getRiskIntelligence,
  getSbomCycloneDx,
  getSbomSpdx
} from '../../services/api';
import {
  Finding,
  ControlResult,
  RiskIntelligenceData
} from '../../types/contracts';
import { RiskScorecardGauge } from '../../components/RiskScorecardGauge';
import { AttackSurfaceMap } from '../../components/AttackSurfaceMap';

type ActiveTab = 'summary' | 'findings' | 'good' | 'gaps' | 'chains' | 'topology' | 'sbom';
type AudienceLens = 'developer' | 'executive' | 'compliance';

export const SecurityPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [activeTab, setActiveTab] = useState<ActiveTab>('summary');
  const [audienceLens, setAudienceLens] = useState<AudienceLens>('developer');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [controls, setControls] = useState<ControlResult[]>([]);
  const [riskData, setRiskData] = useState<RiskIntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);

  // Filters
  const [selectedPriority, setSelectedPriority] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedEngine, setSelectedEngine] = useState<string>('ALL');

  useEffect(() => {
    if (!auditId) return;

    Promise.all([
      getFindings(auditId).catch(() => ({ items: [], total: 0 })),
      getSecurityCoverage(auditId).catch(() => null),
      getRiskIntelligence(auditId).catch(() => null)
    ]).then(([fData, covData, rData]) => {
      if (fData) setFindings(fData.items);
      if (covData) {
        setControls(covData.controls);
      }
      if (rData) setRiskData(rData);
      setLoading(false);
    });
  }, [auditId]);

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-16 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full mb-4"></div>
        <p className="text-slate-500 font-medium text-sm">Loading security results & risk intelligence...</p>
      </div>
    );
  }

  // Filtered findings
  const filteredFindings = findings.filter((f) => {
    if (selectedPriority !== 'ALL' && f.priority !== selectedPriority) return false;
    if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
    if (selectedEngine !== 'ALL' && f.engine !== selectedEngine && f.scanner_name !== selectedEngine) return false;
    return true;
  });

  const goodControls = controls.filter((c) => c.state === 'PASS_EVIDENCED');
  const gapControls = controls.filter((c) => c.state === 'POTENTIAL_GAP' || c.state === 'NOT_VERIFIED');
  const attackChains = riskData?.attack_chains || [];

  const handleExportSbom = async (format: 'cyclonedx' | 'spdx') => {
    if (!auditId) return;
    try {
      const data = format === 'cyclonedx' ? await getSbomCycloneDx(auditId) : await getSbomSpdx(auditId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sbom-${format}-${auditId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Failed to export SBOM: ${err.message || 'Unknown error'}`);
    }
  };

  const handleLensChange = (lens: AudienceLens) => {
    setAudienceLens(lens);
    if (lens === 'executive') {
      setActiveTab('summary');
    } else if (lens === 'developer') {
      setActiveTab('findings');
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 sm:py-8">
      {/* Top Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <img
              src="/logo.jpg"
              alt="SecureScan AI Logo"
              className="w-8 h-8 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 object-cover flex-shrink-0"
            />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Security Audit Results
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-500 mt-1">Scan ID: {auditId}</p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to={`/audits/${auditId}/dpdp`}
            className="px-3.5 py-1.5 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 rounded-xl text-xs font-semibold hover:bg-emerald-100 transition"
          >
            DPDP Readiness →
          </Link>
          <Link
            to={`/audits/${auditId}/report`}
            className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold transition"
          >
            Export Report & Fix Pack
          </Link>
        </div>
      </div>

      {/* Feature 4: Audience Lens Selector Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 p-2 bg-slate-100 dark:bg-slate-800/60 rounded-2xl border border-slate-200/80 dark:border-slate-700/60">
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar">
          <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider pl-2 pr-1 shrink-0">
            Audience Lens:
          </span>
          <button
            onClick={() => handleLensChange('developer')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              audienceLens === 'developer'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Developer Lens</span>
          </button>
          <button
            onClick={() => handleLensChange('executive')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              audienceLens === 'executive'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
            }`}
          >
            <Briefcase className="w-3.5 h-3.5" />
            <span>Executive / CISO</span>
          </button>
          <button
            onClick={() => handleLensChange('compliance')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              audienceLens === 'compliance'
                ? 'bg-emerald-600 text-white shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
            }`}
          >
            <Scale className="w-3.5 h-3.5" />
            <span>Legal & DPDP</span>
          </button>
        </div>

        <div className="text-[11px] text-slate-500 pr-2 hidden md:block">
          {audienceLens === 'developer' && 'Optimized for technical code fixes, AST evidence & line-level triage.'}
          {audienceLens === 'executive' && 'High-level posture rating, radial scores & compound risk traversal.'}
          {audienceLens === 'compliance' && 'Statutory DPDP Act 2023 alignment & Section 33 penalty exposures.'}
        </div>
      </div>

      {/* Audience Lens Contextual Banners */}
      {audienceLens === 'executive' && (
        <div className="p-4 bg-slate-900 text-white rounded-2xl mb-6 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 border border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <Briefcase className="w-4 h-4 text-sky-400" />
              <span className="font-bold text-xs uppercase tracking-wider text-sky-400">
                Executive & CISO Briefing Mode
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1">
              Overall Security Posture: <strong className="text-white">{riskData?.scores?.overall_rating || 'Evaluating'}</strong> across 5 architectural domains with {attackChains.length} compound attack chain(s) identified.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('summary')}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded-xl text-xs font-semibold cursor-pointer transition"
            >
              Radial Posture Gauge
            </button>
            <button
              onClick={() => setActiveTab('chains')}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-xl text-xs font-semibold cursor-pointer transition"
            >
              Attack Chains
            </button>
          </div>
        </div>
      )}

      {audienceLens === 'compliance' && (
        <div className="p-4 bg-emerald-950/40 text-emerald-200 border border-emerald-800 rounded-2xl mb-6 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Scale className="w-4 h-4 text-emerald-400" />
              <span className="font-bold text-xs uppercase tracking-wider text-emerald-400">
                Statutory Compliance & Legal Mode
              </span>
            </div>
            <p className="text-xs text-emerald-300 mt-1">
              Evaluating statutory readiness under the India Digital Personal Data Protection Act, 2023. Readiness Index:{' '}
              <strong className="text-white font-mono">{riskData?.scores?.dpdp_readiness_score || 0} / 100</strong>.
            </p>
          </div>
          <Link
            to={`/audits/${auditId}/dpdp`}
            className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold whitespace-nowrap shadow-xs text-center transition"
          >
            Open DPDP Readiness Matrix →
          </Link>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex overflow-x-auto no-scrollbar gap-2 mb-6 pb-1 border-b border-slate-200 dark:border-slate-800 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('summary')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'summary'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>Executive Summary</span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'findings'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <AlertOctagon className="w-3.5 h-3.5 text-red-500" />
          <span>What Needs Fixing ({findings.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('topology')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'topology'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-cyan-500" />
          <span>Attack Surface Map</span>
        </button>

        <button
          onClick={() => setActiveTab('good')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'good'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
          <span>What Looks Good ({goodControls.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('gaps')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'gaps'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
          <span>Needs Human Look ({gapControls.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('chains')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'chains'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Flame className="w-3.5 h-3.5 text-orange-500" />
          <span>Attack Chains ({attackChains.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('sbom')}
          className={`px-3.5 py-2 rounded-xl transition flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            activeTab === 'sbom'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Package className="w-3.5 h-3.5 text-indigo-500" />
          <span>SBOM View</span>
        </button>
      </div>


      {/* TAB 1: EXECUTIVE SUMMARY */}
      {activeTab === 'summary' && (
        <div className="space-y-6">
          {/* Priority Counts Cards (P0-P3) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 bg-red-50/60 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-xl">
              <span className="text-xs font-bold text-red-700 dark:text-red-300">P0 · CRITICAL</span>
              <p className="text-2xl font-extrabold text-red-600 dark:text-red-400 mt-1">
                {riskData?.priority_counts.P0 || findings.filter(f => f.priority === 'P0' || f.severity === 'CRITICAL').length}
              </p>
              <p className="text-[11px] text-red-500">Immediate Exploitable Risk</p>
            </div>

            <div className="p-4 bg-orange-50/60 dark:bg-orange-950/20 border border-orange-200 dark:border-orange-900/40 rounded-xl">
              <span className="text-xs font-bold text-orange-700 dark:text-orange-300">P1 · HIGH</span>
              <p className="text-2xl font-extrabold text-orange-600 dark:text-orange-400 mt-1">
                {riskData?.priority_counts.P1 || findings.filter(f => f.priority === 'P1' || f.severity === 'HIGH').length}
              </p>
              <p className="text-[11px] text-orange-500">High Impact Defense Gap</p>
            </div>

            <div className="p-4 bg-amber-50/60 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 rounded-xl">
              <span className="text-xs font-bold text-amber-700 dark:text-amber-300">P2 · MEDIUM</span>
              <p className="text-2xl font-extrabold text-amber-600 dark:text-amber-400 mt-1">
                {riskData?.priority_counts.P2 || findings.filter(f => f.priority === 'P2' || f.severity === 'MEDIUM').length}
              </p>
              <p className="text-[11px] text-amber-500">Moderate Vulnerability</p>
            </div>

            <div className="p-4 bg-blue-50/60 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/40 rounded-xl">
              <span className="text-xs font-bold text-blue-700 dark:text-blue-300">P3 · LOW / INFO</span>
              <p className="text-2xl font-extrabold text-blue-600 dark:text-blue-400 mt-1">
                {riskData?.priority_counts.P3 || findings.filter(f => f.priority === 'P3' || f.severity === 'LOW' || f.severity === 'INFO').length}
              </p>
              <p className="text-[11px] text-blue-500">Hardening & Hygiene</p>
            </div>
          </div>

          {/* Feature 3: Radial Multi-Arc Posture Gauge */}
          {riskData?.scores && (
            <RiskScorecardGauge scores={riskData.scores} />
          )}

          {/* Top 5 Things to Fix First */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs">
            <h2 className="text-base font-bold text-slate-900 dark:text-white mb-3">
              Top Priority Fixes
            </h2>
            <div className="space-y-2.5">
              {findings.slice(0, 5).map((f) => (
                <Link
                  key={f.id}
                  to={`/findings/${f.id}`}
                  className="p-3 bg-slate-50 dark:bg-slate-800/40 hover:bg-blue-50/50 dark:hover:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-800 flex items-center justify-between transition"
                >
                  <div className="flex items-center gap-2.5 truncate mr-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 flex-shrink-0">
                      {f.priority || 'P0'}
                    </span>
                    <span className="text-xs font-semibold text-slate-900 dark:text-white truncate">
                      {f.plain_title || f.title}
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono truncate hidden sm:inline">
                      ({f.file_path}:{f.start_line})
                    </span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 flex-shrink-0" />
                </Link>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: FINDINGS ("What Needs Fixing") */}
      {activeTab === 'findings' && (
        <div>
          {/* Filters Bar */}
          <div className="flex flex-wrap items-center gap-2 mb-4 p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200 dark:border-slate-800 text-xs">
            <span className="font-semibold text-slate-500 mr-1">Filter by:</span>

            {/* Priority Filter */}
            <select
              value={selectedPriority}
              onChange={(e) => setSelectedPriority(e.target.value)}
              className="px-2.5 py-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none"
            >
              <option value="ALL">All Priorities</option>
              <option value="P0">P0 (Critical)</option>
              <option value="P1">P1 (High)</option>
              <option value="P2">P2 (Medium)</option>
              <option value="P3">P3 (Low)</option>
            </select>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-2.5 py-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Engine Filter */}
            <select
              value={selectedEngine}
              onChange={(e) => setSelectedEngine(e.target.value)}
              className="px-2.5 py-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none"
            >
              <option value="ALL">All Engines</option>
              <option value="sast">SAST / Code Analysis</option>
              <option value="secrets">Secret Detector</option>
              <option value="dast">DAST / Web Scanner</option>
              <option value="api">API Security</option>
              <option value="authz">Auth Matrix</option>
              <option value="iac">IaC & Cloud Config</option>
              <option value="database">Database Security</option>
              <option value="ai">AI / LLM Security</option>
            </select>
          </div>

          {/* Finding Cards */}
          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                <p className="text-sm font-semibold">No findings matching the selected filters.</p>
              </div>
            ) : (
              filteredFindings.map((f) => (
                <Link
                  key={f.id}
                  to={`/findings/${f.id}`}
                  className="block p-4 sm:p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-blue-400 dark:hover:border-blue-600 rounded-xl transition shadow-xs group"
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 mb-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        f.priority === 'P0' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300' :
                        f.priority === 'P1' ? 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300' :
                        'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}>
                        {f.priority || 'P2'} · {f.severity}
                      </span>
                      <span className="text-xs font-semibold text-slate-900 dark:text-white group-hover:text-blue-600 transition">
                        {f.plain_title || f.title}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-blue-600 font-medium">
                      <span>View details & fix</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </div>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-400 mb-3 line-clamp-2 leading-relaxed">
                    {f.plain_summary || f.description}
                  </p>

                  <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
                    <FileCode className="w-3.5 h-3.5" />
                    <span className="truncate">{f.file_path}:{f.start_line}</span>
                    <span>·</span>
                    <span className="capitalize">{f.scanner_name}</span>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>
      )}

      {/* Feature 1: Attack Surface Topology Map */}
      {activeTab === 'topology' && (
        <AttackSurfaceMap data={riskData?.attack_surface} findings={findings} />
      )}

      {/* TAB 3: WHAT LOOKS GOOD ✅ */}
      {activeTab === 'good' && (
        <div className="space-y-3">
          <div className="p-4 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 rounded-xl text-xs text-emerald-900 dark:text-emerald-200">
            <p className="font-semibold mb-0.5">Verified Defenses (PASS_EVIDENCED)</p>
            <p>Controls that were checked by automated analyzers and confirmed passing based on tangible source or config evidence.</p>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs">
            {goodControls.map((c) => (
              <div key={c.id} className="p-4 hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
                    <span className="font-semibold text-xs text-slate-900 dark:text-white">{c.title}</span>
                  </div>
                  <span className="font-mono text-[11px] text-blue-600">{c.control_id}</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 pl-6 leading-relaxed">{c.rationale}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: NEEDS A HUMAN LOOK 🟡 */}
      {activeTab === 'gaps' && (
        <div className="space-y-3">
          <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl text-xs text-amber-900 dark:text-amber-200">
            <p className="font-semibold mb-0.5">Unverified Controls & Potential Gaps</p>
            <p>Items requiring human architectural review or deeper operational verification that automated tooling cannot guarantee.</p>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs">
            {gapControls.map((c) => (
              <div key={c.id} className="p-4 hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0" />
                    <span className="font-semibold text-xs text-slate-900 dark:text-white">{c.title}</span>
                  </div>
                  <span className="font-mono text-[11px] text-amber-600">{c.control_id}</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 pl-6 leading-relaxed">{c.rationale}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: ATTACK CHAINS */}
      {activeTab === 'chains' && (
        <div className="space-y-4">
          <div className="p-4 bg-orange-50 dark:bg-orange-950/30 border border-orange-200 dark:border-orange-800 rounded-xl text-xs text-orange-900 dark:text-orange-200">
            <p className="font-semibold mb-0.5">Compound Attack Chains (Step 12)</p>
            <p>Automated correlation connecting multiple individually medium/high vulnerabilities into P0 critical compromise paths.</p>
          </div>

          {attackChains.length === 0 ? (
            <div className="p-8 text-center bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
              <p className="text-sm font-semibold">No multi-stage attack chains identified.</p>
            </div>
          ) : (
            attackChains.map((ch) => (
              <div key={ch.chain_id} className="p-5 bg-white dark:bg-slate-900 border border-red-200 dark:border-red-900/50 rounded-2xl shadow-xs space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Flame className="w-5 h-5 text-red-600" />
                    <h3 className="font-bold text-sm text-slate-900 dark:text-white">{ch.title}</h3>
                  </div>
                  <span className="px-2.5 py-0.5 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 rounded font-bold text-xs">
                    {ch.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed bg-red-50/50 dark:bg-red-950/20 p-3 rounded-xl border border-red-100 dark:border-red-900/40">
                  {ch.narrative_story}
                </p>

                <div>
                  <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                    Compound Traversal Steps
                  </h4>
                  <ol className="list-decimal list-inside space-y-1 text-xs text-slate-600 dark:text-slate-400 pl-1">
                    {ch.traversal_steps.map((st, i) => (
                      <li key={i}>{st}</li>
                    ))}
                  </ol>
                </div>

                <div className="pt-2 border-t border-slate-100 dark:border-slate-800 text-xs">
                  <span className="font-semibold text-emerald-600">Remediation: </span>
                  <span className="text-slate-600 dark:text-slate-400">{ch.remediation_strategy}</span>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* TAB 6: SBOM VIEW */}
      {activeTab === 'sbom' && (
        <div className="space-y-4">
          <div className="p-4 bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-indigo-900 dark:text-indigo-200">
            <div>
              <p className="font-semibold mb-0.5">Software Bill of Materials (SBOM) Exporter</p>
              <p>Standardized package inventories supporting supply chain integrity and license verification.</p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => handleExportSbom('cyclonedx')}
                className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold"
              >
                Download CycloneDX 1.6
              </button>
              <button
                onClick={() => handleExportSbom('spdx')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold"
              >
                Download SPDX 2.3
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityPage;
