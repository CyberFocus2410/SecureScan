import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileText,
  X,
  Send,
  Sparkles,
  Scale,
  AlertTriangle,
  RotateCcw
} from 'lucide-react';
import { submitDpdpProfile, getDpdpReadiness } from '../../services/api';
import { DPDPReadinessReport } from '../../types/contracts';

export const DPDPPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [report, setReport] = useState<DPDPReadinessReport | null>(null);
  const [questionnaireOpen, setQuestionnaireOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [updatingProfile, setUpdatingProfile] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [controlFilter, setControlFilter] = useState<string>('ALL');

  // Questionnaire form state
  const [qAnswers, setQAnswers] = useState<{
    processes_personal_data: boolean | null;
    in_territory_of_india: boolean | null;
    targeting_data_principals_in_india: boolean | null;
    processes_children_data: boolean | null;
    is_significant_data_fiduciary: boolean | null;
  }>({
    processes_personal_data: true,
    in_territory_of_india: true,
    targeting_data_principals_in_india: true,
    processes_children_data: false,
    is_significant_data_fiduciary: false
  });

  const loadData = () => {
    if (!auditId) return;
    setLoading(true);
    setError(null);
    getDpdpReadiness(auditId)
      .then((rData) => {
        if (rData) setReport(rData);
      })
      .catch((err) => {
        console.error('Failed to load DPDP readiness:', err);
        setError('Unable to load DPDP readiness report. Please verify backend service availability.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, [auditId]);

  const handleProfileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!auditId) return;
    setUpdatingProfile(true);
    try {
      await submitDpdpProfile(auditId, qAnswers);
      await loadData();
      setQuestionnaireOpen(false);
    } catch (err) {
      console.error('Failed to update DPDP profile:', err);
    } finally {
      setUpdatingProfile(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-16 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-4 border-emerald-600 border-t-transparent rounded-full mb-4"></div>
        <p className="text-slate-500 font-medium text-sm">Evaluating DPDP Act 2023 readiness & statutory controls...</p>
      </div>
    );
  }

  const readinessScore = report?.readiness_score ?? 0;
  const asOfDate = report?.as_of_date || new Date().toISOString().split('T')[0];

  const controlsList = report?.evaluated_controls || [];
  const filteredControls = controlsList.filter((c) => {
    if (controlFilter === 'ALL') return true;
    if (controlFilter === 'VERIFIED') return c.status === 'Verified' || c.status === 'Implemented' || c.status === 'MANUAL_PROVIDED';
    if (controlFilter === 'UPCOMING') return c.status === 'Upcoming' || c.effective_date_status === 'UPCOMING';
    if (controlFilter === 'GAP') return c.status === 'Potential Gap' || c.status === 'POTENTIAL_GAP' || c.status === 'Not detected' || c.status === 'Manual review';
    return true;
  });

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 sm:py-8">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <img
              src="/logo.jpg"
              alt="SecureScan AI Logo"
              className="w-8 h-8 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 object-cover flex-shrink-0"
            />
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                India DPDP Act 2023 Readiness
              </h1>
              <p className="text-xs font-mono text-slate-500">
                Evaluation As Of: {asOfDate} · Gazette No. G.S.R. 843(E) & 846(E)
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setQuestionnaireOpen(true)}
            className="px-3.5 py-1.5 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 rounded-xl text-xs font-semibold hover:bg-emerald-100 transition flex items-center gap-1.5 cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Applicability Questionnaire</span>
          </button>
          <Link
            to={`/audits/${auditId}/security`}
            className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold transition"
          >
            ← Security Results
          </Link>
        </div>
      </div>

      {/* Error Alert if any */}
      {error && (
        <div className="p-4 bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-800 rounded-2xl mb-6 text-xs text-red-900 dark:text-red-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
            <p>{error}</p>
          </div>
          <button
            onClick={loadData}
            className="px-3 py-1 bg-red-100 hover:bg-red-200 dark:bg-red-900/60 dark:hover:bg-red-900 text-red-800 dark:text-red-200 rounded-lg text-xs font-semibold flex items-center gap-1"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Retry
          </button>
        </div>
      )}

      {/* Mandatory Statutory Disclaimer Banner */}
      <div className="p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-2xl mb-6 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-3">
        <Scale className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
        <div>
          <p className="font-bold mb-0.5">Statutory Caveat & Legal Notice</p>
          <p className="leading-relaxed">
            Developer-assistance readiness audit. Not a legal opinion, compliance certificate, or guarantee of immunity.
            Statutory penalty references represent maximum statutory ceilings enacted under Section 33 of the Digital Personal Data Protection Act, 2023.
            Potential legal category; applicability and liability not determined.
          </p>
        </div>
      </div>

      {/* 0-100 Readiness Score Card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs mb-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
          <div>
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              DPDP Overall Readiness Index
            </span>
            <div className="flex items-baseline gap-3 mt-1">
              <span className="text-4xl sm:text-5xl font-extrabold text-slate-900 dark:text-white">
                {readinessScore}
              </span>
              <span className="text-sm font-semibold text-slate-400">/ 100</span>
            </div>
            <p className="text-xs text-slate-500 mt-2 max-w-md">
              Score derived from 18 statutory controls across Categories A–J.
              {report?.hard_cap_applied && (
                <span className="block text-red-600 dark:text-red-400 font-semibold mt-1">
                  ⚠️ Section 8(5) Hard Cap Rule: Score capped at 60 max due to critical security safeguard findings.
                </span>
              )}
            </p>
          </div>

          <div className="flex flex-col gap-2 min-w-[200px]">
            <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl text-center">
              <p className="text-[11px] text-slate-500 font-medium">Controls Evaluated</p>
              <p className="text-lg font-bold text-slate-900 dark:text-white mt-0.5">
                {report?.evaluated_controls?.length || 18} Controls
              </p>
            </div>
            <div className="p-3 bg-emerald-50/60 dark:bg-emerald-950/20 rounded-xl text-center border border-emerald-200 dark:border-emerald-900/40">
              <p className="text-[11px] text-emerald-700 dark:text-emerald-300 font-medium">Statutory Regime</p>
              <p className="text-xs font-semibold text-emerald-800 dark:text-emerald-200 mt-0.5">
                DPDP Act 2023 Enacted
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Categories A through J Grid */}
      {report?.categories && report.categories.length > 0 && (
        <div className="mb-8">
          <h2 className="text-base font-bold text-slate-900 dark:text-white mb-3">
            Readiness by Statutory Category (A through J)
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {report.categories.map((cat) => (
              <div
                key={cat.category_id}
                className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-xs text-slate-900 dark:text-white truncate pr-2">
                    {cat.title}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    cat.status === 'Verified' || cat.status === 'Implemented'
                      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      : cat.status === 'Upcoming'
                      ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                      : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                  }`}>
                    {cat.status}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 mt-2">
                  <span>Progress</span>
                  <span className="font-mono">{cat.implemented_count} / {cat.controls_count} controls</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1.5">
                  <div
                    className="bg-emerald-500 h-full rounded-full transition-all"
                    style={{ width: `${cat.controls_count > 0 ? (cat.implemented_count / cat.controls_count) * 100 : 0}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Statutory Controls Evaluation (18 Controls) */}
      {report?.evaluated_controls && report.evaluated_controls.length > 0 && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs mb-8">
          <div className="p-4 sm:p-6 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                Statutory Controls Evaluation (18 Controls)
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Assessment mapped against Sections 3–16 of the Digital Personal Data Protection Act, 2023.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-500">Filter:</span>
              <select
                value={controlFilter}
                onChange={(e) => setControlFilter(e.target.value)}
                className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-xs font-medium"
              >
                <option value="ALL">All Controls ({report.evaluated_controls.length})</option>
                <option value="VERIFIED">Verified / Implemented</option>
                <option value="UPCOMING">Upcoming Provisions</option>
                <option value="GAP">Potential Gaps / Action Required</option>
              </select>
            </div>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {filteredControls.map((ctrl) => (
              <div key={ctrl.control_id} className="p-4 sm:p-5 hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 font-mono font-bold text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded">
                      {ctrl.control_id}
                    </span>
                    <span className="font-bold text-sm text-slate-900 dark:text-white">
                      {ctrl.title}
                    </span>
                    {ctrl.act_section && (
                      <span className="px-2 py-0.5 font-mono text-[10px] bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 rounded border border-blue-200 dark:border-blue-900">
                        {ctrl.act_section} {ctrl.rules_ref ? `· ${ctrl.rules_ref}` : ''}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold ${
                      ctrl.status === 'Verified' || ctrl.status === 'Implemented' || ctrl.status === 'MANUAL_PROVIDED'
                        ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                        : ctrl.status === 'Upcoming'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                        : ctrl.status === 'Potential Gap' || ctrl.status === 'POTENTIAL_GAP'
                        ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                        : 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300'
                    }`}>
                      {ctrl.status}
                    </span>
                    {ctrl.effective_date_status && (
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                        ctrl.effective_date_status === 'IN_FORCE'
                          ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800'
                          : 'bg-indigo-50 text-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800'
                      }`}>
                        {ctrl.effective_date_status}
                      </span>
                    )}
                  </div>
                </div>

                {ctrl.evidence_summary && (
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 pl-1">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">Observation: </span>
                    {ctrl.evidence_summary}
                  </p>
                )}

                {ctrl.remediation && (
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 pl-1 italic">
                    <span className="font-semibold text-slate-600 dark:text-slate-300 not-italic">Remediation: </span>
                    {ctrl.remediation}
                  </p>
                )}
              </div>
            ))}
            {filteredControls.length === 0 && (
              <div className="p-8 text-center text-xs text-slate-400">
                No controls match the selected filter.
              </div>
            )}
          </div>
        </div>
      )}


      {/* Section 33 Statutory Penalties Table */}
      {report?.statutory_penalties && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs mb-8">
          <div className="p-4 sm:p-6 border-b border-slate-200 dark:border-slate-800">
            <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              Section 33 Statutory Penalty Schedule (Ceilings)
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Statutory limits as enacted by Parliament of India. Zero predicted fine amounts or cumulative calculations.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs sm:text-sm min-w-[620px]">
              <thead className="bg-slate-50 dark:bg-slate-800/50 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-3 w-16">Item</th>
                  <th className="px-4 py-3 w-32">Section</th>
                  <th className="px-4 py-3">Breach Description</th>
                  <th className="px-4 py-3 w-40 text-right">Statutory Ceiling</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                {report.statutory_penalties.map((p) => (
                  <tr key={p.schedule_item} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition">
                    <td className="px-4 py-3 font-mono font-bold text-slate-500">
                      #{p.schedule_item}
                    </td>
                    <td className="px-4 py-3 font-mono font-semibold text-blue-600 dark:text-blue-400">
                      {p.related_act_section}
                    </td>
                    <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                      <p>{p.breach_description}</p>
                      <p className="text-[10px] text-slate-400 italic mt-0.5">{p.mandatory_caveat}</p>
                    </td>
                    <td className="px-4 py-3 text-right font-mono font-bold text-red-600 dark:text-red-400">
                      {p.statutory_ceiling_inr}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Action Plan sorted by Statutory Deadline */}
      {report?.action_plan && report.action_plan.length > 0 && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs">
          <h2 className="text-base font-bold text-slate-900 dark:text-white mb-1">
            Action Plan by Statutory Deadline
          </h2>
          <p className="text-xs text-slate-500 mb-4">
            Recommended remediation steps to advance organizational readiness.
          </p>

          <div className="space-y-3">
            {report.action_plan.map((act) => (
              <div
                key={act.control_id}
                className="p-4 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-blue-600 dark:text-blue-400">{act.control_id}</span>
                    <span className="font-semibold text-slate-900 dark:text-white">{act.title}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                    {act.statutory_deadline}
                  </span>
                </div>
                <p className="text-slate-600 dark:text-slate-400 leading-relaxed pl-1">
                  {act.remediation}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Questionnaire Drawer */}
      {questionnaireOpen && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-xs z-50 flex justify-end">
          <div className="w-full max-w-md bg-white dark:bg-slate-900 h-full p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800 mb-6">
                <div>
                  <h3 className="font-bold text-base text-slate-900 dark:text-white">Applicability Profile</h3>
                  <p className="text-xs text-slate-500">Refine DPDP Act 2023 scope for this audit</p>
                </div>
                <button
                  onClick={() => setQuestionnaireOpen(false)}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <form onSubmit={handleProfileSubmit} className="space-y-4 text-xs">
                <div>
                  <label className="block font-semibold mb-1 text-slate-800 dark:text-slate-200">
                    Does your application process digital personal data?
                  </label>
                  <select
                    value={String(qAnswers.processes_personal_data)}
                    onChange={(e) => setQAnswers({ ...qAnswers, processes_personal_data: e.target.value === 'true' })}
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl"
                  >
                    <option value="true">Yes</option>
                    <option value="false">No</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold mb-1 text-slate-800 dark:text-slate-200">
                    Are data principals located within the territory of India?
                  </label>
                  <select
                    value={String(qAnswers.in_territory_of_india)}
                    onChange={(e) => setQAnswers({ ...qAnswers, in_territory_of_india: e.target.value === 'true' })}
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl"
                  >
                    <option value="true">Yes</option>
                    <option value="false">No</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold mb-1 text-slate-800 dark:text-slate-200">
                    Do you process personal data of children or persons with disabilities? (§9)
                  </label>
                  <select
                    value={String(qAnswers.processes_children_data)}
                    onChange={(e) => setQAnswers({ ...qAnswers, processes_children_data: e.target.value === 'true' })}
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl"
                  >
                    <option value="false">No</option>
                    <option value="true">Yes</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold mb-1 text-slate-800 dark:text-slate-200">
                    Has your entity been notified as a Significant Data Fiduciary (SDF)? (§10)
                  </label>
                  <select
                    value={String(qAnswers.is_significant_data_fiduciary)}
                    onChange={(e) => setQAnswers({ ...qAnswers, is_significant_data_fiduciary: e.target.value === 'true' })}
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl"
                  >
                    <option value="false">No</option>
                    <option value="true">Yes</option>
                  </select>
                </div>

                <div className="pt-4">
                  <button
                    type="submit"
                    disabled={updatingProfile}
                    className="w-full py-3 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold rounded-xl transition flex items-center justify-center gap-2 cursor-pointer"
                  >
                    {updatingProfile ? <Sparkles className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    <span>Update DPDP Evaluation</span>
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DPDPPage;
