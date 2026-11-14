import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Info,
  Calendar,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  MinusCircle,
  FileText,
  X,
  ShieldAlert,
  Send
} from 'lucide-react';
import { getControlResults, getLegalExposure, submitDpdpProfile } from '../../services/api';
import { ControlResult, EffectiveDateStatus } from '../../types/contracts';

interface PenaltyItem {
  schedule_item: number;
  breach_description: string;
  related_act_section: string;
  statutory_ceiling: string;
  mandatory_caveat: string;
  engineering_priority: string;
  plausibility_rationale: string;
}

export const DPDPPage: React.FC = () => {
  const { auditId } = useParams<{ auditId: string }>();
  const [controls, setControls] = useState<ControlResult[]>([]);
  const [penaltyItems, setPenaltyItems] = useState<PenaltyItem[]>([]);
  const [penaltyDrawerOpen, setPenaltyDrawerOpen] = useState(false);
  const [questionnaireOpen, setQuestionnaireOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [updatingProfile, setUpdatingProfile] = useState(false);

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
    Promise.all([
      getControlResults(auditId, 'DPDP').catch(() => []),
      getLegalExposure(auditId).catch(() => ({ items: [] }))
    ]).then(([cData, penData]) => {
      setControls(cData);
      setPenaltyItems(penData.items || []);
      setLoading(false);
    });
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
    } finally {
      setUpdatingProfile(false);
    }
  };

  const renderReadinessBadge = (label?: string | null) => {
    switch (label) {
      case 'evidence_supports':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5" /> Evidence Supports
          </span>
        );
      case 'potential_gap':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300">
            <AlertTriangle className="w-3.5 h-3.5" /> Potential Gap
          </span>
        );
      case 'needs_documents':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300">
            <FileText className="w-3.5 h-3.5" /> Needs Documents
          </span>
        );
      case 'not_applicable':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400">
            <MinusCircle className="w-3.5 h-3.5" /> Not Applicable
          </span>
        );
      case 'requires_legal_review':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-100 text-purple-800 dark:bg-purple-950/60 dark:text-purple-300">
            <HelpCircle className="w-3.5 h-3.5" /> Requires Legal Review
          </span>
        );
    }
  };

  const renderEffectiveDateChip = (status: EffectiveDateStatus, _dateStr?: string | null) => {
    if (status === 'IN_FORCE') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 rounded text-xs font-mono font-medium border border-emerald-200 dark:border-emerald-800">
          <Calendar className="w-3 h-3 text-emerald-600" /> In force (13 Nov 2026)
        </span>
      );
    }
    if (status === 'UPCOMING') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300 rounded text-xs font-mono font-medium border border-amber-200 dark:border-amber-800">
          <Calendar className="w-3 h-3 text-amber-600" /> Upcoming (13 May 2027)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400 rounded text-xs font-mono">
        <Calendar className="w-3 h-3 text-slate-400" /> Date not notified
      </span>
    );
  };

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-16 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full mb-4"></div>
        <p className="text-slate-500 font-medium">Evaluating DPDP statutory readiness...</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Persistent Legal Disclaimer Banner */}
      <div className="p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-2xl mb-6 text-sm text-amber-900 dark:text-amber-200 flex items-start gap-3.5 shadow-sm">
        <Info className="w-5 h-5 flex-shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
        <div>
          <p className="font-bold text-sm">
            Developer-Assistance Readiness Assessment — Not Legal Advice or Compliance Certification
          </p>
          <p className="text-xs text-amber-800 dark:text-amber-300 mt-1 leading-relaxed">
            Evaluations are deterministic checks based on available source files and policy models. Phased statutory obligations are derived dynamically relative to <strong>14 November 2026</strong>. Rule 4 (Consent Managers) and Section 6(9) are in force; general duties commence 13 May 2027.
          </p>
        </div>
      </div>

      {/* Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2.5 sm:gap-3">
            <img
              src="/logo.jpg"
              alt="SecureScan AI Logo"
              className="w-8 h-8 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 object-cover flex-shrink-0"
            />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              DPDP Act 2023 Readiness
            </h1>
          </div>
          <p className="text-[11px] sm:text-xs text-slate-500 font-mono mt-1 break-all">
            Audit: {auditId} • Statutory As-Of: 2026-11-14
          </p>
        </div>
        <div className="flex flex-wrap gap-2 w-full sm:w-auto">
          <button
            onClick={() => setQuestionnaireOpen(!questionnaireOpen)}
            className="flex-1 sm:flex-initial px-3.5 py-2 border border-slate-300 dark:border-slate-700 rounded-xl text-xs sm:text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition text-center cursor-pointer"
          >
            {questionnaireOpen ? 'Hide Form' : 'Questionnaire'}
          </button>
          <button
            onClick={() => setPenaltyDrawerOpen(true)}
            className="flex-1 sm:flex-initial px-3.5 py-2 bg-indigo-600 text-white rounded-xl text-xs sm:text-sm font-semibold hover:bg-indigo-700 active:bg-indigo-800 transition flex items-center justify-center gap-1.5 shadow-xs cursor-pointer"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Penalties</span>
          </button>
          <Link
            to={`/audits/${auditId}/security`}
            className="w-full sm:w-auto px-3.5 py-2 border border-slate-300 dark:border-slate-700 rounded-xl text-xs sm:text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition text-center"
          >
            Security Tab
          </Link>
        </div>
      </div>

      {/* Interactive Questionnaire Panel */}
      {questionnaireOpen && (
        <form onSubmit={handleProfileSubmit} className="p-6 bg-white dark:bg-slate-900 border border-indigo-200 dark:border-indigo-950 rounded-2xl mb-8 shadow-sm">
          <h2 className="text-base font-bold text-slate-900 dark:text-white mb-2">
            DPDP Applicability & Governance Questionnaire
          </h2>
          <p className="text-xs text-slate-500 mb-6">
            Answers customize readiness determinations under Sections 3, 9, and 10. Unanswered questions remain Unknown.
          </p>

          <div className="space-y-4 text-sm mb-6">
            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl">
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-200">Processes Digital Personal Data</p>
                <p className="text-xs text-slate-500">Does this application process personal data in digital form?</p>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, processes_personal_data: true }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.processes_personal_data === true ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  Yes
                </button>
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, processes_personal_data: false }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.processes_personal_data === false ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  No
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl">
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-200">India Processing or User Targeting (Section 3)</p>
                <p className="text-xs text-slate-500">Processing carried out in India or offering goods/services to users in India?</p>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, in_territory_of_india: true, targeting_data_principals_in_india: true }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.in_territory_of_india === true ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  Yes
                </button>
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, in_territory_of_india: false, targeting_data_principals_in_india: false }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.in_territory_of_india === false ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  No
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl">
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-200">Children's Personal Data (Section 9)</p>
                <p className="text-xs text-slate-500">Does this application knowingly collect or process data of children (&lt;18)?</p>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, processes_children_data: true }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.processes_children_data === true ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  Yes
                </button>
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, processes_children_data: false }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.processes_children_data === false ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  No
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl">
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-200">Significant Data Fiduciary (Section 10)</p>
                <p className="text-xs text-slate-500">Designated by Central Government as an SDF?</p>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, is_significant_data_fiduciary: true }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.is_significant_data_fiduciary === true ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  Yes
                </button>
                <button
                  type="button"
                  onClick={() => setQAnswers(prev => ({ ...prev, is_significant_data_fiduciary: false }))}
                  className={`px-3 py-1 rounded text-xs font-medium ${qAnswers.is_significant_data_fiduciary === false ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                >
                  No
                </button>
              </div>
            </div>
          </div>

          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setQuestionnaireOpen(false)}
              className="px-4 py-2 border border-slate-300 dark:border-slate-700 rounded-lg text-xs font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={updatingProfile}
              className="px-5 py-2 bg-indigo-600 text-white rounded-lg text-xs font-semibold hover:bg-indigo-700 transition flex items-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" /> {updatingProfile ? 'Re-evaluating...' : 'Save & Re-evaluate (202)'}
            </button>
          </div>
        </form>
      )}

      {/* 18-Control Evaluation Matrix */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm mb-12">
        <div className="p-6 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center">
          <div>
            <h2 className="text-lg font-bold">18 DPDP Readiness Controls</h2>
            <p className="text-xs text-slate-500 mt-0.5">Primary statutory basis with phased effective-date status</p>
          </div>
          <span className="text-xs font-mono text-slate-400">Total: {controls.length} Controls</span>
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {controls.map((c) => (
            <div key={c.id} className="p-6 hover:bg-slate-50/50 dark:hover:bg-slate-800/20 transition">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 mb-2.5">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-xs px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 font-bold rounded">
                    {c.control_id}
                  </span>
                  <h3 className="font-semibold text-base text-slate-900 dark:text-white">{c.title}</h3>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {renderReadinessBadge(c.readiness_label)}
                  {renderEffectiveDateChip(c.effective_date_status, c.effective_date)}
                </div>
              </div>

              <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">{c.rationale}</p>

              {c.statutory_ref && (
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-500">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">{c.statutory_ref.source_doc}</span>
                  <span>•</span>
                  <span>{c.statutory_ref.clause}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Penalty Reference Drawer Modal */}
      {penaltyDrawerOpen && (
        <div
          className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm flex justify-end"
          role="dialog"
          aria-modal="true"
          onClick={() => setPenaltyDrawerOpen(false)}
        >
          <div
            className="w-full max-w-2xl bg-white dark:bg-slate-900 h-full overflow-y-auto p-6 sm:p-8 shadow-2xl flex flex-col justify-between"
            onClick={(e) => e.stopPropagation()}
          >
            <div>
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-indigo-600" />
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">Statutory Penalty Schedule Ceilings</h2>
                </div>
                <button
                  onClick={() => setPenaltyDrawerOpen(false)}
                  className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500"
                  aria-label="Close drawer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Mandatory Non-Liability Caveat Banner */}
              <div className="p-4 bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-900 rounded-xl mb-6 text-xs text-indigo-900 dark:text-indigo-200 leading-relaxed">
                <p className="font-bold mb-1">Mandatory Reference Notice (PEN-01..06):</p>
                <p>
                  Amounts shown reflect <strong>maximum statutory ceilings</strong> specified in the Schedule to the Digital Personal Data Protection Act, 2023. They do NOT represent an expected fine or predicted liability. Fine amounts are determined by the Data Protection Board on a case-by-case basis under Section 33 factors. Amounts must never be summed or aggregated.
                </p>
              </div>

              <div className="space-y-4">
                {penaltyItems.map((p) => (
                  <div key={p.schedule_item} className="p-4 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-xl">
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div>
                        <span className="text-xs font-mono font-bold text-indigo-600 dark:text-indigo-400">
                          Schedule Item {p.schedule_item} ({p.related_act_section})
                        </span>
                        <h4 className="font-semibold text-sm text-slate-900 dark:text-white mt-0.5">
                          {p.breach_description}
                        </h4>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <span className="px-2.5 py-1 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 rounded font-bold text-xs font-mono">
                          {p.statutory_ceiling}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-400 mb-2">
                      <span className="font-semibold">Context: </span>{p.plausibility_rationale}
                    </p>

                    <p className="text-[11px] font-mono text-amber-700 dark:text-amber-400 italic">
                      "{p.mandatory_caveat}"
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-6 border-t border-slate-200 dark:border-slate-800 flex justify-end">
              <button
                onClick={() => setPenaltyDrawerOpen(false)}
                className="w-full sm:w-auto px-5 py-2.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition cursor-pointer"
              >
                Close Reference Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
