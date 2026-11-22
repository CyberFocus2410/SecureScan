import React from 'react';
import { SecondaryScores } from '../types/contracts';
import { ShieldAlert, ShieldCheck, Shield, AlertTriangle } from 'lucide-react';

interface RiskScorecardGaugeProps {
  scores: SecondaryScores;
}

export const RiskScorecardGauge: React.FC<RiskScorecardGaugeProps> = ({ scores }) => {
  const metrics = [
    { name: 'Security', score: scores.security_score, color: '#ef4444', textClass: 'text-red-600 dark:text-red-400', bgClass: 'bg-red-50 dark:bg-red-950/30' },
    { name: 'Privacy', score: scores.privacy_score, color: '#f59e0b', textClass: 'text-amber-600 dark:text-amber-400', bgClass: 'bg-amber-50 dark:bg-amber-950/30' },
    { name: 'Infrastructure', score: scores.infrastructure_score, color: '#3b82f6', textClass: 'text-blue-600 dark:text-blue-400', bgClass: 'bg-blue-50 dark:bg-blue-950/30' },
    { name: 'Supply Chain', score: scores.supply_chain_score, color: '#10b981', textClass: 'text-emerald-600 dark:text-emerald-400', bgClass: 'bg-emerald-50 dark:bg-emerald-950/30' },
    { name: 'DPDP Readiness', score: scores.dpdp_readiness_score, color: '#8b5cf6', textClass: 'text-purple-600 dark:text-purple-400', bgClass: 'bg-purple-50 dark:bg-purple-950/30' },
  ];

  const overallAvg = Math.round(
    (scores.security_score +
      scores.privacy_score +
      scores.infrastructure_score +
      scores.supply_chain_score +
      scores.dpdp_readiness_score) /
      5
  );

  const getRiskBadge = (rating: string) => {
    const r = rating.toLowerCase();
    if (r.includes('critical') || r.includes('high')) {
      return {
        icon: <ShieldAlert className="w-4 h-4 text-red-500" />,
        className: 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300 border-red-300 dark:border-red-800',
        label: rating,
      };
    }
    if (r.includes('moderate')) {
      return {
        icon: <Shield className="w-4 h-4 text-yellow-500" />,
        className: 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-300 dark:border-amber-800',
        label: rating,
      };
    }
    return {
      icon: <ShieldCheck className="w-4 h-4 text-emerald-500" />,
      className: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800',
      label: rating,
    };
  };

  const badge = getRiskBadge(scores.overall_rating);

  // SVG Radial Gauge Geometry
  const size = 260;
  const center = size / 2;
  const strokeWidth = 10;
  const gap = 6;
  const startRadius = 40;

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-slate-100 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-600 animate-pulse"></span>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              Multi-Dimensional Posture Gauge
            </h3>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            5-pillar architectural evaluation with Section 8(5) statutory hard-cap enforcement.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className={`px-3 py-1 rounded-full border text-xs font-bold flex items-center gap-1.5 shadow-xs ${badge.className}`}>
            {badge.icon}
            <span className="uppercase tracking-wider">{badge.label}</span>
          </div>
          {scores.hard_cap_applied && (
            <span className="px-2.5 py-1 bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300 border border-red-300 dark:border-red-900 rounded-lg text-xs font-bold flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Capped 60</span>
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* SVG Radial Gauge Chart */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center relative">
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="transform -rotate-90">
            {metrics.map((m, idx) => {
              const radius = startRadius + idx * (strokeWidth + gap);
              const circumference = 2 * Math.PI * radius;
              const normalizedScore = Math.max(0, Math.min(100, m.score));
              const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

              return (
                <g key={m.name}>
                  {/* Background Track */}
                  <circle
                    cx={center}
                    cy={center}
                    r={radius}
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={strokeWidth}
                    className="text-slate-100 dark:text-slate-800/80"
                  />
                  {/* Active Value Arc */}
                  <circle
                    cx={center}
                    cy={center}
                    r={radius}
                    fill="none"
                    stroke={m.color}
                    strokeWidth={strokeWidth}
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    className="transition-all duration-1000 ease-out"
                  />
                </g>
              );
            })}
          </svg>

          {/* Centered Score */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
              {overallAvg}
            </span>
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Avg Score
            </span>
          </div>
        </div>

        {/* Breakdown Progress Bars */}
        <div className="lg:col-span-7 space-y-3">
          {metrics.map((m, idx) => {
            return (
              <div key={m.name} className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800/60">
                <div className="flex items-center justify-between text-xs mb-1">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-3 h-3 rounded-full flex-shrink-0"
                      style={{ backgroundColor: m.color }}
                      title={`Radial Ring #${idx + 1}`}
                    />
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{m.name}</span>
                  </div>
                  <span className={`font-mono font-extrabold ${m.textClass}`}>{m.score} / 100</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-700 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${m.score}%`, backgroundColor: m.color }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
