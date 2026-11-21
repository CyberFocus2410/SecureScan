import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { fetchToolHealth, ToolHealthResponse } from '../../services/api';

export const ToolHealthPage: React.FC = () => {
  const { data, isLoading, error, refetch, isFetching } = useQuery<ToolHealthResponse>({
    queryKey: ['admin-tools'],
    queryFn: fetchToolHealth,
    staleTime: 10000,
  });

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Breadcrumb & Navigation */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Link to="/" className="hover:text-slate-800 dark:hover:text-slate-200">
            Home
          </Link>
          <span>/</span>
          <span className="font-semibold text-slate-900 dark:text-slate-100">Tool Health & Diagnostics</span>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-50 transition-colors shadow-sm"
        >
          <span className={isFetching ? 'animate-spin' : ''}>↻</span>
          {isFetching ? 'Running Self-Tests...' : 'Re-run Diagnostics'}
        </button>
      </div>

      {/* Title */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-3">
          Tool Doctor & Sandbox Health
          {data && (
            <span
              className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider ${
                data.status === 'HEALTHY'
                  ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800'
                  : 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-400 border border-amber-300 dark:border-amber-800'
              }`}
            >
              {data.status}
            </span>
          )}
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Self-test diagnostics across all 10 security tool areas and active sandbox backend isolation (Architecture §5, ADR-002).
        </p>
      </div>

      {isLoading && (
        <div className="py-20 text-center">
          <div className="w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-sm text-slate-500">Running diagnostic self-tests against sandbox fixtures...</p>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-rose-800 dark:text-rose-300 text-sm">
          Failed to load tool diagnostic report: {(error as Error).message}
        </div>
      )}

      {data && (
        <div className="space-y-6">
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
              <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Active Sandbox Engine</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white mt-1 capitalize flex items-center gap-2">
                <span>{data.sandbox.active_engine}</span>
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              </div>
              <div className="text-xs text-slate-500 mt-1">
                Env: <span className="font-mono">{data.sandbox.environment}</span> (Fail-Closed: {data.sandbox.fail_closed_enforced ? 'Yes' : 'No'})
              </div>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
              <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Total Scanners</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">{data.total_areas} Areas</div>
              <div className="text-xs text-slate-500 mt-1">100% verification coverage</div>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
              <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Primary Tools Active</div>
              <div className="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-1">
                {data.primary_count} Installed
              </div>
              <div className="text-xs text-slate-500 mt-1">Hardware / Container binaries</div>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
              <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Fallback Chains Active</div>
              <div className="text-lg font-bold text-blue-600 dark:text-blue-400 mt-1">
                {data.fallback_count} Operational
              </div>
              <div className="text-xs text-slate-500 mt-1">Zero downtime degraded execution</div>
            </div>
          </div>

          {/* Tools Status Table */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden bg-white dark:bg-slate-900 shadow-sm">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/50 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Security Tool Status Matrix</h2>
              <span className="text-xs font-mono text-slate-500">Section 5 Compliance</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 bg-slate-50 dark:bg-slate-800/30">
                    <th className="py-3 px-4 font-semibold">Area</th>
                    <th className="py-3 px-4 font-semibold">Status</th>
                    <th className="py-3 px-4 font-semibold">Active Engine</th>
                    <th className="py-3 px-4 font-semibold">Primary Tool</th>
                    <th className="py-3 px-4 font-semibold">Primary Version</th>
                    <th className="py-3 px-4 font-semibold">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {data.tools.map((tool) => (
                    <tr key={tool.category} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-medium text-slate-900 dark:text-white whitespace-nowrap">
                        {tool.category}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {tool.status === 'PASS' ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                            PASS
                          </span>
                        ) : tool.status === 'FALLBACK_ACTIVE' ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800">
                            <span className="w-1.5 h-1.5 rounded-full bg-sky-500"></span>
                            FALLBACK ACTIVE
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-800">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                            FAIL
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-700 dark:text-slate-300 whitespace-nowrap">
                        {tool.active_engine}
                      </td>
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-400 whitespace-nowrap">
                        {tool.primary_tool}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-500 whitespace-nowrap">
                        {tool.primary_version || '—'}
                      </td>
                      <td className="py-3 px-4 text-slate-500 text-[11px] max-w-xs truncate" title={tool.details}>
                        {tool.details}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
