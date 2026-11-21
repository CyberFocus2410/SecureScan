import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { HomePage } from './pages/Home/HomePage';
import { AuditProgressPage } from './pages/AuditProgress/AuditProgressPage';
import { SecurityPage } from './pages/Security/SecurityPage';
import { DPDPPage } from './pages/DPDP/DPDPPage';
import { FindingDetailPage } from './pages/Finding/FindingDetailPage';
import { ReportPage } from './pages/Report/ReportPage';
import { ToolHealthPage } from './pages/Admin/ToolHealthPage';
import { ComparePage } from './pages/Compare/ComparePage';
import { PWAInstallPrompt } from './components/PWAInstallPrompt';

const queryClient = new QueryClient();

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 overflow-x-hidden">
          <header className="border-b border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 backdrop-blur sticky top-0 z-40">
            <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
              <Link to="/" className="flex items-center gap-2.5 font-bold text-base sm:text-lg text-slate-900 dark:text-white group flex-shrink-0">
                <img
                  src="/logo.jpg"
                  alt="SecureScan AI Logo"
                  className="w-8 h-8 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 object-cover group-hover:scale-105 transition-transform"
                />
                <span className="tracking-tight font-extrabold bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                  SecureScan 2.0
                </span>
              </Link>
              <div className="flex items-center gap-3 sm:gap-5 text-xs font-mono text-slate-500">
                <Link to="/" className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors font-sans text-xs font-medium">
                  New Audit
                </Link>
                <Link to="/compare" className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors font-sans text-xs font-medium">
                  Compare
                </Link>
                <Link to="/admin/tools" className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors font-sans text-xs font-medium">
                  Tool Health
                </Link>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                  <span className="text-[11px] font-semibold">Ready</span>
                </span>
              </div>
            </div>
          </header>

          <main className="flex-1 w-full max-w-full overflow-x-hidden">
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/audits/:auditId" element={<AuditProgressPage />} />
              <Route path="/audits/:auditId/security" element={<SecurityPage />} />
              <Route path="/audits/:auditId/dpdp" element={<DPDPPage />} />
              <Route path="/audits/:auditId/report" element={<ReportPage />} />
              <Route path="/audits/:auditId/compare" element={<ComparePage />} />
              <Route path="/compare" element={<ComparePage />} />
              <Route path="/findings/:findingId" element={<FindingDetailPage />} />
              <Route path="/admin/tools" element={<ToolHealthPage />} />
            </Routes>
          </main>

          <PWAInstallPrompt />

          <footer className="border-t border-slate-200 dark:border-slate-800 py-6 px-4 text-center text-xs text-slate-500">
            <div className="flex items-center justify-center gap-2 mb-2">
              <img src="/logo.jpg" alt="SecureScan AI" className="w-5 h-5 rounded object-cover opacity-85 shadow-sm" />
              <span className="font-semibold text-slate-700 dark:text-slate-300">SecureScan 2.0</span>
            </div>
            <p className="max-w-xl mx-auto leading-relaxed">
              Developer-assistance automated security testing & DPDP readiness engine. Not a legal opinion, penetration test, or compliance certificate.
            </p>
          </footer>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
};
export default App;
