import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { HomePage } from './pages/Home/HomePage';
import { AuditProgressPage } from './pages/AuditProgress/AuditProgressPage';
import { SecurityPage } from './pages/Security/SecurityPage';
import { DPDPPage } from './pages/DPDP/DPDPPage';
import { FindingDetailPage } from './pages/Finding/FindingDetailPage';
import { ReportPage } from './pages/Report/ReportPage';

const queryClient = new QueryClient();

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
          <header className="border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur sticky top-0 z-50">
            <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
              <Link to="/" className="flex items-center gap-3 font-bold text-lg text-slate-900 dark:text-white group">
                <img
                  src="/logo.jpg"
                  alt="SecureScan AI Logo"
                  className="w-8 h-8 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 object-cover group-hover:scale-105 transition-transform"
                />
                <span className="tracking-tight">SecureScan AI</span>
              </Link>
              <div className="flex items-center gap-4 text-xs font-mono text-slate-500">
                <span>as_of_date: 2026-11-14</span>
                <span className="w-2 h-2 rounded-full bg-emerald-500" title="API Ready"></span>
              </div>
            </div>
          </header>

          <main className="flex-1">
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/audits/:auditId" element={<AuditProgressPage />} />
              <Route path="/audits/:auditId/security" element={<SecurityPage />} />
              <Route path="/audits/:auditId/dpdp" element={<DPDPPage />} />
              <Route path="/audits/:auditId/report" element={<ReportPage />} />
              <Route path="/findings/:findingId" element={<FindingDetailPage />} />
            </Routes>
          </main>

          <footer className="border-t border-slate-200 dark:border-slate-800 py-6 text-center text-xs text-slate-500">
            <div className="flex items-center justify-center gap-2 mb-2">
              <img src="/logo.jpg" alt="SecureScan AI" className="w-5 h-5 rounded object-cover opacity-85 shadow-sm" />
              <span className="font-semibold text-slate-700 dark:text-slate-300">SecureScan AI</span>
            </div>
            <p>Developer-assistance static audit & DPDP readiness engine. Not a legal opinion or compliance certificate.</p>
          </footer>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
};
export default App;

