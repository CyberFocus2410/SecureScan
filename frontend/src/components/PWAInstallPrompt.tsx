import React, { useState, useEffect } from 'react';
import { Download, X, Smartphone, Share, PlusSquare, ShieldCheck } from 'lucide-react';

interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{
    outcome: 'accepted' | 'dismissed';
    platform: string;
  }>;
  prompt(): Promise<void>;
}

export const PWAInstallPrompt: React.FC = () => {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [showPrompt, setShowPrompt] = useState(false);
  const [isIOS, setIsIOS] = useState(false);
  const [isStandalone, setIsStandalone] = useState(false);

  useEffect(() => {
    // Check if already in standalone PWA mode
    const isStandaloneMode = window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as unknown as { standalone?: boolean }).standalone === true;
    setIsStandalone(isStandaloneMode);

    if (isStandaloneMode) return;

    // Detect iOS devices
    const userAgent = window.navigator.userAgent.toLowerCase();
    const isIosDevice = /iphone|ipad|ipod/.test(userAgent);
    setIsIOS(isIosDevice);

    // Listen for beforeinstallprompt event (Android, Chrome, Edge)
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
      // Check if user dismissed prompt recently
      const dismissedUntil = localStorage.getItem('pwa_install_dismissed_until');
      if (!dismissedUntil || Date.now() > parseInt(dismissedUntil, 10)) {
        setShowPrompt(true);
      }
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    // For iOS devices: show install guide after 2 seconds if not dismissed
    if (isIosDevice) {
      const dismissedUntil = localStorage.getItem('pwa_install_dismissed_until');
      if (!dismissedUntil || Date.now() > parseInt(dismissedUntil, 10)) {
        const timer = setTimeout(() => {
          setShowPrompt(true);
        }, 2000);
        return () => {
          clearTimeout(timer);
          window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
        };
      }
    }

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    };
  }, []);

  const handleInstallClick = async () => {
    if (!deferredPrompt) return;
    setShowPrompt(false);
    await deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      setDeferredPrompt(null);
    }
  };

  const handleDismiss = () => {
    setShowPrompt(false);
    // Dismiss for 24 hours
    localStorage.setItem('pwa_install_dismissed_until', (Date.now() + 24 * 60 * 60 * 1000).toString());
  };

  if (isStandalone || !showPrompt) {
    return null;
  }

  return (
    <aside aria-label="App installation banner" className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-6 sm:bottom-6 sm:max-w-md z-50 animate-in fade-in slide-in-from-bottom-5 duration-300">
      <div className="bg-slate-900 text-white border border-slate-700/80 rounded-2xl p-5 shadow-2xl backdrop-blur-lg bg-slate-900/95 ring-1 ring-white/10">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-3">
            <div className="relative">
              <img
                src="/logo.jpg"
                alt="SecureScan AI Logo"
                className="w-12 h-12 rounded-xl object-cover border border-white/20 shadow-md"
              />
              <span className="absolute -bottom-1 -right-1 w-4 h-4 bg-emerald-500 border-2 border-slate-900 rounded-full flex items-center justify-center">
                <ShieldCheck className="w-2.5 h-2.5 text-white" />
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-sm text-white">Install SecureScan AI</h3>
                <span className="px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded">App</span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Use as native mobile app with instant launch</p>
            </div>
          </div>
          <button
            onClick={handleDismiss}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
            aria-label="Close install banner"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {isIOS ? (
          <div className="text-xs text-slate-300 bg-slate-800/80 rounded-xl p-3 mb-3 border border-slate-700/60 space-y-1.5">
            <p className="font-semibold text-blue-400 flex items-center gap-1.5">
              <Smartphone className="w-3.5 h-3.5" /> Install on your iPhone / iPad:
            </p>
            <p className="flex items-center gap-1.5">
              1. Tap the Share button <Share className="w-3.5 h-3.5 text-blue-400" /> at bottom of Safari.
            </p>
            <p className="flex items-center gap-1.5">
              2. Scroll down & select <PlusSquare className="w-3.5 h-3.5 text-emerald-400" /> <span className="font-semibold text-white">Add to Home Screen</span>.
            </p>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs text-slate-300 mb-4 bg-slate-800/60 rounded-xl p-2.5 border border-slate-800">
            <Smartphone className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>Install on mobile or desktop for full-screen audits and zero browser bar clutter.</span>
          </div>
        )}

        <div className="flex items-center gap-2.5">
          {!isIOS && deferredPrompt && (
            <button
              onClick={handleInstallClick}
              className="flex-1 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 transition shadow-lg shadow-blue-600/25"
            >
              <Download className="w-4 h-4" />
              <span>Install App</span>
            </button>
          )}
          <button
            onClick={handleDismiss}
            className={`py-2.5 px-4 bg-slate-800 hover:bg-slate-700 active:bg-slate-850 text-slate-300 font-medium rounded-xl text-xs transition ${
              isIOS || !deferredPrompt ? 'w-full text-center' : ''
            }`}
          >
            {isIOS ? 'Got It' : 'Maybe Later'}
          </button>
        </div>
      </div>
    </aside>
  );
};
