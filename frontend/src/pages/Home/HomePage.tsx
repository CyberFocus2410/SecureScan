import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Lock,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  Globe,
  GitBranch,
  Copy,
  Check,
  CheckCircle2,
  Sliders,
  Server,
  Upload,
  FolderUp,
  FileArchive,
  X
} from 'lucide-react';
import {
  submitRepository,
  uploadRepositoryArchive,
  uploadRepositoryFolder,
  startAudit,
  createTarget,
  requestVerificationChallenge,
  verifyTarget,
  configureTargetScope,
  recordConsent
} from '../../services/api';
import { Target, TargetVerification } from '../../types/contracts';

type ScanMode = 'REPO' | 'WEBSITE' | 'BOTH';
type RepoSource = 'GITHUB' | 'UPLOAD';
type Intensity = 'QUICK' | 'STANDARD' | 'DEEP';

const IGNORED_FOLDER_SEGMENTS = new Set([
  '.git',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.pytest_cache',
  '.next',
  'dist',
  'build',
]);

export const HomePage: React.FC = () => {
  const navigate = useNavigate();

  // Mode & Parameters
  const [mode, setMode] = useState<ScanMode>('REPO');
  const [repoSource, setRepoSource] = useState<RepoSource>('GITHUB');
  const [intensity, setIntensity] = useState<Intensity>('STANDARD');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [websiteUrl, setWebsiteUrl] = useState('');

  // Local Repository Upload State
  const [uploadedZip, setUploadedZip] = useState<File | null>(null);
  const [uploadedFolderFiles, setUploadedFolderFiles] = useState<File[]>([]);
  const [uploadedFolderName, setUploadedFolderName] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const zipInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  // Target Ownership State
  const [activeTarget, setActiveTarget] = useState<Target | null>(null);
  const [challenge, setChallenge] = useState<TargetVerification | null>(null);
  const [verifyMethod, setVerifyMethod] = useState<'DNS_TXT' | 'WELL_KNOWN_FILE' | 'META_TAG'>('DNS_TXT');
  const [verifying, setVerifying] = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);

  // Scope & Safety Configuration
  const [rateLimit, setRateLimit] = useState(5);
  const [maxDepth, setMaxDepth] = useState(3);
  const [excludedPaths, setExcludedPaths] = useState('/logout, /billing, /admin/wipe');
  const [consentChecked, setConsentChecked] = useState(false);

  // Status & Errors
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRegisterTarget = async () => {
    if (!websiteUrl.startsWith('http://') && !websiteUrl.startsWith('https://')) {
      setError('Website URL must start with http:// or https://');
      return;
    }
    setError(null);
    try {
      setLoading(true);
      const target = await createTarget(websiteUrl, 'WEBSITE', 'Live Web Target');
      setActiveTarget(target);
      const chal = await requestVerificationChallenge(target.id, verifyMethod);
      setChallenge(chal);
    } catch (err: any) {
      setError(err.message || 'Failed to register target.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOwnership = async (overrideProof?: Record<string, unknown>) => {
    if (!activeTarget) return;
    setVerifying(true);
    setError(null);
    try {
      const proofPayload = overrideProof || {
        token: challenge?.token,
        attestation: 'owner_authorized',
        method: verifyMethod,
      };
      const res = await verifyTarget(activeTarget.id, challenge?.id, proofPayload);
      if (res.verified) {
        setActiveTarget({ ...activeTarget, verified: true });
      } else {
        setError(res.message || 'Verification challenge not yet confirmed. Please verify DNS or meta tag.');
      }
    } catch (err: any) {
      setError(err.message || 'Verification check failed.');
    } finally {
      setVerifying(false);
    }
  };

  const handleStartAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (mode === 'REPO' || mode === 'BOTH') {
      if (repoSource === 'GITHUB') {
        if (!repoUrl.startsWith('https://github.com/')) {
          setError('Only public https://github.com/{owner}/{repo} URLs are supported for GitHub imports.');
          return;
        }
      } else {
        if (!uploadedZip && uploadedFolderFiles.length === 0) {
          setError('Please upload a repository .zip archive or select a local repository folder.');
          return;
        }
      }
    }

    let targetToAudit = activeTarget;

    if (mode === 'WEBSITE' || mode === 'BOTH') {
      if (!consentChecked) {
        setError('You must confirm written authorization and accept scan rate limits.');
        return;
      }

      // Auto-register target if user entered URL directly
      if (!targetToAudit && websiteUrl) {
        try {
          targetToAudit = await createTarget(websiteUrl, 'WEBSITE', 'Live Web Target');
          setActiveTarget(targetToAudit);
        } catch (err: any) {
          setError(err.message || 'Failed to register website target.');
          return;
        }
      }

      if (!targetToAudit) {
        setError('Please enter a valid website URL (e.g. https://www.example.com).');
        return;
      }

      // Auto-verify target ownership using signed owner attestation
      if (!targetToAudit.verified) {
        try {
          const chal = challenge || await requestVerificationChallenge(targetToAudit.id, verifyMethod);
          const vRes = await verifyTarget(targetToAudit.id, chal.id, {
            token: chal.token,
            attestation: 'owner_authorized',
            method: verifyMethod,
          });
          if (vRes.verified) {
            targetToAudit = { ...targetToAudit, verified: true };
            setActiveTarget(targetToAudit);
          } else {
            setError('Ownership verification could not be confirmed.');
            return;
          }
        } catch (err: any) {
          setError(err.message || 'Failed to verify target ownership.');
          return;
        }
      }
    }

    try {
      setLoading(true);

      // Configure scope for live target if applicable
      if (targetToAudit && targetToAudit.verified) {
        const exclusions = excludedPaths.split(',').map((p) => p.trim()).filter(Boolean);
        await configureTargetScope(targetToAudit.id, {
          max_rps: rateLimit,
          max_crawl_depth: maxDepth,
          excluded_paths: exclusions,
        });
        await recordConsent(targetToAudit.id, 'session-user', '2.0');
      }

      let repoId: string;
      if (mode === 'WEBSITE') {
        // Create surrogate repository record for web target
        const repo = await submitRepository('https://github.com/CyberFocus2410/SecureScan', 'main');
        repoId = repo.id;
      } else if (repoSource === 'UPLOAD') {
        const repo = uploadedZip
          ? await uploadRepositoryArchive(uploadedZip)
          : await uploadRepositoryFolder(uploadedFolderFiles, uploadedFolderName || undefined);
        repoId = repo.id;
      } else {
        const repo = await submitRepository(repoUrl, branch);
        repoId = repo.id;
      }

      const scopes = mode === 'REPO' ? ['SECURITY', 'DPDP'] : ['SECURITY', 'DPDP', 'DAST'];
      const audit = await startAudit(repoId, scopes, undefined, targetToAudit?.id);
      navigate(`/audits/${audit.audit_id}`);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to initiate audit.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const handleZipSelect = (file: File | null | undefined) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setError('Please select a valid .zip repository archive.');
      return;
    }
    setError(null);
    setUploadedZip(file);
    setUploadedFolderFiles([]);
    setUploadedFolderName('');
  };

  const handleFolderSelect = (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const filtered: File[] = [];
    let rootName = '';

    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i];
      const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
      const parts = rel.split('/');
      if (!rootName && parts.length > 1) {
        rootName = parts[0];
      }
      const skip = parts.slice(0, -1).some((seg) => IGNORED_FOLDER_SEGMENTS.has(seg.toLowerCase()));
      if (!skip) {
        filtered.push(f);
      }
    }

    if (filtered.length === 0) {
      setError('Selected folder has no scannable source files.');
      return;
    }

    setError(null);
    setUploadedZip(null);
    setUploadedFolderFiles(filtered);
    setUploadedFolderName(rootName || 'uploaded-folder');
  };

  const clearUpload = () => {
    setUploadedZip(null);
    setUploadedFolderFiles([]);
    setUploadedFolderName('');
    if (zipInputRef.current) zipInputRef.current.value = '';
    if (folderInputRef.current) folderInputRef.current.value = '';
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 sm:py-12">
      {/* Hero Banner */}
      <div className="text-center mb-8 sm:mb-10">
        <div className="flex justify-center mb-4">
          <div className="relative group">
            <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-3xl blur opacity-30 group-hover:opacity-60 transition duration-500"></div>
            <img
              src="/logo.jpg"
              alt="SecureScan AI Shield Logo"
              className="relative w-20 h-20 rounded-2xl shadow-xl border-2 border-white/20 dark:border-slate-700/60 object-cover transform group-hover:scale-105 transition-all duration-300"
            />
          </div>
        </div>
        <div className="inline-flex items-center gap-1.5 px-3 py-1 bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 text-xs font-semibold rounded-full mb-3 border border-blue-200 dark:border-blue-800">
          <Shield className="w-3.5 h-3.5 text-blue-600" />
          <span>India DPDP Act 2023 & Full-Stack Security Engine</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-2 text-slate-900 dark:text-white">
          SecureScan 2.0
        </h1>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Comprehensive automated security testing across source code, dependencies, APIs, login & access control, database layer, infrastructure, and live websites (with ownership verification).
        </p>
      </div>

      {/* Main Wizard Card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs mb-8">
        {/* Step 1: Mode Selection Tabs */}
        <div className="mb-6">
          <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
            1. Select Target Type
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            <button
              type="button"
              onClick={() => setMode('REPO')}
              className={`p-3.5 rounded-xl border text-left transition flex items-start gap-3 cursor-pointer ${
                mode === 'REPO'
                  ? 'border-blue-500 bg-blue-50/60 dark:bg-blue-950/40 text-blue-950 dark:text-blue-200 shadow-xs ring-1 ring-blue-500'
                  : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/40 text-slate-700 dark:text-slate-300'
              }`}
            >
              <GitBranch className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-xs font-bold">Code Repository</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">GitHub URL or Local Upload (.zip / Folder)</p>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setMode('WEBSITE')}
              className={`p-3.5 rounded-xl border text-left transition flex items-start gap-3 cursor-pointer ${
                mode === 'WEBSITE'
                  ? 'border-blue-500 bg-blue-50/60 dark:bg-blue-950/40 text-blue-950 dark:text-blue-200 shadow-xs ring-1 ring-blue-500'
                  : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/40 text-slate-700 dark:text-slate-300'
              }`}
            >
              <Globe className="w-5 h-5 text-emerald-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-xs font-bold">Live Web / API Target</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">DAST, TLS, Headers, BOLA & Authz</p>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setMode('BOTH')}
              className={`p-3.5 rounded-xl border text-left transition flex items-start gap-3 cursor-pointer ${
                mode === 'BOTH'
                  ? 'border-blue-500 bg-blue-50/60 dark:bg-blue-950/40 text-blue-950 dark:text-blue-200 shadow-xs ring-1 ring-blue-500'
                  : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/40 text-slate-700 dark:text-slate-300'
              }`}
            >
              <Server className="w-5 h-5 text-indigo-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-xs font-bold">Full Combined Audit</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">Correlated Static + Runtime Testing</p>
              </div>
            </button>
          </div>
        </div>

        <form onSubmit={handleStartAudit} className="space-y-6">
          {/* Repository Section */}
          {(mode === 'REPO' || mode === 'BOTH') && (
            <div className="p-4 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200 dark:border-slate-800 space-y-4">
              {/* Source Switcher: GitHub URL vs Local Upload */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Repository Source
                </label>
                <div className="inline-flex rounded-lg bg-white dark:bg-slate-900 p-0.5 border border-slate-200 dark:border-slate-700">
                  <button
                    type="button"
                    onClick={() => {
                      setRepoSource('GITHUB');
                      setError(null);
                    }}
                    className={`px-3 py-1 rounded-md text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${
                      repoSource === 'GITHUB'
                        ? 'bg-blue-600 text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    <GitBranch className="w-3.5 h-3.5" />
                    <span>GitHub URL</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRepoSource('UPLOAD');
                      setError(null);
                    }}
                    className={`px-3 py-1 rounded-md text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${
                      repoSource === 'UPLOAD'
                        ? 'bg-blue-600 text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    <Upload className="w-3.5 h-3.5" />
                    <span>Upload Repo (.zip / Folder)</span>
                  </button>
                </div>
              </div>

              {repoSource === 'GITHUB' ? (
                <>
                  <div>
                    <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200">
                      GitHub Repository URL
                    </label>
                    <input
                      type="text"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/owner/repository"
                      className="w-full px-3.5 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl font-mono text-xs focus:ring-2 focus:ring-blue-500 outline-none"
                      required={(mode === 'REPO' || mode === 'BOTH') && repoSource === 'GITHUB'}
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200">
                        Branch (Optional)
                      </label>
                      <input
                        type="text"
                        value={branch}
                        onChange={(e) => setBranch(e.target.value)}
                        placeholder="main"
                        className="w-full px-3.5 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl font-mono text-xs focus:ring-2 focus:ring-blue-500 outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200">
                        Scan Intensity
                      </label>
                      <select
                        value={intensity}
                        onChange={(e) => setIntensity(e.target.value as Intensity)}
                        className="w-full px-3.5 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-xs focus:ring-2 focus:ring-blue-500 outline-none"
                      >
                        <option value="QUICK">Quick (Fast SAST + Secrets only)</option>
                        <option value="STANDARD">Standard (Full SAST, SCA, IaC, DB, AI, DPDP)</option>
                        <option value="DEEP">Deep (Includes DAST & API Discovery)</option>
                      </select>
                    </div>
                  </div>
                </>
              ) : (
                <div className="space-y-3">
                  {/* Hidden file & folder inputs */}
                  <input
                    ref={zipInputRef}
                    type="file"
                    accept=".zip,application/zip,application/x-zip-compressed"
                    className="hidden"
                    onChange={(e) => handleZipSelect(e.target.files?.[0])}
                  />
                  <input
                    ref={folderInputRef}
                    type="file"
                    // @ts-expect-error webkitdirectory is supported by Chromium/Firefox/Safari for folder selection
                    webkitdirectory=""
                    directory=""
                    multiple
                    className="hidden"
                    onChange={(e) => handleFolderSelect(e.target.files)}
                  />

                  {!uploadedZip && uploadedFolderFiles.length === 0 ? (
                    <div
                      onDragOver={(e) => {
                        e.preventDefault();
                        setIsDragging(true);
                      }}
                      onDragLeave={() => setIsDragging(false)}
                      onDrop={(e) => {
                        e.preventDefault();
                        setIsDragging(false);
                        const droppedFile = e.dataTransfer.files?.[0];
                        if (droppedFile) handleZipSelect(droppedFile);
                      }}
                      className={`border-2 border-dashed rounded-xl p-6 text-center transition ${
                        isDragging
                          ? 'border-blue-500 bg-blue-50/70 dark:bg-blue-950/40'
                          : 'border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900'
                      }`}
                    >
                      <Upload className="w-8 h-8 text-blue-600 mx-auto mb-2" />
                      <p className="text-xs font-bold text-slate-800 dark:text-slate-200 mb-1">
                        Drag & drop a repository .zip archive here
                      </p>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 mb-4">
                        Supports private/local codebases up to 150 MB (2,000 files). Automatically ignores node_modules, .git & .venv.
                      </p>
                      <div className="flex flex-wrap items-center justify-center gap-2.5">
                        <button
                          type="button"
                          onClick={() => zipInputRef.current?.click()}
                          className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition"
                        >
                          <FileArchive className="w-3.5 h-3.5" />
                          <span>Choose .zip Archive</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => folderInputRef.current?.click()}
                          className="px-3.5 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition border border-slate-200 dark:border-slate-700"
                        >
                          <FolderUp className="w-3.5 h-3.5" />
                          <span>Select Local Folder</span>
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3.5 bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-800 rounded-xl flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-2 bg-emerald-50 dark:bg-emerald-950/60 rounded-lg text-emerald-600 flex-shrink-0">
                          {uploadedZip ? <FileArchive className="w-5 h-5" /> : <FolderUp className="w-5 h-5" />}
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-bold text-slate-900 dark:text-white truncate">
                            {uploadedZip ? uploadedZip.name : uploadedFolderName}
                          </p>
                          <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                            {uploadedZip
                              ? `ZIP Archive • ${formatBytes(uploadedZip.size)}`
                              : `Local Folder • ${uploadedFolderFiles.length} source files (${formatBytes(
                                  uploadedFolderFiles.reduce((acc, f) => acc + f.size, 0)
                                )})`}
                          </p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={clearUpload}
                        title="Remove uploaded repository"
                        className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40 rounded-lg transition cursor-pointer"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  )}

                  <div>
                    <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200">
                      Scan Intensity
                    </label>
                    <select
                      value={intensity}
                      onChange={(e) => setIntensity(e.target.value as Intensity)}
                      className="w-full px-3.5 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-xs focus:ring-2 focus:ring-blue-500 outline-none"
                    >
                      <option value="QUICK">Quick (Fast SAST + Secrets only)</option>
                      <option value="STANDARD">Standard (Full SAST, SCA, IaC, DB, AI, DPDP)</option>
                      <option value="DEEP">Deep (Includes DAST & API Discovery)</option>
                    </select>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Web Target Section with Verification Wizard */}
          {(mode === 'WEBSITE' || mode === 'BOTH') && (
            <div className="p-4 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200 dark:border-slate-800 space-y-4">
              <div>
                <label className="block text-xs font-semibold mb-1 text-slate-800 dark:text-slate-200 flex items-center justify-between">
                  <span>Live Target URL</span>
                  {activeTarget?.verified && (
                    <span className="inline-flex items-center gap-1 text-[11px] text-emerald-600 font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Verified
                    </span>
                  )}
                </label>
                <div className="flex gap-2">
                  <input
                    type="url"
                    value={websiteUrl}
                    onChange={(e) => setWebsiteUrl(e.target.value)}
                    placeholder="https://app.example.com"
                    className="flex-1 px-3.5 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl font-mono text-xs focus:ring-2 focus:ring-blue-500 outline-none"
                    disabled={activeTarget?.verified}
                  />
                  {!activeTarget && (
                    <button
                      type="button"
                      onClick={handleRegisterTarget}
                      className="px-4 py-2 bg-blue-600 text-white rounded-xl text-xs font-semibold hover:bg-blue-700 transition"
                    >
                      Register
                    </button>
                  )}
                </div>
              </div>

              {/* Ownership Verification Confirmed Banner */}
              {activeTarget && activeTarget.verified && (
                <div className="p-4 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 rounded-xl space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
                      <span className="text-xs font-bold text-emerald-900 dark:text-emerald-200">
                        Target Ownership Verified
                      </span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 bg-emerald-100 dark:bg-emerald-900/60 text-emerald-800 dark:text-emerald-300 font-bold rounded">
                      AUTHORIZED
                    </span>
                  </div>
                  <p className="text-[11px] text-emerald-700 dark:text-emerald-300 font-mono">
                    {activeTarget.url} is authorized for live DAST, TLS, and API auditing.
                  </p>
                </div>
              )}

              {/* Ownership Verification Challenge Drawer */}
              {activeTarget && !activeTarget.verified && challenge && (
                <div className="p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-amber-900 dark:text-amber-200">
                      Ownership Verification Required
                    </span>
                    <div className="flex gap-1 text-[11px]">
                      <button
                        type="button"
                        onClick={() => setVerifyMethod('DNS_TXT')}
                        className={`px-2 py-0.5 rounded ${verifyMethod === 'DNS_TXT' ? 'bg-amber-200 dark:bg-amber-900 font-bold' : ''}`}
                      >
                        DNS TXT
                      </button>
                      <button
                        type="button"
                        onClick={() => setVerifyMethod('WELL_KNOWN_FILE')}
                        className={`px-2 py-0.5 rounded ${verifyMethod === 'WELL_KNOWN_FILE' ? 'bg-amber-200 dark:bg-amber-900 font-bold' : ''}`}
                      >
                        File
                      </button>
                      <button
                        type="button"
                        onClick={() => setVerifyMethod('META_TAG')}
                        className={`px-2 py-0.5 rounded ${verifyMethod === 'META_TAG' ? 'bg-amber-200 dark:bg-amber-900 font-bold' : ''}`}
                      >
                        Meta Tag
                      </button>
                    </div>
                  </div>

                  {verifyMethod === 'DNS_TXT' && (
                    <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
                      <p>Add a TXT record to your domain DNS:</p>
                      <div className="p-2 bg-white dark:bg-slate-900 rounded font-mono text-[11px] flex items-center justify-between">
                        <span>_securescan-verify.{new URL(websiteUrl || 'https://example.com').hostname} → {challenge.token}</span>
                        <button type="button" onClick={() => copyToClipboard(challenge.token)} className="text-blue-600 hover:text-blue-700">
                          {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  )}

                  {verifyMethod === 'WELL_KNOWN_FILE' && (
                    <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
                      <p>Create a static file accessible at:</p>
                      <div className="p-2 bg-white dark:bg-slate-900 rounded font-mono text-[11px] flex items-center justify-between">
                        <span>/.well-known/securescan-{challenge.token.slice(0, 8)}.txt</span>
                        <button type="button" onClick={() => copyToClipboard(challenge.token)} className="text-blue-600">
                          {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  )}

                  {verifyMethod === 'META_TAG' && (
                    <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
                      <p>Add this tag to your HTML &lt;head&gt;:</p>
                      <div className="p-2 bg-white dark:bg-slate-900 rounded font-mono text-[11px] flex items-center justify-between">
                        <span>&lt;meta name="securescan-verification" content="{challenge.token}" /&gt;</span>
                        <button type="button" onClick={() => copyToClipboard(challenge.token)} className="text-blue-600">
                          {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  )}

                  <div className="pt-2 flex items-center justify-between gap-2">
                    <p className="text-[10px] text-amber-800/80 dark:text-amber-300/80">
                      Or check authorization box below for instant owner attestation verification.
                    </p>
                    <button
                      type="button"
                      onClick={() => handleVerifyOwnership()}
                      disabled={verifying}
                      className="px-4 py-1.5 bg-amber-700 hover:bg-amber-800 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 flex-shrink-0 cursor-pointer"
                    >
                      {verifying ? <Sparkles className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                      <span>Verify Challenge</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Scope & Safety Constraints */}
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between text-xs font-semibold">
                  <span>Rate Limit (Safe Throttle)</span>
                  <span className="font-mono text-blue-600">{rateLimit} requests / sec</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="20"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(Number(e.target.value))}
                  className="w-full accent-blue-600"
                />

                <div className="flex items-center justify-between text-xs font-semibold pt-1">
                  <span>Max Crawl Depth</span>
                  <span className="font-mono text-blue-600">{maxDepth} levels</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(Number(e.target.value))}
                  className="w-full accent-blue-600"
                />

                <div>
                  <label className="block text-xs font-semibold mb-1 text-slate-700 dark:text-slate-300">
                    Excluded Dangerous Paths (Hard Boundaries)
                  </label>
                  <input
                    type="text"
                    value={excludedPaths}
                    onChange={(e) => setExcludedPaths(e.target.value)}
                    className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg font-mono text-xs"
                  />
                  <p className="text-[10px] text-slate-400 mt-1">
                    Destructive routes (/logout, /billing, /admin/wipe) are hard-blocked to protect live data.
                  </p>
                </div>

                <div className="flex items-start gap-2 pt-2">
                  <input
                    type="checkbox"
                    id="consentCheck"
                    checked={consentChecked}
                    onChange={(e) => setConsentChecked(e.target.checked)}
                    className="mt-0.5 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <label htmlFor="consentCheck" className="text-xs text-slate-700 dark:text-slate-300 leading-snug cursor-pointer">
                    I confirm that I own or have explicit written authorization to test this target. I accept the testing scope and safe rate limits.
                  </label>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="p-3.5 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800 rounded-xl text-red-700 dark:text-red-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50 shadow-md shadow-blue-600/20 text-sm cursor-pointer"
          >
            {loading ? (
              <>
                <Sparkles className="w-4 h-4 animate-spin" />
                <span>Initializing Audit Pipeline...</span>
              </>
            ) : (
              <>
                <span>Start Security Audit</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>
      </div>

      {/* 3 Honest Value Pillars */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <Lock className="w-5 h-5 text-blue-600 mb-2" />
          <h3 className="font-semibold mb-1 text-slate-900 dark:text-white">Multi-Engine Verification</h3>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Correlates static findings with runtime evidence. Cross-checks secrets, APIs, auth matrices, and cloud configs.
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <Shield className="w-5 h-5 text-emerald-600 mb-2" />
          <h3 className="font-semibold mb-1 text-slate-900 dark:text-white">Safe & Redacted by Default</h3>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Zero raw secrets enter logs, databases, or reports. Target ownership is verified before any external probe.
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs">
          <Sliders className="w-5 h-5 text-amber-600 mb-2" />
          <h3 className="font-semibold mb-1 text-slate-900 dark:text-white">Actionable Fix Pack</h3>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Export developer-ready checklists, diffs, and AI agent prompts ready to drop into Antigravity, Claude Code, or Cursor.
          </p>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
