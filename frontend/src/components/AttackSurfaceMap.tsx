import React, { useMemo, useState } from 'react';
import { AttackSurfaceData, AttackSurfaceNode, Finding } from '../types/contracts';
import {
  Globe,
  Database,
  Server,
  Cloud,
  AlertTriangle,
  Filter,
  Layers
} from 'lucide-react';

interface AttackSurfaceMapProps {
  data?: AttackSurfaceData | null;
  findings: Finding[];
}

export const AttackSurfaceMap: React.FC<AttackSurfaceMapProps> = ({ data, findings }) => {
  const [selectedNode, setSelectedNode] = useState<AttackSurfaceNode | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>('ALL');

  // Fallback generation if backend data not yet loaded
  const topology = useMemo(() => {
    if (data && data.nodes && data.nodes.length > 0) {
      return data;
    }

    // Client-side fallback derivation from findings
    const nodes: AttackSurfaceNode[] = [];
    const edges: { source: string; target: string }[] = [];
    const seen = new Set<string>();

    const rootRisk = findings.some(f => f.priority === 'P0' || f.severity === 'CRITICAL')
      ? 'high'
      : findings.some(f => f.priority === 'P1' || f.severity === 'HIGH')
      ? 'medium'
      : 'low';

    nodes.push({
      id: 'root',
      label: 'Audited Application',
      type: 'root',
      risk_level: rootRisk,
      details: 'Core application gateway and runtime environment',
      findings_count: findings.length
    });
    seen.add('root');

    // Extract routes from findings
    const routeRegex = /\/([a-zA-Z0-9_\-{}]+(?:\/[a-zA-Z0-9_\-{}]+)*)/g;
    const extractedRoutes = new Map<string, { risk: 'high' | 'medium' | 'low'; count: number }>();

    findings.forEach(f => {
      const text = `${f.title} ${f.description}`;
      const matches = text.match(routeRegex);
      const risk: 'high' | 'medium' | 'low' =
        f.priority === 'P0' || f.severity === 'CRITICAL' ? 'high' : f.priority === 'P1' ? 'medium' : 'low';

      if (matches) {
        matches.forEach(m => {
          if (m.length > 2 && !m.endsWith('.py') && !m.endsWith('.ts') && !m.endsWith('.json')) {
            const clean = m.split(' ')[0].replace(/[,.;:'")]$/, '');
            const existing = extractedRoutes.get(clean);
            if (!existing) {
              extractedRoutes.set(clean, { risk, count: 1 });
            } else {
              existing.count += 1;
              if (risk === 'high') existing.risk = 'high';
            }
          }
        });
      }
    });

    let rIdx = 0;
    extractedRoutes.forEach((info, rPath) => {
      if (rIdx < 6) {
        const nid = `route_${rIdx}`;
        nodes.push({
          id: nid,
          label: rPath,
          type: 'route',
          risk_level: info.risk,
          details: `Discovered API endpoint (${info.count} finding(s))`,
          findings_count: info.count
        });
        edges.push({ source: 'root', target: nid });
        rIdx++;
      }
    });

    // Check for databases & processors
    const hasDb = findings.some(f => f.file_path.includes('schema') || f.file_path.includes('models') || f.file_path.includes('db'));
    if (hasDb) {
      nodes.push({
        id: 'db_primary',
        label: 'Relational Database / Models',
        type: 'database',
        risk_level: findings.some(f => f.category === 'database' || f.file_path.includes('schema_insecure')) ? 'high' : 'low',
        details: 'Entity persistence and storage tier',
        findings_count: 2
      });
      edges.push({ source: 'root', target: 'db_primary' });
    }

    const hasCloud = findings.some(f => f.title.toLowerCase().includes('s3') || f.file_path.includes('docker') || f.file_path.includes('iac'));
    if (hasCloud) {
      nodes.push({
        id: 'cloud_infra',
        label: 'Cloud Infrastructure / S3',
        type: 'external',
        risk_level: findings.some(f => f.title.toLowerCase().includes('s3') && f.priority === 'P0') ? 'high' : 'medium',
        details: 'Cloud hosting, storage buckets & containers',
        findings_count: 3
      });
      edges.push({ source: 'root', target: 'cloud_infra' });
    }

    return { nodes, edges };
  }, [data, findings]);

  const filteredNodes = useMemo(() => {
    if (typeFilter === 'ALL') return topology.nodes;
    return topology.nodes.filter(n => n.type === typeFilter || n.type === 'root');
  }, [topology, typeFilter]);

  // Layout calculation
  const layout = useMemo(() => {
    const width = 640;
    const height = 440;
    const centerX = width / 2;
    const centerY = height / 2;
    const root = filteredNodes.find(n => n.type === 'root') || filteredNodes[0];
    const others = filteredNodes.filter(n => n.id !== root?.id);

    const positions = new Map<string, { x: number; y: number; node: AttackSurfaceNode }>();
    if (root) {
      positions.set(root.id, { x: centerX, y: centerY, node: root });
    }

    const radius = 150;
    others.forEach((node, idx) => {
      const angle = (idx / others.length) * 2 * Math.PI - Math.PI / 2;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      positions.set(node.id, { x, y, node });
    });

    return { positions, width, height };
  }, [filteredNodes]);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'root':
        return <Globe className="w-5 h-5 text-white" />;
      case 'database':
        return <Database className="w-4 h-4 text-purple-300" />;
      case 'external':
        return <Cloud className="w-4 h-4 text-amber-300" />;
      case 'route':
      default:
        return <Server className="w-4 h-4 text-blue-300" />;
    }
  };

  const getNodeColors = (node: AttackSurfaceNode) => {
    if (node.type === 'root') {
      return {
        bg: 'bg-blue-600 dark:bg-blue-700',
        border: 'border-blue-400',
        ring: 'ring-blue-500/30'
      };
    }
    if (node.risk_level === 'high') {
      return {
        bg: 'bg-red-950/80',
        border: 'border-red-500',
        ring: 'ring-red-500/40 text-red-400'
      };
    }
    if (node.risk_level === 'medium') {
      return {
        bg: 'bg-amber-950/80',
        border: 'border-amber-500',
        ring: 'ring-amber-500/40 text-amber-400'
      };
    }
    return {
      bg: 'bg-slate-900',
      border: 'border-slate-700',
      ring: 'ring-slate-700 text-slate-300'
    };
  };

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs space-y-6">
      {/* Top Header & Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500 animate-pulse"></span>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              Attack Surface & Component Topology Map
            </h3>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Interconnected component graph mapping routes, databases, and external cloud assets against discovered risk.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-xs font-semibold outline-none"
          >
            <option value="ALL">All Components ({topology.nodes.length})</option>
            <option value="route">API Routes</option>
            <option value="database">Databases & Models</option>
            <option value="external">Cloud & 3rd Party APIs</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Interactive SVG Canvas */}
        <div className="lg:col-span-8 relative border border-slate-200 dark:border-slate-800 rounded-2xl bg-slate-950 overflow-hidden flex justify-center items-center p-4 min-h-[420px]">
          <svg
            width="100%"
            height={layout.height}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            className="max-w-[640px]"
          >
            {/* Edge Connecting Lines */}
            {topology.edges.map((edge, idx) => {
              const start = layout.positions.get(edge.source);
              const end = layout.positions.get(edge.target);
              if (!start || !end) return null;
              return (
                <line
                  key={`edge-${idx}`}
                  x1={start.x}
                  y1={start.y}
                  x2={end.x}
                  y2={end.y}
                  stroke="#334155"
                  strokeWidth="2"
                  strokeDasharray="4 2"
                  strokeOpacity="0.8"
                />
              );
            })}

            {/* Glowing Pulse Rings for High Risk Nodes */}
            {Array.from(layout.positions.values()).map(({ x, y, node }) => {
              if (node.risk_level !== 'high') return null;
              return (
                <circle
                  key={`pulse-${node.id}`}
                  cx={x}
                  cy={y}
                  r={node.type === 'root' ? 32 : 26}
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="1.5"
                  strokeOpacity="0.4"
                  className="animate-ping"
                />
              );
            })}

            {/* Node Circles */}
            {Array.from(layout.positions.values()).map(({ x, y, node }) => {
              const isSelected = selectedNode?.id === node.id;
              return (
                <g
                  key={`node-${node.id}`}
                  transform={`translate(${x},${y})`}
                  className="cursor-pointer"
                  onClick={() => setSelectedNode(node)}
                >
                  <circle
                    r={node.type === 'root' ? 24 : 19}
                    fill={node.type === 'root' ? '#2563eb' : '#0f172a'}
                    stroke={
                      isSelected
                        ? '#38bdf8'
                        : node.risk_level === 'high'
                        ? '#ef4444'
                        : node.risk_level === 'medium'
                        ? '#f59e0b'
                        : '#475569'
                    }
                    strokeWidth={isSelected ? 3 : 2}
                    className="transition-all duration-200"
                  />
                </g>
              );
            })}
          </svg>

          {/* HTML Overlay for Interactive Icons & Badges */}
          <div className="absolute inset-0 pointer-events-none flex justify-center items-center">
            <div className="relative w-full h-full max-w-[640px]">
              {Array.from(layout.positions.values()).map(({ x, y, node }) => {
                const styling = getNodeColors(node);
                const isSelected = selectedNode?.id === node.id;

                return (
                  <div
                    key={`overlay-${node.id}`}
                    className="absolute transform -translate-x-1/2 -translate-y-1/2 pointer-events-auto cursor-pointer group flex flex-col items-center"
                    style={{ left: x, top: y }}
                    onClick={() => setSelectedNode(node)}
                  >
                    <div
                      className={`w-10 h-10 rounded-full flex items-center justify-center border-2 shadow-lg transition-transform duration-200 group-hover:scale-110 ${
                        styling.bg
                      } ${styling.border} ${isSelected ? 'scale-115 ring-4 ring-sky-400' : ''}`}
                    >
                      {getNodeIcon(node.type)}
                    </div>

                    {/* High Risk Alert Badge */}
                    {node.risk_level === 'high' && (
                      <div className="absolute -top-1 -right-1 bg-red-500 rounded-full p-0.5 border border-slate-900 z-10 shadow-xs">
                        <AlertTriangle className="w-2.5 h-2.5 text-white" />
                      </div>
                    )}

                    {/* Label Pill */}
                    <div className="mt-1.5 px-2 py-0.5 rounded-md bg-slate-900/90 border border-slate-700/80 text-[10px] font-mono text-slate-200 max-w-[130px] truncate shadow-xs text-center">
                      {node.label}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Node Details Inspector Panel */}
        <div className="lg:col-span-4 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-700">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600" />
              <h4 className="font-bold text-xs uppercase tracking-wider text-slate-800 dark:text-slate-200">
                Component Inspector
              </h4>
            </div>
            {selectedNode && (
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                  selectedNode.risk_level === 'high'
                    ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                    : selectedNode.risk_level === 'medium'
                    ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                    : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                }`}
              >
                {selectedNode.risk_level} Risk
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-3 animate-fade-in text-xs">
              <div>
                <p className="font-semibold text-slate-500 text-[11px]">Component Name</p>
                <p className="font-bold text-sm text-slate-900 dark:text-white mt-0.5 font-mono break-all">
                  {selectedNode.label}
                </p>
              </div>

              <div>
                <p className="font-semibold text-slate-500 text-[11px]">Category / Architecture Tier</p>
                <p className="capitalize text-slate-800 dark:text-slate-200 font-medium">
                  {selectedNode.type === 'root'
                    ? 'Core Runtime'
                    : selectedNode.type === 'route'
                    ? 'HTTP / API Endpoint'
                    : selectedNode.type === 'database'
                    ? 'Database & Data Models'
                    : 'Cloud & External Processors'}
                </p>
              </div>

              <div>
                <p className="font-semibold text-slate-500 text-[11px]">Details & Scope</p>
                <p className="text-slate-600 dark:text-slate-300 leading-relaxed mt-0.5">
                  {selectedNode.details}
                </p>
              </div>

              {selectedNode.findings_count !== undefined && selectedNode.findings_count > 0 && (
                <div className="p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/40 rounded-xl">
                  <p className="font-bold text-red-700 dark:text-red-300">
                    {selectedNode.findings_count} Security Finding(s) Impacted
                  </p>
                  <p className="text-[11px] text-red-600 dark:text-red-400 mt-0.5">
                    Component contains vulnerabilities evaluated in this audit.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-400">
              <p>Click on any node in the topology map to inspect its component classification and security impact.</p>
            </div>
          )}

          {/* Map Legend */}
          <div className="pt-4 border-t border-slate-200 dark:border-slate-700 space-y-1.5 text-[11px] text-slate-500">
            <p className="font-bold uppercase tracking-wider text-slate-400 mb-2">Topology Legend</p>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
              <span>High Risk (P0/P1 Finding Linked)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span>Medium Risk (P2 Gap / Unverified)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
              <span>Baseline Node / Low Risk</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
