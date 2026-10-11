import { useEffect, useRef, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  getLiveMonitoringDiagnostics,
  getLiveMonitoringExportUrl,
  getLiveMonitoringStatus,
  startLiveMonitoring,
  stopLiveMonitoring,
} from '../services/api';

function riskBadgeClass(level) {
  if (level === 'critical') return 'risk-badge-critical';
  if (level === 'warning') return 'risk-badge-warning';
  return 'risk-badge-safe';
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function LiveMonitoring() {
  const [targetIp, setTargetIp] = useState('');
  const [session, setSession] = useState(null);
  const [diagnostics, setDiagnostics] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [error, setError] = useState('');
  const [ipError, setIpError] = useState('');
  const pollIntervalRef = useRef(null);

  // Validate IPv4 format
  function validateIp(value) {
    const trimmed = value.trim();
    if (!trimmed) {
      setIpError('Please enter an IPv4 address');
      return false;
    }
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    if (!ipv4Regex.test(trimmed)) {
      setIpError('Invalid IPv4 format (e.g., 10.57.150.11 or 192.168.43.15)');
      return false;
    }
    setIpError('');
    return true;
  }

  // Fetch initial diagnostics
  useEffect(() => {
    async function loadDiagnostics() {
      try {
        const diag = await getLiveMonitoringDiagnostics();
        if (diag) {
          setDiagnostics(diag);
          if (diag.default_local_ip && !targetIp) {
            setTargetIp(diag.default_local_ip);
          }
        }
      } catch (err) {
        console.warn('Diagnostics fetch error:', err);
      }
    }
    loadDiagnostics();
  }, []);

  // Periodic Status Polling
  useEffect(() => {
    async function fetchStatus() {
      try {
        const response = await getLiveMonitoringStatus(session?.session_id);
        if (response?.session) {
          setSession(response.session);
        }
        if (response?.diagnostics) {
          setDiagnostics(response.diagnostics);
        }
      } catch (err) {
        console.warn('Status poll error:', err);
      }
    }

    // Initial check on mount
    fetchStatus();

    // Poll every 1.5 seconds if active
    if (session?.is_active) {
      pollIntervalRef.current = setInterval(fetchStatus, 1500);
    } else {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    }

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [session?.is_active, session?.session_id]);

  async function handleStart() {
    setError('');
    if (!validateIp(targetIp)) return;

    setIsStarting(true);
    try {
      const result = await startLiveMonitoring(targetIp.trim());
      if (!result.success) {
        setError(result.error || 'Failed to start live capture');
      } else {
        setSession(result.session);
      }
    } catch (err) {
      setError(err.message || 'Error connecting to backend API');
    } finally {
      setIsStarting(false);
    }
  }

  async function handleStop() {
    setIsStopping(true);
    try {
      const result = await stopLiveMonitoring(session?.session_id);
      if (result.success && result.session) {
        setSession(result.session);
      }
    } catch (err) {
      setError(err.message || 'Error stopping session');
    } finally {
      setIsStopping(false);
    }
  }

  const isCapturing = Boolean(session?.is_active);
  const targetVerified = Boolean(session?.target_packets_verified > 0);
  const permissionDenied = session?.engine_status === 'PERMISSION_DENIED' || (diagnostics && !diagnostics.is_admin);
  const currentPid = session?.backend_pid || diagnostics?.backend_pid;
  const isElevated = session?.is_process_elevated ?? diagnostics?.is_admin;
  const availableInterfaces = session?.available_interfaces || diagnostics?.available_interfaces || [];
  const isLoopbackTarget = targetIp.trim() === '127.0.0.1';

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <section className="page-hero rounded-3xl p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.35em] text-[var(--accent-primary)]">
              Real-Time Device Telemetry
            </p>
            <h2 className="mt-2 font-display text-3xl font-semibold">Live Device Network Monitoring</h2>
            <p className="mt-2 max-w-3xl text-sm soft-label">
              Capture and inspect Layer 3/4 packet flows for a specific device IP in real time.
              Computes continuous trust scores, isolates suspicious ports, checks periodic beaconing,
              and transparently reports network visibility status under hotspot/Wi-Fi environments.
            </p>
          </div>
          {currentPid && (
            <div className="flex flex-col items-end gap-1.5">
              <span className="font-mono text-xs soft-label">
                Backend Process: <strong className="text-white">PID {currentPid}</strong>
              </span>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${
                  isElevated
                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                    : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                }`}
              >
                <span className={`h-2 w-2 rounded-full ${isElevated ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                {isElevated ? 'Administrator Active' : 'Non-Elevated User'}
              </span>
            </div>
          )}
        </div>
      </section>

      {/* Control Panel */}
      <section className="surface-card rounded-3xl p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-5">
          <div>
            <h3 className="font-display text-xl font-semibold text-white">Target Device Configuration</h3>
            <p className="mt-1 text-sm soft-label">
              Enter the IPv4 address of the target device to capture and evaluate its live communications.
            </p>
          </div>
          {session?.local_interface_ip && (
            <div className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-xs soft-label">
              <span className="h-2 w-2 rounded-full bg-[var(--accent-primary)]" />
              <span>Bound Sniffing Interface: <strong className="font-mono text-white">{session.local_interface_ip}</strong></span>
            </div>
          )}
        </div>

        {/* Available Interface Selection Chips */}
        {availableInterfaces.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="text-xs soft-label font-mono uppercase tracking-wider">Detected Host Interfaces:</span>
            {availableInterfaces.map((ifaceIp) => (
              <button
                key={ifaceIp}
                type="button"
                onClick={() => {
                  setTargetIp(ifaceIp);
                  setIpError('');
                }}
                disabled={isCapturing}
                className={`rounded-xl border px-3 py-1.5 text-xs font-mono transition ${
                  targetIp === ifaceIp
                    ? 'border-[var(--accent-primary)] bg-[rgba(61,232,203,0.15)] text-white'
                    : 'border-white/10 bg-white/5 soft-label hover:bg-white/10 hover:text-white'
                }`}
              >
                🎯 Target {ifaceIp}
              </button>
            ))}
          </div>
        )}

        <div className="mt-5 flex flex-wrap items-start gap-4">
          <div className="flex-1 min-w-[260px] max-w-md">
            <label className="block text-xs font-mono uppercase tracking-[0.2em] soft-label mb-2">
              Target Device IP Address
            </label>
            <div className="relative">
              <input
                type="text"
                placeholder="e.g. 10.57.150.11 or 192.168.43.15"
                value={targetIp}
                onChange={(e) => {
                  setTargetIp(e.target.value);
                  if (ipError) validateIp(e.target.value);
                }}
                disabled={isCapturing}
                className="w-full rounded-2xl border border-white/10 bg-black/30 px-4 py-3 font-mono text-sm text-white placeholder-slate-500 transition focus:border-[var(--accent-primary)] focus:outline-none disabled:opacity-50"
              />
            </div>
            {ipError && <p className="mt-1.5 text-xs text-red-400">{ipError}</p>}
            {isLoopbackTarget && (
              <p className="mt-1.5 text-xs text-amber-300">
                ⚠️ Notice: Windows NDIS raw sockets do not capture 127.0.0.1 loopback packets. To monitor real traffic on this laptop, select your network IP ({diagnostics?.default_local_ip || '10.57.150.11'}) above.
              </p>
            )}
          </div>

          <div className="flex items-end gap-3 pt-6">
            {!isCapturing ? (
              <button
                type="button"
                onClick={handleStart}
                disabled={isStarting}
                className="btn-accent inline-flex items-center gap-2 rounded-xl px-6 py-3 font-semibold text-sm disabled:opacity-50"
              >
                {isStarting ? (
                  <>
                    <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-900 border-t-transparent" />
                    Starting Sniffer...
                  </>
                ) : (
                  <>
                    <span className="inline-block h-2 w-2 rounded-full bg-emerald-950" />
                    Start Monitoring
                  </>
                )}
              </button>
            ) : (
              <button
                type="button"
                onClick={handleStop}
                disabled={isStopping}
                className="inline-flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/20 px-6 py-3 font-semibold text-sm text-red-300 hover:bg-red-500/30 disabled:opacity-50 transition"
              >
                {isStopping ? (
                  <>
                    <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-red-300 border-t-transparent" />
                    Stopping...
                  </>
                ) : (
                  <>
                    <span className="inline-block h-2 w-2 rounded-full bg-red-400 animate-pulse" />
                    Stop Monitoring
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mt-4 rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
            {error}
          </div>
        )}
      </section>

      {/* Network Diagnostics & Visibility Advisories */}
      <section className="space-y-3">
        {permissionDenied && (
          <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5">
            <div className="flex items-start gap-3">
              <span className="text-xl">⚠️</span>
              <div>
                <h4 className="font-semibold text-amber-200">
                  Administrator Privileges Required for Raw Socket (Backend PID: {currentPid || 'Unknown'})
                </h4>
                <p className="mt-1 text-sm text-amber-300/90 leading-relaxed">
                  The backend server currently handling API requests (<strong>PID {currentPid}</strong>) is running as a <strong>standard non-elevated user</strong>.
                  Windows restricts raw packet sniffing (<code>socket.SOCK_RAW</code>) exclusively to processes with Administrator elevation.
                </p>
                <div className="mt-3 rounded-xl bg-black/30 p-3 text-xs soft-label space-y-1.5 font-mono">
                  <div className="text-amber-200 font-semibold uppercase">Exact Steps to Resolve:</div>
                  <div>1. Stop the current backend process holding port 8000 (PID {currentPid}).</div>
                  <div>2. Open a new PowerShell terminal using <strong>&quot;Run as Administrator&quot;</strong>.</div>
                  <div>3. Run: <code>uvicorn app.main:app --host 127.0.0.1 --port 8000</code> in the backend directory.</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {isCapturing && !targetVerified && (
          <div className="rounded-2xl border border-cyan-500/30 bg-cyan-950/20 p-5">
            <div className="flex items-start gap-3">
              <span className="text-xl">📡</span>
              <div>
                <h4 className="font-semibold text-cyan-200">
                  Awaiting Target Traffic — Hotspot &amp; Wi-Fi Isolation Advisory
                </h4>
                <p className="mt-1 text-sm text-cyan-300/80 leading-relaxed">
                  Capture engine is active on interface <strong>{session?.local_interface_ip}</strong>{' '}
                  ({session?.total_interface_packets} total interface packets observed), but{' '}
                  <strong>0 packets match target IP {session?.target_ip}</strong> yet.
                </p>
                <div className="mt-2 text-xs soft-label bg-black/20 p-3 rounded-xl space-y-1">
                  <div>
                    • <strong>Hotspot / Wi-Fi Isolation:</strong> Mobile phone hotspots and standard Wi-Fi routers do not broadcast third-party unicast traffic to other clients.
                  </div>
                  <div>
                    • <strong>Observable Traffic:</strong> The laptop can observe direct host-to-device communications, subnet broadcasts (mDNS/ARP), or traffic when targeting this laptop's own IP.
                  </div>
                  <div>
                    • <strong>Test Tip:</strong> If verifying real packet parsing, target your laptop's Wi-Fi IP (<code>{session?.local_interface_ip}</code>) or send a ping/probe to <code>{session?.target_ip}</code>.
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {targetVerified && (
          <div className="rounded-2xl border border-emerald-500/30 bg-emerald-950/20 p-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span className="h-3 w-3 rounded-full bg-emerald-400 animate-pulse" />
              <div>
                <h4 className="font-semibold text-emerald-200">
                  Live Target Traffic Verified ({session?.target_ip})
                </h4>
                <p className="text-xs text-emerald-300/80">
                  Actual Layer 3/4 packet flows matching the target device are actively being captured and analyzed.
                </p>
              </div>
            </div>
            <span className="font-mono text-xs rounded-full border border-emerald-400/30 bg-emerald-400/10 px-3 py-1 text-emerald-300">
              {session?.target_packets_verified} packets verified
            </span>
          </div>
        )}
      </section>

      {/* KPI Metrics Strip */}
      {session && (
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="surface-card rounded-3xl p-5">
            <p className="font-mono text-xs uppercase tracking-[0.25em] soft-label">Verified Target Packets</p>
            <p className="mt-3 font-mono text-3xl font-semibold text-white">
              {session.target_packets_verified}
            </p>
            <p className="mt-1 text-xs soft-label">
              Total interface observed: {session.total_interface_packets}
            </p>
          </div>

          <div className="surface-card rounded-3xl p-5">
            <p className="font-mono text-xs uppercase tracking-[0.25em] soft-label">Verified Volume</p>
            <p className="mt-3 font-mono text-3xl font-semibold text-[var(--accent-primary)]">
              {formatBytes(session.target_bytes_verified)}
            </p>
            <p className="mt-1 text-xs soft-label">
              Interface total: {formatBytes(session.total_interface_bytes)}
            </p>
          </div>

          <div className="surface-card rounded-3xl p-5">
            <p className="font-mono text-xs uppercase tracking-[0.25em] soft-label">Unique Destinations</p>
            <p className="mt-3 font-mono text-3xl font-semibold text-white">
              {session.unique_destinations_count || 0}
            </p>
            <p className="mt-1 text-xs soft-label">
              External / internal peers contacted
            </p>
          </div>

          <div className="surface-card rounded-3xl p-5">
            <div className="flex items-center justify-between">
              <p className="font-mono text-xs uppercase tracking-[0.25em] soft-label">Live Trust Score</p>
              <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider ${riskBadgeClass(session.risk_level)}`}>
                {session.risk_level}
              </span>
            </div>
            <p className="mt-3 font-mono text-3xl font-semibold text-white">
              {session.trust_score}
            </p>
            <p className="mt-1 text-xs soft-label">
              Evaluated using Phantom Nexus trust model
            </p>
          </div>
        </section>
      )}

      {/* Charts & Behavioral Anomaly Section */}
      {session && (
        <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          {/* Traffic Volume Chart */}
          <div className="surface-card rounded-3xl p-6">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h3 className="font-display text-xl font-semibold text-white">Live Traffic Trajectory</h3>
                <p className="text-xs soft-label">Packet arrival rate for {session.target_ip}</p>
              </div>
              <span className="font-mono text-xs soft-label">
                Session duration: {session.duration_seconds}s
              </span>
            </div>
            <div className="h-64 w-full">
              {session.traffic_history?.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={session.traffic_history}>
                    <defs>
                      <linearGradient id="liveTrafficGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--accent-primary)" stopOpacity={0.7} />
                        <stop offset="100%" stopColor="var(--accent-primary)" stopOpacity={0.05} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                    <XAxis dataKey="timestamp" tick={{ fill: 'var(--chart-axis)', fontSize: 10 }} />
                    <YAxis tick={{ fill: 'var(--chart-axis)', fontSize: 10 }} />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--chart-tooltip-bg)',
                        border: '1px solid var(--chart-tooltip-border)',
                        borderRadius: '12px',
                        color: 'var(--text-primary)',
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="packets"
                      name="Packets"
                      stroke="var(--accent-primary)"
                      strokeWidth={2}
                      fill="url(#liveTrafficGrad)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center rounded-2xl border border-dashed border-white/10 bg-white/5 text-xs soft-label text-center p-6">
                  {targetVerified
                    ? 'Accumulating traffic data points...'
                    : 'Awaiting target packets to plot live trajectory...'}
                </div>
              )}
            </div>
          </div>

          {/* Anomaly Indicators & Port Distribution */}
          <div className="surface-card rounded-3xl p-6 flex flex-col justify-between">
            <div>
              <h3 className="font-display text-xl font-semibold text-white">Live Threat Indicators</h3>
              <p className="text-xs soft-label">Behavioral anomalies and suspicious port hits</p>

              <div className="mt-4 space-y-2.5">
                {session.detected_anomalies?.length > 0 ? (
                  session.detected_anomalies.map((anomaly, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-3 rounded-2xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200"
                    >
                      <span className="text-base">🚨</span>
                      <span className="font-medium">{anomaly}</span>
                    </div>
                  ))
                ) : (
                  <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-xs text-emerald-300/80">
                    {targetVerified
                      ? '✓ No active recruitment indicators detected in current packet stream.'
                      : 'No indicators active (Awaiting target traffic).'}
                  </div>
                )}
              </div>
            </div>

            {/* Port Distribution Mini-Bar */}
            <div className="mt-6 border-t border-white/10 pt-4">
              <h4 className="text-xs font-mono uppercase tracking-[0.2em] soft-label mb-3">
                Top Destination Ports
              </h4>
              <div className="h-28 w-full">
                {session.port_distribution?.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={session.port_distribution}>
                      <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                      <XAxis dataKey="port" tick={{ fill: 'var(--chart-axis)', fontSize: 10 }} />
                      <YAxis tick={{ fill: 'var(--chart-axis)', fontSize: 10 }} />
                      <Tooltip
                        contentStyle={{
                          background: 'var(--chart-tooltip-bg)',
                          border: '1px solid var(--chart-tooltip-border)',
                          borderRadius: '8px',
                          color: 'var(--text-primary)',
                          fontSize: '11px',
                        }}
                      />
                      <Bar dataKey="count" name="Flow Count" fill="var(--accent-primary)" radius={[6, 6, 0, 0]}>
                        {session.port_distribution.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={[23, 2323, 4444, 48101, 5555, 6667].includes(Number(entry.port)) ? '#ef4444' : 'var(--accent-primary)'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs soft-label">
                    No ports observed yet
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Live Connection Stream Table */}
      {session && (
        <section className="surface-card rounded-3xl overflow-hidden">
          <div className="border-b border-white/10 px-6 py-4 flex items-center justify-between">
            <div>
              <h3 className="font-display text-xl font-semibold text-white">Live Connection Stream</h3>
              <p className="text-xs soft-label">
                Real-time Layer 3/4 flow records captured for {session.target_ip}
              </p>
            </div>
            <span className="font-mono text-xs soft-label rounded-full border border-white/10 bg-white/5 px-3 py-1">
              Showing latest {session.recent_flows?.length || 0} flows
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="bg-white/5 soft-label">
                <tr>
                  <th className="px-6 py-3 font-medium">Timestamp</th>
                  <th className="px-6 py-3 font-medium">Direction</th>
                  <th className="px-6 py-3 font-medium">Source IP</th>
                  <th className="px-6 py-3 font-medium">Destination IP</th>
                  <th className="px-6 py-3 font-medium">Port</th>
                  <th className="px-6 py-3 font-medium">Protocol</th>
                  <th className="px-6 py-3 font-medium">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {session.recent_flows?.length > 0 ? (
                  session.recent_flows.slice().reverse().map((flow, index) => {
                    const isSuspiciousPort = [23, 2323, 4444, 48101, 5555, 6667].includes(Number(flow.dest_port));
                    return (
                      <tr key={index} className="hover:bg-white/[0.02]">
                        <td className="px-6 py-3 font-mono soft-label">
                          {new Date(flow.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-6 py-3">
                          <span
                            className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                              flow.direction === 'outbound'
                                ? 'bg-amber-400/10 text-amber-300 border border-amber-400/20'
                                : 'bg-cyan-400/10 text-cyan-300 border border-cyan-400/20'
                            }`}
                          >
                            {flow.direction || 'flow'}
                          </span>
                        </td>
                        <td className="px-6 py-3 font-mono text-white">{flow.src_ip}</td>
                        <td className="px-6 py-3 font-mono text-white">{flow.dest_ip}</td>
                        <td className="px-6 py-3 font-mono">
                          <span className={isSuspiciousPort ? 'text-red-400 font-bold' : 'soft-label'}>
                            {flow.dest_port || '—'}
                          </span>
                        </td>
                        <td className="px-6 py-3 font-mono soft-label">{flow.protocol}</td>
                        <td className="px-6 py-3 font-mono soft-label">{formatBytes(flow.bytes)}</td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} className="px-6 py-8 text-center text-xs soft-label">
                      {isCapturing
                        ? 'Sniffing interface... Waiting for packets matching target device IP.'
                        : 'No active session. Click Start Monitoring to begin traffic collection.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Session Preservation & CSV Export Card */}
      {session && !isCapturing && (
        <section className="surface-card rounded-3xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.3em] text-[var(--accent-primary)]">
                Session Complete
              </p>
              <h3 className="mt-1 font-display text-2xl font-semibold text-white">
                Preserve &amp; Export Session Telemetry
              </h3>
              <p className="mt-1 text-sm soft-label">
                Session data has been preserved. You can download the captured packets as a CSV strictly
                formatted according to the Phantom Nexus 8-column schema, or feed it into the fleet analysis.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <a
                href={getLiveMonitoringExportUrl(session.session_id)}
                download={`${session.session_id}.csv`}
                className="btn-accent inline-flex items-center gap-2 rounded-xl px-5 py-3 text-sm font-semibold"
              >
                <span>📥</span> Download Captured CSV
              </a>
            </div>
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-3 text-xs soft-label border-t border-white/10 pt-4">
            <div>
              <span className="font-medium text-white">Session ID:</span>{' '}
              <span className="font-mono">{session.session_id}</span>
            </div>
            <div>
              <span className="font-medium text-white">Duration:</span>{' '}
              <span className="font-mono">{session.duration_seconds}s</span>
            </div>
            <div>
              <span className="font-medium text-white">Schema Conformance:</span>{' '}
              <span className="text-emerald-400">100% (8-column REQUIRED_COLUMNS)</span>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
