import { useState, useEffect } from "react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from "recharts";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

const COLORS = {
  safe: "#00e5a0",
  suspicious: "#f5c542",
  high_risk: "#ff4d6d",
};

const RISK_LABEL = (score) => {
  if (score <= 3) return { label: "Safe", color: COLORS.safe };
  if (score <= 6) return { label: "Suspicious", color: COLORS.suspicious };
  return { label: "High Risk", color: COLORS.high_risk };
};

function StatCard({ title, value, sub, accent }) {
  return (
    <div style={{
      background: "#0f1117",
      border: `1px solid ${accent}33`,
      borderRadius: 16,
      padding: "24px 28px",
      display: "flex",
      flexDirection: "column",
      gap: 6,
      boxShadow: `0 0 24px ${accent}11`,
    }}>
      <span style={{ color: "#888", fontSize: 12, letterSpacing: 2, textTransform: "uppercase", fontFamily: "'DM Mono', monospace" }}>{title}</span>
      <span style={{ color: accent, fontSize: 42, fontWeight: 700, fontFamily: "'Syne', sans-serif", lineHeight: 1 }}>{value}</span>
      {sub && <span style={{ color: "#555", fontSize: 12, fontFamily: "'DM Mono', monospace" }}>{sub}</span>}
    </div>
  );
}

function RiskBadge({ score }) {
  const { label, color } = RISK_LABEL(score);
  return (
    <span style={{
      background: `${color}22`,
      color: color,
      border: `1px solid ${color}55`,
      borderRadius: 6,
      padding: "2px 10px",
      fontSize: 11,
      fontFamily: "'DM Mono', monospace",
      letterSpacing: 1,
    }}>{label} · {score}/10</span>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ background: "#0f1117", border: "1px solid #222", borderRadius: 8, padding: "10px 16px" }}>
        <p style={{ color: "#888", fontSize: 11, margin: 0, fontFamily: "'DM Mono', monospace" }}>{label}</p>
        <p style={{ color: "#00e5a0", fontSize: 18, margin: 0, fontWeight: 700 }}>{payload[0].value} scans</p>
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      if (!res.ok) throw new Error("Failed to fetch stats");
      const data = await res.json();
      setStats(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchStats(); }, []);

  const handleScan = async () => {
    if (!url) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/shorten`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();

      if (!res.ok) {
        setScanResult({ error: data.detail || "Could not create link" });
        setScanning(false);
        return;
      }

      // /api/shorten returns immediately with status "pending" — the actual
      // Bedrock + VirusTotal scan runs in the background. Poll /api/status
      // until it resolves to "completed" or "blocked".
      setScanResult({ ...data, pending: true });
      pollStatus(data.code, data.short_url);
    } catch (e) {
      setScanResult({ error: e.message });
      setScanning(false);
    }
  };

  const pollStatus = (code, shortUrl) => {
    let attempts = 0;
    const interval = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch(`${API_BASE}/api/status/${code}`);
        const data = await res.json();

        if (data.status === "pending") {
          if (attempts > 30) {
            clearInterval(interval);
            setScanResult({ error: "Scan is taking longer than expected." });
            setScanning(false);
          }
          return;
        }

        clearInterval(interval);
        setScanResult({
          code,
          short_url: shortUrl,
          status: data.status,
          risk_score: data.risk_score,
          risk_reason: data.risk_reason,
          original_url: url,
        });
        setUrl("");
        setScanning(false);
        setTimeout(fetchStats, 500);
      } catch (e) {
        // transient network error — let the interval retry
      }
    }, 1000);
  };

  const pieData = stats ? [
    { name: "Safe", value: stats.risk_distribution.safe },
    { name: "Suspicious", value: stats.risk_distribution.suspicious },
    { name: "High Risk", value: stats.risk_distribution.high_risk },
  ] : [];

  return (
    <div style={{
      minHeight: "100vh",
      background: "#080a0f",
      color: "#e0e0e0",
      fontFamily: "'DM Sans', sans-serif",
      padding: "0 0 60px 0",
    }}>
      {/* Google Fonts */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500&family=DM+Mono:wght@400;500&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0f1117; }
        ::-webkit-scrollbar-thumb { background: #222; border-radius: 4px; }
        .scan-input:focus { outline: none; border-color: #00e5a0 !important; box-shadow: 0 0 0 3px #00e5a022; }
        .scan-btn:hover { background: #00e5a0 !important; color: #080a0f !important; }
        .row-hover:hover { background: #ffffff08 !important; }
        @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }
      `}</style>

      {/* Header */}
      <div style={{
        borderBottom: "1px solid #ffffff0a",
        padding: "28px 48px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "#0a0c12",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: "linear-gradient(135deg, #00e5a0, #0066ff)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18,
          }}>🔗</div>
          <div>
            <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 20, fontWeight: 800, color: "#fff", letterSpacing: -0.5 }}>
              SafeLink <span style={{ color: "#00e5a0" }}>AI</span>
            </div>
            <div style={{ fontSize: 11, color: "#444", fontFamily: "'DM Mono', monospace", letterSpacing: 1 }}>SECURITY DASHBOARD</div>
          </div>
        </div>
        <div style={{
          background: "#00e5a022",
          border: "1px solid #00e5a044",
          borderRadius: 8,
          padding: "6px 14px",
          fontSize: 12,
          color: "#00e5a0",
          fontFamily: "'DM Mono', monospace",
          display: "flex", alignItems: "center", gap: 6,
        }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#00e5a0", display: "inline-block" }} />
          LIVE
        </div>
      </div>

      <div style={{ padding: "40px 48px", maxWidth: 1200, margin: "0 auto" }}>

        {/* Scan Input */}
        <div style={{
          background: "#0f1117",
          border: "1px solid #ffffff0f",
          borderRadius: 16,
          padding: "28px 32px",
          marginBottom: 40,
        }}>
          <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 16, fontWeight: 700, color: "#fff", marginBottom: 16 }}>
            Scan a URL
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <input
              className="scan-input"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="https://example.com"
              style={{
                flex: 1, background: "#080a0f", border: "1px solid #1e2030",
                borderRadius: 10, padding: "12px 18px", color: "#e0e0e0",
                fontSize: 14, fontFamily: "'DM Mono', monospace",
                transition: "border-color 0.2s, box-shadow 0.2s",
              }}
            />
            <button
              className="scan-btn"
              onClick={handleScan}
              disabled={scanning || !url}
              style={{
                background: "#0f1117", border: "1px solid #00e5a055",
                color: "#00e5a0", borderRadius: 10, padding: "12px 28px",
                fontSize: 13, fontFamily: "'DM Mono', monospace", cursor: "pointer",
                letterSpacing: 1, transition: "all 0.2s",
                opacity: scanning || !url ? 0.5 : 1,
              }}
            >
              {scanning ? "SCANNING..." : "SCAN →"}
            </button>
          </div>

          {scanResult && scanResult.pending && (
            <div style={{
              marginTop: 16, padding: "16px 20px",
              background: "#080a0f", borderRadius: 10,
              border: "1px solid #2a2a2a",
              fontSize: 12, color: "#777", fontFamily: "'DM Mono', monospace",
              display: "flex", alignItems: "center", gap: 8,
            }}>
              <span style={{ animation: "pulse 1.2s infinite" }}>●</span>
              Scanning with Claude AI + VirusTotal…
            </div>
          )}

          {scanResult && scanResult.error && (
            <div style={{
              marginTop: 16, padding: "16px 20px",
              background: "#080a0f", borderRadius: 10,
              border: "1px solid #ff3c5a33",
              fontSize: 12, color: "#ff3c5a", fontFamily: "'DM Mono', monospace",
            }}>
              {scanResult.error}
            </div>
          )}

          {scanResult && !scanResult.error && !scanResult.pending && (
            <div style={{
              marginTop: 16, padding: "16px 20px",
              background: "#080a0f", borderRadius: 10,
              border: `1px solid ${RISK_LABEL(scanResult.risk_score).color}33`,
              display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16,
            }}>
              <div>
                <div style={{ fontSize: 12, color: "#555", fontFamily: "'DM Mono', monospace", marginBottom: 6 }}>RESULT</div>
                <div style={{ fontSize: 13, color: "#ccc", marginBottom: 8, wordBreak: "break-all" }}>{scanResult.original_url}</div>
                <div style={{ fontSize: 12, color: "#777", fontFamily: "'DM Mono', monospace" }}>{scanResult.risk_reason}</div>
              </div>
              <div style={{ flexShrink: 0 }}>
                <RiskBadge score={scanResult.risk_score} />
              </div>
            </div>
          )}
        </div>

        {loading && (
          <div style={{ textAlign: "center", color: "#444", fontFamily: "'DM Mono', monospace", fontSize: 13, padding: 60 }}>
            <span style={{ animation: "pulse 1.5s infinite" }}>Loading stats...</span>
          </div>
        )}

        {error && (
          <div style={{ textAlign: "center", color: "#ff4d6d", fontFamily: "'DM Mono', monospace", fontSize: 13, padding: 60 }}>
            Error: {error}. Make sure the API is running at {API_BASE}.
          </div>
        )}

        {stats && (
          <>
            {/* Stat Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 32 }}>
              <StatCard title="Total Scanned" value={stats.total_scanned} sub="all time" accent="#00e5a0" />
              <StatCard title="Avg Risk Score" value={stats.average_risk_score} sub="out of 10" accent="#f5c542" />
              <StatCard title="Safe Links" value={stats.safe_count} sub="score ≤ 3" accent="#00e5a0" />
              <StatCard title="Blocked" value={stats.blocked_count} sub="score ≥ 7" accent="#ff4d6d" />
            </div>

            {/* Charts Row */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 32 }}>

              {/* Line Chart */}
              <div style={{ background: "#0f1117", border: "1px solid #ffffff0a", borderRadius: 16, padding: "24px 28px" }}>
                <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 24 }}>
                  Scan Volume — Last 7 Days
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={stats.scan_volume_over_time}>
                    <XAxis dataKey="date" tick={{ fill: "#444", fontSize: 10, fontFamily: "'DM Mono', monospace" }} axisLine={false} tickLine={false}
                      tickFormatter={d => d.slice(5)} />
                    <YAxis tick={{ fill: "#444", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Line type="monotone" dataKey="count" stroke="#00e5a0" strokeWidth={2} dot={{ fill: "#00e5a0", r: 3 }} activeDot={{ r: 5 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Pie Chart */}
              <div style={{ background: "#0f1117", border: "1px solid #ffffff0a", borderRadius: 16, padding: "24px 28px" }}>
                <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 24 }}>
                  Risk Distribution
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                      {pieData.map((entry, index) => (
                        <Cell key={index} fill={Object.values(COLORS)[index]} />
                      ))}
                    </Pie>
                    <Legend formatter={(v) => <span style={{ color: "#888", fontSize: 12, fontFamily: "'DM Mono', monospace" }}>{v}</span>} />
                    <Tooltip formatter={(v, n) => [v, n]} contentStyle={{ background: "#0f1117", border: "1px solid #222", borderRadius: 8 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Bottom Row */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

              {/* Top Risky Domains */}
              <div style={{ background: "#0f1117", border: "1px solid #ffffff0a", borderRadius: 16, padding: "24px 28px" }}>
                <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 20 }}>
                  Top Risky Domains
                </div>
                {stats.top_risky_domains.length === 0 ? (
                  <div style={{ color: "#333", fontSize: 13, fontFamily: "'DM Mono', monospace" }}>No risky domains yet.</div>
                ) : (
                  stats.top_risky_domains.map((d, i) => (
                    <div key={i} className="row-hover" style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      padding: "10px 12px", borderRadius: 8, marginBottom: 4, transition: "background 0.15s",
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ color: "#333", fontSize: 11, fontFamily: "'DM Mono', monospace", width: 16 }}>#{i + 1}</span>
                        <span style={{ fontSize: 13, color: "#ccc", fontFamily: "'DM Mono', monospace", maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.domain}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ color: "#444", fontSize: 11 }}>{d.count} scan{d.count !== 1 ? "s" : ""}</span>
                        <RiskBadge score={Math.round(d.avg_score)} />
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Recent Links */}
              <div style={{ background: "#0f1117", border: "1px solid #ffffff0a", borderRadius: 16, padding: "24px 28px" }}>
                <div style={{ fontFamily: "'Syne', sans-serif", fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 20 }}>
                  Recent Scans
                </div>
                {stats.recent_links.length === 0 ? (
                  <div style={{ color: "#333", fontSize: 13, fontFamily: "'DM Mono', monospace" }}>No scans yet.</div>
                ) : (
                  stats.recent_links.map((l, i) => (
                    <div key={i} className="row-hover" style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      padding: "10px 12px", borderRadius: 8, marginBottom: 4, transition: "background 0.15s",
                    }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, color: "#ccc", fontFamily: "'DM Mono', monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {l.original_url}
                        </div>
                        <div style={{ fontSize: 10, color: "#444", marginTop: 2 }}>
                          {l.created_at ? new Date(l.created_at).toLocaleString() : ""}
                        </div>
                      </div>
                      <div style={{ marginLeft: 12, flexShrink: 0 }}>
                        <RiskBadge score={l.risk_score} />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}