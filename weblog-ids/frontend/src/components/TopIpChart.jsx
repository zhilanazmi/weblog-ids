import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

// TopIpChart.jsx - Bar chart IP penyerang terbanyak.
// data: [{ ip, jumlah }] dari GET /api/dashboard/top-attacker-ip.
export default function TopIpChart({ data }) {
  if (!data || data.length === 0) {
    return <p className="label">Belum ada data serangan.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        {/* layout vertical: sumbu nilai di X, kategori IP di Y agar label IP terbaca. */}
        <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
        <YAxis type="category" dataKey="ip" stroke="#94a3b8" width={110} />
        <Tooltip />
        <Bar dataKey="jumlah" fill="#38bdf8" />
      </BarChart>
    </ResponsiveContainer>
  );
}
