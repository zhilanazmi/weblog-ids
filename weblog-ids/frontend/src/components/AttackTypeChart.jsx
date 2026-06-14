import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

// AttackTypeChart.jsx - Pie chart jumlah deteksi per label.
// data: [{ label, jumlah }] dari GET /api/dashboard/attack-types.

// Warna per label agar konsisten dengan tema dashboard.
const COLORS = {
  Normal: "#22c55e",
  XSS: "#d946ef",
  SQLi: "#f97316",
  Multiple: "#ef4444",
};

export default function AttackTypeChart({ data }) {
  if (!data || data.length === 0) {
    return <p className="label">Belum ada data.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={data}
          dataKey="jumlah"
          nameKey="label"
          cx="50%"
          cy="50%"
          outerRadius={90}
          label={(entry) => `${entry.label}: ${entry.jumlah}`}
        >
          {data.map((entry) => (
            <Cell
              key={entry.label}
              fill={COLORS[entry.label] || "#38bdf8"}
            />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}
