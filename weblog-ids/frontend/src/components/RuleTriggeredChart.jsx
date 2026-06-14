import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

// RuleTriggeredChart.jsx - Bar chart rule paling sering terpicu.
// data: [{ rule_code, jumlah }] dari GET /api/dashboard/rule-triggered.
export default function RuleTriggeredChart({ data }) {
  if (!data || data.length === 0) {
    return <p className="label">Belum ada rule yang terpicu.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ bottom: 10 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="rule_code" stroke="#94a3b8" />
        <YAxis stroke="#94a3b8" allowDecimals={false} />
        <Tooltip />
        <Bar dataKey="jumlah" fill="#f59e0b" />
      </BarChart>
    </ResponsiveContainer>
  );
}
