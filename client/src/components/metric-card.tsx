import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  change: string;
  changeType: "positive" | "negative";
  icon: LucideIcon;
  iconColor: "red" | "blue" | "green" | "purple";
}

export default function MetricCard({
  title,
  value,
  change,
  changeType,
  icon: Icon,
  iconColor,
}: MetricCardProps) {
  const changeColorClass = changeType === "positive" ? "text-green-500" : "text-red-500";

  return (
    <div className="metric-card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-slate-600 uppercase tracking-wide">
            {title}
          </p>
          <p className="text-3xl font-bold text-slate-900 mt-2">{value}</p>
          <div className="flex items-center mt-2">
            <span className={`text-sm font-medium ${changeColorClass}`}>
              {change}
            </span>
            <span className="text-slate-500 text-sm ml-2">from last week</span>
          </div>
        </div>
        <div className={`metric-icon ${iconColor}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}
