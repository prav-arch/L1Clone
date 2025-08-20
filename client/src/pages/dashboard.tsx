import { useQuery } from "@tanstack/react-query";
import MetricCard from "@/components/metric-card";
import { AlertTriangle, BarChart3, Shield, FileText } from "lucide-react";
import type { DashboardMetrics, DashboardMetricsWithChanges, AnomalyTrend, AnomalyTypeBreakdown } from "@shared/schema";

export default function Dashboard() {
  const { data: metricsWithChanges, isLoading: metricsLoading } = useQuery<DashboardMetricsWithChanges>({
    queryKey: ["/api/dashboard/metrics-with-changes"],
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const { data: trends } = useQuery<AnomalyTrend[]>({
    queryKey: ["/api/dashboard/trends"],
    refetchInterval: 60000, // Refetch every minute
  });

  const { data: breakdown } = useQuery<AnomalyTypeBreakdown[]>({
    queryKey: ["/api/dashboard/breakdown"],
    refetchInterval: 60000,
  });

  if (metricsLoading) {
    return (
      <div className="p-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <div className="animate-pulse">
                <div className="h-4 bg-slate-200 rounded w-3/4 mb-4"></div>
                <div className="h-8 bg-slate-200 rounded w-1/2 mb-2"></div>
                <div className="h-3 bg-slate-200 rounded w-2/3"></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const formatChangeValue = (value: number | undefined) => {
    if (value === undefined || value === null) return "+0.0%";
    const sign = value >= 0 ? "+" : "";
    return `${sign}${value.toFixed(1)}%`;
  };

  return (
    <div className="p-8">
      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard
          title="Total Anomalies"
          value={metricsWithChanges?.totalAnomalies || 0}
          change={formatChangeValue(metricsWithChanges?.totalAnomaliesChange)}
          changeType={metricsWithChanges?.totalAnomaliesChange && metricsWithChanges.totalAnomaliesChange >= 0 ? "negative" : "positive"}
          icon={AlertTriangle}
          iconColor="red"
        />
        <MetricCard
          title="Sessions Analyzed"
          value={metricsWithChanges?.sessionsAnalyzed || 0}
          change={formatChangeValue(metricsWithChanges?.sessionsAnalyzedChange)}
          changeType={metricsWithChanges?.sessionsAnalyzedChange && metricsWithChanges.sessionsAnalyzedChange >= 0 ? "positive" : "negative"}
          icon={BarChart3}
          iconColor="blue"
        />
        <MetricCard
          title="Detection Rate"
          value={`${metricsWithChanges?.detectionRate || 0}%`}
          change={formatChangeValue(metricsWithChanges?.detectionRateChange)}
          changeType={metricsWithChanges?.detectionRateChange && metricsWithChanges.detectionRateChange >= 0 ? "positive" : "negative"}
          icon={Shield}
          iconColor="green"
        />
        <MetricCard
          title="Files Processed"
          value={metricsWithChanges?.filesProcessed || 0}
          change={formatChangeValue(metricsWithChanges?.filesProcessedChange)}
          changeType={metricsWithChanges?.filesProcessedChange && metricsWithChanges.filesProcessedChange >= 0 ? "positive" : "negative"}
          icon={FileText}
          iconColor="purple"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Anomaly Trends Chart */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-slate-900">Anomaly Trends</h3>
            <div className="flex items-center space-x-2">
              <button className="text-sm text-slate-500 hover:text-slate-700">This week</button>
              <button className="text-sm text-primary-blue">Last 7 days</button>
            </div>
          </div>
          <div className="h-64 flex items-end space-x-2">
            {trends && trends.length > 0 ? (
              trends.map((trend, index) => {
                const maxCount = Math.max(...trends.map(t => t.count || 0));
                const height = maxCount > 0 ? ((trend.count || 0) / maxCount) * 100 : 5;
                const isToday = index === trends.length - 1;
                
                return (
                  <div
                    key={trend.date || index}
                    className={`flex-1 rounded-t transition-all hover:opacity-80 ${
                      isToday 
                        ? 'bg-blue-500' 
                        : 'bg-slate-300'
                    }`}
                    style={{ 
                      height: `${Math.max(height, 5)}%`,
                      minHeight: '4px'
                    }}
                    title={`${trend.date || 'Unknown'}: ${trend.count || 0} anomalies`}
                  />
                );
              })
            ) : (
              <div className="flex-1 flex items-center justify-center text-slate-500">
                <p>No trend data available</p>
              </div>
            )}
          </div>
          <div className="flex justify-between text-xs text-slate-500 mt-2">
            {trends?.map((trend, index) => (
              <span key={trend.date}>
                {trend.date ? new Date(trend.date).toLocaleDateString('en-US', { weekday: 'short' }) : 'N/A'}
              </span>
            ))}
          </div>
        </div>

        {/* Anomaly Types Breakdown */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
          <h3 className="text-lg font-semibold text-slate-900 mb-6">Anomaly Types</h3>
          <div className="space-y-4">
            {breakdown?.map((item, index) => {
              const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-blue-500'];
              const color = colors[index % colors.length];
              
              return (
                <div key={item.type} className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 ${color} rounded-full`}></div>
                    <span className="text-slate-700 capitalize">
                      {item.type ? item.type.replace('_', ' ') : 'Unknown'}
                    </span>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-semibold text-slate-900">
                      {item.percentage || 0}%
                    </div>
                    <div className="text-xs text-slate-500">
                      {item.count || 0} events
                    </div>
                  </div>
                </div>
              );
            })}
            {(!breakdown || breakdown.length === 0) && (
              <div className="text-center text-slate-500 py-8">
                No anomalies detected yet
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="text-lg font-semibold text-slate-900 mb-6">Recent Activity</h3>
        <div className="space-y-4">
          <div className="text-center text-slate-500 py-8">
            No recent activity to display. Upload files to start anomaly detection.
          </div>
        </div>
      </div>
    </div>
  );
}
