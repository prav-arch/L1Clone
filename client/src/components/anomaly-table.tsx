import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Search, RefreshCw, AlertTriangle, Smartphone, Network, Shield } from "lucide-react";
import { RecommendationsPopup } from "./RecommendationsPopup";
import { ExplainableAIModal } from "./ExplainableAIModal";
import type { Anomaly } from "@shared/schema";

export default function AnomalyTable() {
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedAnomalyForDetails, setSelectedAnomalyForDetails] = useState<Anomaly | null>(null);
  const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);

  const { data: anomalies = [], isLoading, refetch } = useQuery<Anomaly[]>({
    queryKey: ["/api/anomalies"],
    refetchInterval: 10000, // Refetch every 10 seconds
  });

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "fronthaul":
        return <AlertTriangle className="w-4 h-4 mr-1" />;
      case "ue_event":
        return <Smartphone className="w-4 h-4 mr-1" />;
      case "mac_address":
        return <Network className="w-4 h-4 mr-1" />;
      case "protocol":
        return <Shield className="w-4 h-4 mr-1" />;
      default:
        return <AlertTriangle className="w-4 h-4 mr-1" />;
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case "fronthaul":
        return "Fronthaul";
      case "ue_event":
        return "UE Event";
      case "mac_address":
        return "MAC Address";
      case "protocol":
        return "Protocol";
      default:
        return type;
    }
  };

  const formatTimestamp = (timestamp: string | Date) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const handleGetRecommendations = (anomaly: Anomaly) => {
    setSelectedAnomaly(anomaly);
    setIsModalOpen(true);
  };

  const handleGetDetails = (anomaly: Anomaly) => {
    setSelectedAnomalyForDetails(anomaly);
    setIsDetailsModalOpen(true);
  };

  // Filter anomalies based on search and filters
  const filteredAnomalies = anomalies.filter((anomaly) => {
    const matchesSearch = anomaly.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         anomaly.source_file.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === "all" || anomaly.type === typeFilter;
    const matchesSeverity = severityFilter === "all" || anomaly.severity === severityFilter;
    
    return matchesSearch && matchesType && matchesSeverity;
  });

  // Debug logging to see if buttons are rendering
  console.log('AnomalyTable rendered with', filteredAnomalies.length, 'anomalies');

  if (isLoading) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-8">
        <div className="animate-pulse">
          <div className="h-4 bg-slate-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-12 bg-slate-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Filters and Search */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-4 h-4" />
              <Input
                placeholder="Search anomalies..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 w-64"
              />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="fronthaul">Fronthaul Issues</SelectItem>
                <SelectItem value="ue_event">UE Events</SelectItem>
                <SelectItem value="mac_address">MAC Address</SelectItem>
                <SelectItem value="protocol">Protocol</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="All Severities" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button 
            onClick={() => refetch()} 
            className="bg-primary-blue text-white hover:bg-indigo-700"
            style={{ backgroundColor: 'hsl(var(--primary-blue))' }}
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Anomalies Table */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200">
          <h3 className="text-lg font-semibold text-slate-900">Detected Anomalies</h3>
          <p className="text-sm text-slate-600 mt-1">Recent network anomalies requiring attention</p>
        </div>

        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-slate-50">
                <TableHead>Timestamp</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAnomalies.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-slate-500">
                    No anomalies found matching your criteria.
                  </TableCell>
                </TableRow>
              ) : (
                filteredAnomalies.map((anomaly) => (
                  <TableRow key={anomaly.id} className="hover:bg-slate-50">
                    <TableCell className="whitespace-nowrap">
                      {formatTimestamp(anomaly.timestamp)}
                    </TableCell>
                    <TableCell>
                      <span className={`type-badge ${anomaly.type}`}>
                        {getTypeIcon(anomaly.type)}
                        {getTypeLabel(anomaly.type)}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-md">
                      <div className="space-y-1">
                        <div className="truncate">{anomaly.description}</div>
                        {anomaly.packet_number && (
                          <div className="text-xs text-blue-600 font-mono">
                            Packet #{anomaly.packet_number}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-slate-600">
                      {anomaly.source_file}
                    </TableCell>
                    <TableCell>
                      <span className={`severity-badge ${anomaly.severity}`}>
                        {anomaly.severity.charAt(0).toUpperCase() + anomaly.severity.slice(1)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex space-x-2">
                        <Button
                          size="sm"
                          onClick={() => handleGetRecommendations(anomaly)}
                          className="bg-blue-600 text-white hover:bg-blue-700 text-xs px-3 py-1"
                          data-testid={`button-recommendations-${anomaly.id}`}
                        >
                          Get Recommendations
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleGetDetails(anomaly)}
                          className="text-xs px-3 py-1 border-blue-600 text-blue-600 hover:bg-blue-50"
                          data-testid={`button-details-${anomaly.id}`}
                        >
                          Details
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        {filteredAnomalies.length > 0 && (
          <div className="px-6 py-4 border-t border-slate-200 flex items-center justify-between">
            <div className="text-sm text-slate-600">
              Showing {filteredAnomalies.length} of {anomalies.length} results
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="sm" disabled>
                Previous
              </Button>
              <Button 
                size="sm"
                className="bg-primary-blue text-white"
                style={{ backgroundColor: 'hsl(var(--primary-blue))' }}
              >
                1
              </Button>
              <Button variant="outline" size="sm" disabled>
                Next
              </Button>
            </div>
          </div>
        )}
      </div>

      <RecommendationsPopup
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        anomaly={selectedAnomaly}
      />

      <ExplainableAIModal
        isOpen={isDetailsModalOpen}
        onClose={() => setIsDetailsModalOpen(false)}
        anomaly={selectedAnomalyForDetails}
      />
    </>
  );
}
