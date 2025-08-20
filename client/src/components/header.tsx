import { Button } from "@/components/ui/button";
import { Upload, User } from "lucide-react";

interface HeaderProps {
  currentPage: string;
}

export default function Header({ currentPage }: HeaderProps) {
  const getPageSubtitle = (page: string) => {
    switch (page) {
      case "Dashboard":
        return "Network anomaly detection and analysis";
      case "Anomalies":
        return "Detected network anomalies and recommendations";
      case "File Manager":
        return "Upload and manage PCAP and log files";
      default:
        return "Network anomaly detection and analysis";
    }
  };

  return (
    <header className="bg-white shadow-sm border-b border-slate-200">
      <div className="px-8 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">{currentPage}</h1>
            <p className="text-slate-600 mt-1">{getPageSubtitle(currentPage)}</p>
          </div>
          <div className="flex items-center space-x-4">
            <Button 
              className="bg-primary-blue text-white hover:bg-indigo-700 transition-colors"
              style={{ backgroundColor: 'hsl(var(--primary-blue))' }}
            >
              <Upload className="w-4 h-4 mr-2" />
              Upload Files
            </Button>
            <div className="w-10 h-10 bg-slate-200 rounded-full flex items-center justify-center">
              <User className="w-5 h-5 text-slate-600" />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
