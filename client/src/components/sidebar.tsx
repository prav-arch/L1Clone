import { Link, useLocation } from "wouter";
import { 
  BarChart3, 
  AlertTriangle, 
  Wifi
} from "lucide-react";

interface SidebarProps {
  setCurrentPage: (page: string) => void;
}

export default function Sidebar({ setCurrentPage }: SidebarProps) {
  const [location] = useLocation();

  const navigationItems = [
    { path: "/dashboard", icon: BarChart3, label: "Dashboard" },
    { path: "/anomalies", icon: AlertTriangle, label: "Anomalies" },
  ];

  const handleNavClick = (label: string) => {
    setCurrentPage(label);
  };

  return (
    <div className="fixed inset-y-0 left-0 z-50 sidebar-width bg-white shadow-lg border-r border-slate-200">
      {/* Logo */}
      <div className="flex items-center px-6 py-4 border-b border-slate-200">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 bg-primary-blue rounded-lg flex items-center justify-center">
            <Wifi className="text-white h-4 w-4" />
          </div>
          <span className="text-lg font-bold text-slate-800">L1 Troubleshooting</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="px-3 py-4">
        <div className="space-y-1">
          {navigationItems.map((item) => {
            const isActive = location === item.path || (location === "/" && item.path === "/dashboard");
            return (
              <Link
                key={item.path}
                href={item.path}
                className={`nav-item ${isActive ? "active" : ""}`}
                onClick={() => handleNavClick(item.label)}
              >
                <item.icon className="w-5 h-5" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </div>
      </nav>
    </div>
  );
}
