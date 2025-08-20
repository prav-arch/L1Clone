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
import { Badge } from "@/components/ui/badge";
import FileUpload from "@/components/file-upload";
import { 
  FileText, 
  Download, 
  Eye, 
  Trash2, 
  Filter, 
  MoreHorizontal,
  CheckCircle,
  Clock,
  AlertCircle,
  Loader2
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import type { ProcessedFile } from "@shared/schema";

export default function FileManager() {
  const { toast } = useToast();

  const { data: files = [], isLoading, refetch } = useQuery<ProcessedFile[]>({
    queryKey: ["/api/files"],
    refetchInterval: 5000, // Refetch every 5 seconds to update processing status
  });

  const getFileIcon = (fileType: string) => {
    switch (fileType.toLowerCase()) {
      case "pcap":
        return <FileText className="text-blue-500 w-5 h-5" />;
      case "log":
        return <FileText className="text-green-500 w-5 h-5" />;
      default:
        return <FileText className="text-gray-500 w-5 h-5" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return (
          <Badge variant="outline" className="status-badge completed">
            <CheckCircle className="w-3 h-3 mr-1" />
            Processed
          </Badge>
        );
      case "processing":
        return (
          <Badge variant="outline" className="status-badge processing">
            <Loader2 className="w-3 h-3 mr-1 animate-spin" />
            Processing
          </Badge>
        );
      case "pending":
        return (
          <Badge variant="outline" className="status-badge pending">
            <Clock className="w-3 h-3 mr-1" />
            Pending
          </Badge>
        );
      case "failed":
        return (
          <Badge variant="outline" className="status-badge failed">
            <AlertCircle className="w-3 h-3 mr-1" />
            Failed
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="status-badge pending">
            {status}
          </Badge>
        );
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatDate = (dateString: string | Date) => {
    const date = new Date(dateString);
    return date.toLocaleString("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const handleViewFile = (file: ProcessedFile) => {
    toast({
      title: "View File",
      description: `Viewing details for ${file.filename}`,
    });
    // TODO: Implement file viewing functionality
  };

  const handleDownloadFile = (file: ProcessedFile) => {
    toast({
      title: "Download Started",
      description: `Downloading ${file.filename}`,
    });
    // TODO: Implement file download functionality
  };

  const handleDeleteFile = (file: ProcessedFile) => {
    toast({
      title: "Delete File",
      description: `Are you sure you want to delete ${file.filename}?`,
    });
    // TODO: Implement file deletion functionality
  };

  const handleExport = () => {
    toast({
      title: "Export",
      description: "Exporting file list...",
    });
    // TODO: Implement export functionality
  };

  if (isLoading) {
    return (
      <div className="p-8">
        <FileUpload />
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
      </div>
    );
  }

  return (
    <div className="p-8">
      {/* Upload Section */}
      <FileUpload />

      {/* File List */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200">
        <div className="px-6 py-4 border-b border-slate-200">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-slate-900">Processed Files</h3>
              <p className="text-sm text-slate-600 mt-1">
                Manage your uploaded PCAP and log files
              </p>
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="sm">
                <Filter className="w-4 h-4 mr-1" />
                Filter
              </Button>
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="w-4 h-4 mr-1" />
                Export
              </Button>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-slate-50">
                <TableHead>File Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Upload Date</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Anomalies Found</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {files.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-slate-500">
                    No files uploaded yet. Use the upload section above to get started.
                  </TableCell>
                </TableRow>
              ) : (
                files.map((file) => (
                  <TableRow key={file.id} className="hover:bg-slate-50">
                    <TableCell>
                      <div className="flex items-center space-x-3">
                        {getFileIcon(file.file_type)}
                        <span className="text-sm font-medium text-slate-900 max-w-xs truncate">
                          {file.filename}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-slate-600 uppercase">
                        {file.file_type}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-slate-600">
                        {formatFileSize(file.file_size)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-slate-600">
                        {formatDate(file.upload_date)}
                      </span>
                    </TableCell>
                    <TableCell>
                      {getStatusBadge(file.processing_status)}
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-slate-900">
                        {file.processing_status === "completed" 
                          ? file.anomalies_found || 0
                          : "-"
                        }
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleViewFile(file)}
                          disabled={file.processing_status !== "completed"}
                          className="p-1 h-8 w-8"
                        >
                          <Eye className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDownloadFile(file)}
                          className="p-1 h-8 w-8"
                        >
                          <Download className="w-4 h-4" />
                        </Button>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm" className="p-1 h-8 w-8">
                              <MoreHorizontal className="w-4 h-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleDeleteFile(file)}>
                              <Trash2 className="w-4 h-4 mr-2 text-red-600" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* Status Summary */}
        {files.length > 0 && (
          <div className="px-6 py-4 border-t border-slate-200">
            <div className="flex items-center justify-between">
              <div className="text-sm text-slate-600">
                Total: {files.length} files | 
                Completed: {files.filter(f => f.processing_status === "completed").length} | 
                Processing: {files.filter(f => f.processing_status === "processing").length} | 
                Failed: {files.filter(f => f.processing_status === "failed").length}
              </div>
              <div className="text-sm text-slate-600">
                Total Anomalies: {files.reduce((sum, file) => sum + (file.anomalies_found || 0), 0)}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
