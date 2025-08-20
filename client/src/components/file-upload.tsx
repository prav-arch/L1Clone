import { useState, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { CloudUpload, File } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";

export default function FileUpload() {
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await apiRequest('POST', '/api/files/upload', formData);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "File uploaded successfully",
        description: "Your file is being processed. Check the file manager for status updates.",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/files'] });
    },
    onError: (error) => {
      toast({
        title: "Upload failed",
        description: error.message || "Failed to upload file. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    handleFiles(files);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      handleFiles(files);
    }
  };

  const handleFiles = (files: File[]) => {
    files.forEach((file) => {
      // Validate file type and size
      const validTypes = ['.pcap', '.pcapng', '.log', '.txt'];
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      
      if (!validTypes.includes(fileExtension)) {
        toast({
          title: "Invalid file type",
          description: `${file.name} is not a supported file type. Please upload PCAP or log files.`,
          variant: "destructive",
        });
        return;
      }

      if (file.size > 100 * 1024 * 1024) { // 100MB limit
        toast({
          title: "File too large",
          description: `${file.name} is larger than 100MB. Please upload a smaller file.`,
          variant: "destructive",
        });
        return;
      }

      uploadMutation.mutate(file);
    });
  };

  const openFileDialog = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
      <h3 className="text-lg font-semibold text-slate-900 mb-4">File Upload</h3>
      
      <div
        className={`upload-dropzone border-2 border-dashed rounded-lg p-8 text-center transition-all ${
          isDragOver 
            ? 'border-primary-blue bg-slate-50 drag-over' 
            : 'border-slate-300 hover:border-primary-blue'
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={openFileDialog}
      >
        <CloudUpload className="mx-auto h-12 w-12 text-slate-400 mb-4" />
        <p className="text-lg font-medium text-slate-900 mb-2">Upload PCAP or Log Files</p>
        <p className="text-slate-600 mb-4">Drag and drop files here, or click to browse</p>
        
        <Button 
          type="button"
          className="bg-primary-blue text-white hover:bg-indigo-700"
          style={{ backgroundColor: 'hsl(var(--primary-blue))' }}
          disabled={uploadMutation.isPending}
        >
          {uploadMutation.isPending ? 'Uploading...' : 'Choose Files'}
        </Button>
        
        <p className="text-xs text-slate-500 mt-2">
          Supported formats: .pcap, .pcapng, .log, .txt (Max 100MB)
        </p>

        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".pcap,.pcapng,.log,.txt"
          onChange={handleFileSelect}
          className="hidden"
        />
      </div>
    </div>
  );
}
