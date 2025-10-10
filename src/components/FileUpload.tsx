import { useState, useRef, useCallback } from "react";
import { Upload, File, X, CheckCircle, AlertCircle } from "lucide-react";
import { Progress } from "./ui/progress";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import { calculateFileSHA256, formatSHA256ForDisplay } from "@/lib/hashUtils";
import FirestoreService from "@/lib/firestoreService";

interface UploadedFile {
  id: string;
  name: string;
  size: number;
  progress: number;
  status: 'uploading' | 'completed' | 'error';
  url?: string;
  sha256Hash?: string;
}

interface FileUploadProps {
  onFileUploaded?: (file: { 
    id: string; 
    name: string; 
    sha256Hash: string;
    analysisSessionId: string;
  }) => void;
}

export const FileUpload = ({ onFileUploaded }: FileUploadProps) => {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();
  const { user } = useAuth();

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const uploadFile = async (file: File) => {
    const fileId = Math.random().toString(36).substring(7);
    const newFile: UploadedFile = {
      id: fileId,
      name: file.name,
      size: file.size,
      progress: 0,
      status: 'uploading'
    };

    setFiles(prev => [...prev, newFile]);

    try {
      // Check if user is authenticated
      if (!user) {
        throw new Error('Authentication required');
      }

      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setFiles(prev => prev.map(f => {
          if (f.id === fileId && f.progress < 90) {
            return { ...f, progress: f.progress + 10 };
          }
          return f;
        }));
      }, 200);
      
      try {
        // Calculate SHA256 hash before upload
        const sha256Hash = await calculateFileSHA256(file);
        
        // Upload file using FirestoreService with SHA256 hash
        const result = await FirestoreService.uploadFile(file, user.uid, sha256Hash);
        
        console.log('File uploaded successfully:', result.downloadURL);
        
        // Create analysis session for the uploaded file
        const analysisSession = await FirestoreService.createAnalysisSession(
          result.fileId,
          user.uid,
          file.name,
          sha256Hash
        );
        
        console.log('Analysis session created:', analysisSession.id);
        
        clearInterval(progressInterval);

        // Update file status with SHA256 hash
        setFiles(prev => prev.map(f => 
          f.id === fileId 
            ? { ...f, status: 'completed', progress: 100, sha256Hash, url: result.downloadURL }
            : f
        ));

        toast({
          title: "Upload successful",
          description: `${file.name} uploaded successfully. Analysis session created. SHA256: ${formatSHA256ForDisplay(sha256Hash)}`,
        });

        // Notify parent component about the uploaded file with analysis session
        if (onFileUploaded) {
          onFileUploaded({
            id: result.fileId,
            name: file.name,
            sha256Hash: sha256Hash,
            analysisSessionId: analysisSession.id
          });
        }
        
      } catch (uploadError) {
        console.error('FirestoreService upload failed:', uploadError);
        throw new Error('Failed to upload file');
      }

    } catch (error) {
      console.error('Upload error:', error);
      setFiles(prev => prev.map(f => 
        f.id === fileId ? { ...f, status: 'error' } : f
      ));

      toast({
        title: "Upload failed",
        description: error instanceof Error ? error.message : "Failed to upload file",
        variant: "destructive",
      });
    }
  };

  const handleFiles = useCallback((fileList: FileList) => {
    Array.from(fileList).forEach(file => {
      // Basic file validation
      if (file.size > 100 * 1024 * 1024) { // 100MB limit
        toast({
          title: "File too large",
          description: `${file.name} exceeds 100MB limit`,
          variant: "destructive",
        });
        return;
      }
      uploadFile(file);
    });
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    if (e.dataTransfer.files) {
      handleFiles(e.dataTransfer.files);
    }
  }, [handleFiles]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleFileSelect = () => {
    fileInputRef.current?.click();
  };

  const removeFile = (fileId: string) => {
    setFiles(prev => prev.filter(f => f.id !== fileId));
  };

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <Card 
        className={`border-2 border-dashed transition-all duration-200 cursor-pointer ${
          isDragOver 
            ? 'border-primary bg-primary/5 shadow-glow-soft' 
            : 'border-border hover:border-primary/50 hover:bg-primary/5'
        }`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={handleFileSelect}
      >
        <div className="p-8 text-center">
          <Upload className={`h-12 w-12 mx-auto mb-4 transition-colors ${
            isDragOver ? 'text-primary' : 'text-muted-foreground'
          }`} />
          <h3 className="text-lg font-semibold mb-2">
            {isDragOver ? 'Drop files here' : 'Upload Malware Samples'}
          </h3>
          <p className="text-muted-foreground mb-4">
            Drag and drop files here, or click to browse
          </p>
          <div className="bg-green-50 border border-green-200 rounded-lg p-3 mb-4">
            <p className="text-sm text-green-800">
              <strong>Firebase Integration:</strong> Files are stored in Firebase Storage with metadata in Firestore. 
              SHA256 hash calculation and main node creation are fully functional.
            </p>
          </div>
          <Button variant="secondary" size="sm">
            Select Files
          </Button>
          <p className="text-xs text-muted-foreground mt-2">
            Maximum file size: 100MB
          </p>
        </div>
      </Card>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={(e) => e.target.files && handleFiles(e.target.files)}
        className="hidden"
        accept="*/*"
      />

      {/* File List */}
      {files.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-foreground">Upload Progress</h4>
          {files.map((file) => (
            <Card key={file.id} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-3">
                  <File className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <p className="text-sm font-medium truncate max-w-xs">
                      {file.name}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {formatFileSize(file.size)}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  {file.status === 'completed' && (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  )}
                  {file.status === 'error' && (
                    <AlertCircle className="h-5 w-5 text-destructive" />
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeFile(file.id)}
                    className="h-6 w-6"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {file.status === 'uploading' && (
                <div className="space-y-1">
                  <Progress value={file.progress} className="h-2" />
                  <p className="text-xs text-muted-foreground">
                    {Math.round(file.progress)}% uploaded
                  </p>
                </div>
              )}

              {file.status === 'error' && (
                <p className="text-xs text-destructive">
                  Upload failed. Please try again.
                </p>
              )}

              {file.status === 'completed' && (
                <div className="space-y-1">
                  <p className="text-xs text-green-600">
                    Upload completed successfully
                  </p>
                  {file.sha256Hash && (
                    <div className="bg-muted/50 p-2 rounded text-xs">
                      <p className="text-muted-foreground font-medium">SHA256:</p>
                      <p className="font-mono text-xs break-all">
                        {formatSHA256ForDisplay(file.sha256Hash)}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};