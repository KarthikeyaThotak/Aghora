import { useState, useEffect } from "react";
import { 
  Search, 
  Download, 
  Trash2, 
  File, 
  Calendar, 
  HardDrive,
  AlertCircle,
  CheckCircle,
  Clock,
  RefreshCw
} from "lucide-react";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Input } from "./ui/input";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useFirestore } from "@/hooks/useFirestore";
import { formatSHA256ForDisplay } from "@/lib/hashUtils";

export const FirestoreFileManager = () => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const { toast } = useToast();
  const {
    files,
    loading,
    error,
    deleteFile,
    searchFiles,
    refreshFiles,
    fileStats
  } = useFirestore();

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (timestamp: any) => {
    if (!timestamp) return 'Unknown';
    const date = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'uploaded':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'processing':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'analyzed':
        return <CheckCircle className="h-4 w-4 text-blue-500" />;
      case 'error':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'uploaded':
        return 'bg-green-100 text-green-800';
      case 'processing':
        return 'bg-yellow-100 text-yellow-800';
      case 'analyzed':
        return 'bg-blue-100 text-blue-800';
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const handleSearch = async () => {
    await searchFiles(searchTerm);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const handleDeleteFile = async (fileId: string) => {
    try {
      await deleteFile(fileId);
      toast({
        title: "File deleted",
        description: "File has been successfully deleted",
      });
    } catch (error) {
      toast({
        title: "Delete failed",
        description: error instanceof Error ? error.message : "Failed to delete file",
        variant: "destructive",
      });
    }
  };

  const handleBulkDelete = async () => {
    if (selectedFiles.length === 0) return;

    try {
      const promises = selectedFiles.map(fileId => deleteFile(fileId));
      await Promise.all(promises);
      
      setSelectedFiles([]);
      toast({
        title: "Files deleted",
        description: `${selectedFiles.length} files have been successfully deleted`,
      });
    } catch (error) {
      toast({
        title: "Bulk delete failed",
        description: error instanceof Error ? error.message : "Failed to delete files",
        variant: "destructive",
      });
    }
  };

  const handleDownload = (downloadURL: string, fileName: string) => {
    const link = document.createElement('a');
    link.href = downloadURL;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const toggleFileSelection = (fileId: string) => {
    setSelectedFiles(prev => 
      prev.includes(fileId) 
        ? prev.filter(id => id !== fileId)
        : [...prev, fileId]
    );
  };

  const selectAllFiles = () => {
    setSelectedFiles(files.map(file => file.id));
  };

  const clearSelection = () => {
    setSelectedFiles([]);
  };

  return (
    <div className="space-y-6">
      {/* Header with Stats */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">File Manager</h2>
          <p className="text-muted-foreground">Manage your uploaded malware samples</p>
        </div>
        <Button onClick={refreshFiles} variant="outline" disabled={loading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      {fileStats && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="p-4">
            <div className="flex items-center space-x-2">
              <File className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Total Files</p>
                <p className="text-2xl font-bold">{fileStats.totalFiles}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center space-x-2">
              <HardDrive className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-sm font-medium">Total Size</p>
                <p className="text-2xl font-bold">{formatFileSize(fileStats.totalSize)}</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center space-x-2">
              <Calendar className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-sm font-medium">Status Distribution</p>
                <div className="flex space-x-1 mt-1">
                  {Object.entries(fileStats.filesByStatus).map(([status, count]) => (
                    <Badge key={status} variant="secondary" className="text-xs">
                      {status}: {count}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Search and Actions */}
      <Card className="p-4">
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search files by name or SHA256 hash..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyPress={handleKeyPress}
                className="pl-10"
              />
            </div>
          </div>
          <Button onClick={handleSearch} disabled={loading}>
            Search
          </Button>
          {selectedFiles.length > 0 && (
            <div className="flex items-center space-x-2">
              <span className="text-sm text-muted-foreground">
                {selectedFiles.length} selected
              </span>
              <Button 
                onClick={handleBulkDelete} 
                variant="destructive" 
                size="sm"
                disabled={loading}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete Selected
              </Button>
            </div>
          )}
        </div>
      </Card>

      {/* Error Display */}
      {error && (
        <Card className="p-4 border-red-200 bg-red-50">
          <div className="flex items-center space-x-2">
            <AlertCircle className="h-5 w-5 text-red-500" />
            <p className="text-red-700">{error}</p>
          </div>
        </Card>
      )}

      {/* Loading State */}
      {loading && (
        <Card className="p-8">
          <div className="flex items-center justify-center space-x-2">
            <RefreshCw className="h-5 w-5 animate-spin" />
            <p>Loading files...</p>
          </div>
        </Card>
      )}

      {/* Files List */}
      {!loading && files.length === 0 && (
        <Card className="p-8 text-center">
          <File className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
          <h3 className="text-lg font-semibold mb-2">No files found</h3>
          <p className="text-muted-foreground">
            {searchTerm ? 'No files match your search criteria.' : 'Upload some files to get started.'}
          </p>
        </Card>
      )}

      {!loading && files.length > 0 && (
        <div className="space-y-4">
          {/* Selection Controls */}
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Button 
                variant="outline" 
                size="sm" 
                onClick={selectAllFiles}
                disabled={files.length === 0}
              >
                Select All
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={clearSelection}
                disabled={selectedFiles.length === 0}
              >
                Clear Selection
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              {files.length} file{files.length !== 1 ? 's' : ''} found
            </p>
          </div>

          {/* Files Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {files.map((file) => (
              <Card key={file.id} className="p-4 hover:shadow-md transition-shadow">
                <div className="space-y-3">
                  {/* File Header */}
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2 flex-1 min-w-0">
                      <input
                        type="checkbox"
                        checked={selectedFiles.includes(file.id)}
                        onChange={() => toggleFileSelection(file.id)}
                        className="mt-1"
                      />
                      <File className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium truncate" title={file.name}>
                          {file.name}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {formatFileSize(file.size)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      {getStatusIcon(file.status)}
                      <Badge className={`text-xs ${getStatusColor(file.status)}`}>
                        {file.status}
                      </Badge>
                    </div>
                  </div>

                  {/* SHA256 Hash */}
                  {file.sha256Hash && (
                    <div className="bg-muted/50 p-2 rounded text-xs">
                      <p className="text-muted-foreground font-medium mb-1">SHA256:</p>
                      <p className="font-mono break-all">
                        {formatSHA256ForDisplay(file.sha256Hash)}
                      </p>
                    </div>
                  )}

                  {/* Upload Date */}
                  <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                    <Calendar className="h-3 w-3" />
                    <span>Uploaded: {formatDate(file.uploadTime)}</span>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownload(file.downloadURL, file.name)}
                      className="flex-1"
                    >
                      <Download className="h-3 w-3 mr-1" />
                      Download
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDeleteFile(file.id)}
                      className="text-red-600 hover:text-red-700 hover:bg-red-50"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default FirestoreFileManager;

