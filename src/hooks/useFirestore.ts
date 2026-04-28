import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import FirestoreService, { FileMetadata } from '@/lib/firestoreService';

export interface UseFirestoreReturn {
  files: FileMetadata[];
  loading: boolean;
  error: string | null;
  uploadFile: (file: File) => Promise<void>;
  deleteFile: (fileId: string) => Promise<void>;
  updateFile: (fileId: string, updates: Partial<FileMetadata>) => Promise<void>;
  searchFiles: (searchTerm: string) => Promise<void>;
  refreshFiles: () => Promise<void>;
  fileStats: {
    totalFiles: number;
    totalSize: number;
    filesByStatus: Record<string, number>;
  } | null;
}

export const useFirestore = (): UseFirestoreReturn => {
  const [files, setFiles] = useState<FileMetadata[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileStats, setFileStats] = useState<{
    totalFiles: number;
    totalSize: number;
    filesByStatus: Record<string, number>;
  } | null>(null);

  const { user } = useAuth();

  const fetchFiles = useCallback(async () => {
    if (!user) {
      setFiles([]);
      setFileStats(null);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const userFiles = await FirestoreService.getUserFiles(user.uid);
      setFiles(userFiles);

      const stats = await FirestoreService.getFileStats(user.uid);
      setFileStats(stats);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch files';
      setError(errorMessage);
      console.error('Error fetching files:', err);
    } finally {
      setLoading(false);
    }
  }, [user]);

  const uploadFile = useCallback(async (file: File) => {
    if (!user) {
      throw new Error('User must be authenticated to upload files');
    }

    setLoading(true);
    setError(null);

    try {
      // Calculate SHA256 hash before upload
      const { calculateFileSHA256 } = await import('@/lib/hashUtils');
      const sha256Hash = await calculateFileSHA256(file);
      
      await FirestoreService.uploadFile(file, user.uid, sha256Hash);
      // Refresh the files list after successful upload
      await fetchFiles();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to upload file';
      setError(errorMessage);
      console.error('Error uploading file:', err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [user, fetchFiles]);

  const deleteFile = useCallback(async (fileId: string) => {
    if (!user) {
      throw new Error('User must be authenticated to delete files');
    }

    setLoading(true);
    setError(null);

    try {
      await FirestoreService.deleteFile(fileId, user.uid);
      // Remove the file from local state immediately for better UX
      setFiles(prev => prev.filter(file => file.id !== fileId));
      
      // Refresh stats
      const stats = await FirestoreService.getFileStats(user.uid);
      setFileStats(stats);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to delete file';
      setError(errorMessage);
      console.error('Error deleting file:', err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [user]);

  const updateFile = useCallback(async (fileId: string, updates: Partial<FileMetadata>) => {
    if (!user) {
      throw new Error('User must be authenticated to update files');
    }

    setLoading(true);
    setError(null);

    try {
      await FirestoreService.updateFileMetadata(fileId, updates, user.uid);
      
      // Update local state
      setFiles(prev => prev.map(file => 
        file.id === fileId ? { ...file, ...updates } : file
      ));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update file';
      setError(errorMessage);
      console.error('Error updating file:', err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [user]);

  const searchFiles = useCallback(async (searchTerm: string) => {
    if (!user) {
      throw new Error('User must be authenticated to search files');
    }

    if (!searchTerm.trim()) {
      await fetchFiles();
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const searchResults = await FirestoreService.searchFiles(user.uid, searchTerm);
      setFiles(searchResults);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to search files';
      setError(errorMessage);
      console.error('Error searching files:', err);
    } finally {
      setLoading(false);
    }
  }, [user, fetchFiles]);

  const refreshFiles = useCallback(async () => {
    await fetchFiles();
  }, [fetchFiles]);

  // Fetch files when user changes
  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  return {
    files,
    loading,
    error,
    uploadFile,
    deleteFile,
    updateFile,
    searchFiles,
    refreshFiles,
    fileStats
  };
};

export default useFirestore;

