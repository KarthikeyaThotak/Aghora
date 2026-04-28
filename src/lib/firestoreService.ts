import { 
  collection, 
  addDoc, 
  getDocs, 
  doc, 
  updateDoc, 
  deleteDoc, 
  query, 
  where, 
  orderBy, 
  limit,
  serverTimestamp,
  DocumentData,
  QueryDocumentSnapshot
} from 'firebase/firestore';
import { 
  ref, 
  uploadBytes, 
  getDownloadURL, 
  deleteObject,
  listAll,
  getMetadata
} from 'firebase/storage';
import { db, storage, connectionManager } from '@/config/firebase';

export interface FileMetadata {
  id: string;
  name: string;
  size: number;
  sha256Hash: string;
  downloadURL: string;
  filePath: string;
  userId: string;
  uploadTime: any; // serverTimestamp
  status: 'processing' | 'analyzed' | 'error';
  analysisResults?: any;
  analysisSessionId?: string; // Link to analysis session
  createdAt?: any;
  updatedAt?: any;
}

export interface AnalysisSession {
  id: string;
  fileId: string;
  userId: string;
  fileName: string;
  sha256Hash: string;
  status: 'processing' | 'analyzed' | 'error';
  createdAt: any; // serverTimestamp
  updatedAt: any; // serverTimestamp
  analysisResults?: {
    threatLevel: 'Low' | 'Medium' | 'High' | 'Critical';
    detections: number;
    summary: string;
    details: any;
  };
  graphData?: {
    nodes: any[];
    connections: any[];
  };
}

export interface GraphNode {
  id: string;
  type: 'main' | 'sub' | 'connection';
  label: string;
  x: number;
  y: number;
  sessionId: string;
  userId: string;
  sha256Hash?: string;
  fileName?: string;
  details?: any;
  createdAt: any; // serverTimestamp
}

export interface UploadProgress {
  bytesTransferred: number;
  totalBytes: number;
  percentage: number;
}

export class FirestoreService {
  private static readonly COLLECTIONS = {
    UPLOADED_FILES: 'uploadedFiles',
    ANALYSIS_RESULTS: 'analysisResults',
    ANALYSIS_SESSIONS: 'analysisSessions',
    GRAPH_NODES: 'graphNodes',
    USER_PROFILES: 'userProfiles'
  };

  // Retry mechanism for Firestore operations
  private static async withRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    delay: number = 1000
  ): Promise<T> {
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        // Check if we're online before attempting the operation
        if (!navigator.onLine) {
          throw new Error('No internet connection');
        }
        
        return await operation();
      } catch (error) {
        lastError = error as Error;
        console.warn(`Firestore operation attempt ${attempt + 1} failed:`, error);
        
        // Check if it's a connection-related error
        const errorMessage = error instanceof Error ? error.message.toLowerCase() : '';
        const isConnectionError = errorMessage.includes('network') || 
                                 errorMessage.includes('connection') ||
                                 errorMessage.includes('blocked') ||
                                 errorMessage.includes('timeout');
        
        if (isConnectionError && attempt < maxRetries - 1) {
          // Try to reconnect
          await connectionManager.retryConnection(1, delay);
          // Wait before retrying
          await new Promise(resolve => setTimeout(resolve, delay * (attempt + 1)));
        } else if (attempt < maxRetries - 1) {
          // For non-connection errors, just wait and retry
          await new Promise(resolve => setTimeout(resolve, delay * (attempt + 1)));
        }
      }
    }
    
    throw lastError || new Error('Operation failed after all retries');
  }

  // File Upload Operations
  static async uploadFile(
    file: File, 
    userId: string, 
    sha256Hash?: string,
    onProgress?: (progress: UploadProgress) => void
  ): Promise<{ fileId: string; downloadURL: string; metadata: FileMetadata }> {
    const fileId = Math.random().toString(36).substring(7);
    const filePath = `malware-files/${userId}/${fileId}-${file.name}`;
    const storageRef = ref(storage, filePath);

    try {
      // Upload file to Firebase Storage
      const snapshot = await uploadBytes(storageRef, file);
      const downloadURL = await getDownloadURL(snapshot.ref);

      // Create file metadata
      const metadata: Omit<FileMetadata, 'id'> = {
        name: file.name,
        size: file.size,
        sha256Hash: sha256Hash || '', // Use provided hash or empty string
        downloadURL,
        filePath,
        userId,
        uploadTime: serverTimestamp(),
        status: 'processing',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      };

      // Store metadata in Firestore
      const docRef = await addDoc(collection(db, this.COLLECTIONS.UPLOADED_FILES), {
        ...metadata,
        id: fileId
      });

      return {
        fileId,
        downloadURL,
        metadata: { ...metadata, id: fileId }
      };
    } catch (error) {
      console.error('Error uploading file:', error);
      throw new Error(`Failed to upload file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Update file metadata
  static async updateFileMetadata(
    fileId: string, 
    updates: Partial<FileMetadata>,
    userId: string
  ): Promise<void> {
    return this.withRetry(async () => {
      if (!userId) {
        throw new Error('User ID is required for updating file metadata');
      }

      // First, find the document by querying with userId filter for security
      const fileQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('id', '==', fileId),
        where('userId', '==', userId)
      );
      
      const querySnapshot = await getDocs(fileQuery);
      
      if (querySnapshot.empty) {
        throw new Error('File not found or you do not have permission to update it');
      }

      const docRef = querySnapshot.docs[0].ref;
      
      // Ensure userId is preserved in the update to maintain security rules
      const updateData = {
        ...updates,
        userId: userId, // Ensure userId is preserved
        updatedAt: serverTimestamp()
      };
      
      // Update the document with the new data
      await updateDoc(docRef, updateData);
      
      console.log('File metadata updated successfully:', fileId);
    }).catch(error => {
      console.error('Error updating file metadata:', error);
      throw new Error(`Failed to update file metadata: ${error instanceof Error ? error.message : 'Unknown error'}`);
    });
  }

  // Get user's uploaded files
  static async getUserFiles(userId: string, limitCount: number = 50): Promise<FileMetadata[]> {
    return this.withRetry(async () => {
      const fileQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('userId', '==', userId),
        orderBy('uploadTime', 'desc'),
        limit(limitCount)
      );

      const querySnapshot = await getDocs(fileQuery);
      return querySnapshot.docs.map(doc => doc.data() as FileMetadata);
    }).catch(error => {
      console.error('Error fetching user files:', error);
      throw new Error(`Failed to fetch user files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    });
  }

  // Get file by ID (requires userId for proper permissions)
  static async getFileById(fileId: string, userId: string): Promise<FileMetadata | null> {
    try {
      const fileQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('id', '==', fileId),
        where('userId', '==', userId)
      );

      const querySnapshot = await getDocs(fileQuery);
      
      if (querySnapshot.empty) {
        return null;
      }

      return querySnapshot.docs[0].data() as FileMetadata;
    } catch (error) {
      console.error('Error fetching file by ID:', error);
      throw new Error(`Failed to fetch file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Delete file and its metadata
  static async deleteFile(fileId: string, userId: string): Promise<void> {
    try {
      // Query for the file with userId filter to ensure proper permissions
      const fileQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('id', '==', fileId),
        where('userId', '==', userId)
      );

      const querySnapshot = await getDocs(fileQuery);
      
      if (querySnapshot.empty) {
        throw new Error('File not found or you do not have permission to delete it');
      }

      const fileMetadata = querySnapshot.docs[0].data() as FileMetadata;
      const docRef = querySnapshot.docs[0].ref;

      // Delete file from Storage
      const storageRef = ref(storage, fileMetadata.filePath);
      await deleteObject(storageRef);

      // Delete metadata from Firestore
      await deleteDoc(docRef);
      
      console.log('File deleted successfully:', fileId);
    } catch (error) {
      console.error('Error deleting file:', error);
      throw new Error(`Failed to delete file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Search files by name or hash
  static async searchFiles(
    userId: string, 
    searchTerm: string, 
    limitCount: number = 20
  ): Promise<FileMetadata[]> {
    try {
      // Search by name (case-insensitive)
      const nameQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('userId', '==', userId),
        where('name', '>=', searchTerm),
        where('name', '<=', searchTerm + '\uf8ff'),
        orderBy('name'),
        limit(limitCount)
      );

      const nameSnapshot = await getDocs(nameQuery);
      const nameResults = nameSnapshot.docs.map(doc => doc.data() as FileMetadata);

      // Search by hash
      const hashQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('userId', '==', userId),
        where('sha256Hash', '==', searchTerm),
        limit(limitCount)
      );

      const hashSnapshot = await getDocs(hashQuery);
      const hashResults = hashSnapshot.docs.map(doc => doc.data() as FileMetadata);

      // Combine and deduplicate results
      const allResults = [...nameResults, ...hashResults];
      const uniqueResults = allResults.filter((file, index, self) => 
        index === self.findIndex(f => f.id === file.id)
      );

      return uniqueResults.slice(0, limitCount);
    } catch (error) {
      console.error('Error searching files:', error);
      throw new Error(`Failed to search files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Get file statistics
  static async getFileStats(userId: string): Promise<{
    totalFiles: number;
    totalSize: number;
    filesByStatus: Record<string, number>;
  }> {
    try {
      const fileQuery = query(
        collection(db, this.COLLECTIONS.UPLOADED_FILES),
        where('userId', '==', userId)
      );

      const querySnapshot = await getDocs(fileQuery);
      const files = querySnapshot.docs.map(doc => doc.data() as FileMetadata);

      const stats = {
        totalFiles: files.length,
        totalSize: files.reduce((sum, file) => sum + file.size, 0),
        filesByStatus: files.reduce((acc, file) => {
          acc[file.status] = (acc[file.status] || 0) + 1;
          return acc;
        }, {} as Record<string, number>)
      };

      return stats;
    } catch (error) {
      console.error('Error getting file stats:', error);
      throw new Error(`Failed to get file stats: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Batch operations
  static async batchUpdateFiles(
    fileIds: string[], 
    updates: Partial<FileMetadata>,
    userId?: string
  ): Promise<void> {
    try {
      const promises = fileIds.map(fileId => 
        this.updateFileMetadata(fileId, updates, userId)
      );
      
      await Promise.all(promises);
    } catch (error) {
      console.error('Error batch updating files:', error);
      throw new Error(`Failed to batch update files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Storage operations
  static async getFileDownloadURL(filePath: string): Promise<string> {
    try {
      const storageRef = ref(storage, filePath);
      return await getDownloadURL(storageRef);
    } catch (error) {
      console.error('Error getting download URL:', error);
      throw new Error(`Failed to get download URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  static async getFileMetadata(filePath: string): Promise<any> {
    try {
      const storageRef = ref(storage, filePath);
      return await getMetadata(storageRef);
    } catch (error) {
      console.error('Error getting file metadata:', error);
      throw new Error(`Failed to get file metadata: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Analysis Session Operations
  static async createAnalysisSession(
    fileId: string,
    userId: string,
    fileName: string,
    sha256Hash: string
  ): Promise<AnalysisSession> {
    try {
      const sessionId = Math.random().toString(36).substring(7);
      
      const analysisSession: Omit<AnalysisSession, 'id'> = {
        id: sessionId,
        fileId,
        userId,
        fileName,
        sha256Hash,
        status: 'processing',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        analysisResults: {
          threatLevel: 'Low',
          detections: 0,
          summary: 'Analysis in progress...',
          details: {}
        },
        graphData: {
          nodes: [],
          connections: []
        }
      };

      // Create analysis session document
      await addDoc(collection(db, this.COLLECTIONS.ANALYSIS_SESSIONS), analysisSession);

      // Create initial main graph node
      await this.createMainGraphNode(sessionId, userId, fileName, sha256Hash);

      // Update file metadata to link to analysis session
      await this.updateFileMetadata(fileId, { analysisSessionId: sessionId }, userId);

      return analysisSession as AnalysisSession;
    } catch (error) {
      console.error('Error creating analysis session:', error);
      throw new Error(`Failed to create analysis session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Graph Node Operations
  static async createMainGraphNode(
    sessionId: string,
    userId: string,
    fileName: string,
    sha256Hash: string
  ): Promise<GraphNode> {
    try {
      const nodeId = Math.random().toString(36).substring(7);
      
      const graphNode: Omit<GraphNode, 'id'> = {
        id: nodeId,
        type: 'main',
        label: fileName.length > 20 ? fileName.substring(0, 20) + '...' : fileName,
        x: 300,
        y: 200,
        sessionId,
        userId,
        sha256Hash,
        fileName,
        details: {
          description: `Main analysis node for ${fileName}`,
          riskLevel: 'critical',
          metadata: {
            'File Name': fileName,
            'SHA256': sha256Hash,
            'Upload Time': new Date().toLocaleString(),
            'Analysis Status': 'Processing'
          }
        },
        createdAt: serverTimestamp()
      };

      await addDoc(collection(db, this.COLLECTIONS.GRAPH_NODES), graphNode);
      return graphNode as GraphNode;
    } catch (error) {
      console.error('Error creating main graph node:', error);
      throw new Error(`Failed to create graph node: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Get analysis session by ID
  static async getAnalysisSession(sessionId: string, userId: string): Promise<AnalysisSession | null> {
    try {
      const sessionQuery = query(
        collection(db, this.COLLECTIONS.ANALYSIS_SESSIONS),
        where('id', '==', sessionId),
        where('userId', '==', userId)
      );

      const querySnapshot = await getDocs(sessionQuery);
      
      if (querySnapshot.empty) {
        return null;
      }

      return querySnapshot.docs[0].data() as AnalysisSession;
    } catch (error) {
      console.error('Error fetching analysis session:', error);
      throw new Error(`Failed to fetch analysis session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Get user's analysis sessions
  static async getUserAnalysisSessions(userId: string, limitCount: number = 50): Promise<AnalysisSession[]> {
    try {
      const sessionQuery = query(
        collection(db, this.COLLECTIONS.ANALYSIS_SESSIONS),
        where('userId', '==', userId),
        orderBy('createdAt', 'desc'),
        limit(limitCount)
      );

      const querySnapshot = await getDocs(sessionQuery);
      return querySnapshot.docs.map(doc => doc.data() as AnalysisSession);
    } catch (error) {
      console.error('Error fetching user analysis sessions:', error);
      throw new Error(`Failed to fetch analysis sessions: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Get graph nodes for a session
  static async getSessionGraphNodes(sessionId: string, userId: string): Promise<GraphNode[]> {
    try {
      const nodeQuery = query(
        collection(db, this.COLLECTIONS.GRAPH_NODES),
        where('sessionId', '==', sessionId),
        where('userId', '==', userId),
        orderBy('createdAt', 'asc')
      );

      const querySnapshot = await getDocs(nodeQuery);
      return querySnapshot.docs.map(doc => doc.data() as GraphNode);
    } catch (error) {
      console.error('Error fetching session graph nodes:', error);
      throw new Error(`Failed to fetch graph nodes: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Update analysis session
  static async updateAnalysisSession(
    sessionId: string,
    updates: Partial<AnalysisSession>
  ): Promise<void> {
    try {
      const sessionQuery = query(
        collection(db, this.COLLECTIONS.ANALYSIS_SESSIONS),
        where('id', '==', sessionId)
      );
      
      const querySnapshot = await getDocs(sessionQuery);
      
      if (querySnapshot.empty) {
        throw new Error('Analysis session not found');
      }

      const docRef = querySnapshot.docs[0].ref;
      
      await updateDoc(docRef, {
        ...updates,
        updatedAt: serverTimestamp()
      });
      
      console.log('Analysis session updated successfully:', sessionId);
    } catch (error) {
      console.error('Error updating analysis session:', error);
      throw new Error(`Failed to update analysis session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Delete analysis session and related data
  static async deleteAnalysisSession(sessionId: string, userId: string): Promise<void> {
    try {
      // Delete all graph nodes for this session
      const nodeQuery = query(
        collection(db, this.COLLECTIONS.GRAPH_NODES),
        where('sessionId', '==', sessionId),
        where('userId', '==', userId)
      );

      const nodeSnapshot = await getDocs(nodeQuery);
      const deleteNodePromises = nodeSnapshot.docs.map(doc => deleteDoc(doc.ref));
      await Promise.all(deleteNodePromises);

      // Delete the analysis session
      const sessionQuery = query(
        collection(db, this.COLLECTIONS.ANALYSIS_SESSIONS),
        where('id', '==', sessionId),
        where('userId', '==', userId)
      );

      const sessionSnapshot = await getDocs(sessionQuery);
      if (!sessionSnapshot.empty) {
        await deleteDoc(sessionSnapshot.docs[0].ref);
      }

      console.log('Analysis session deleted successfully:', sessionId);
    } catch (error) {
      console.error('Error deleting analysis session:', error);
      throw new Error(`Failed to delete analysis session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export default FirestoreService;

