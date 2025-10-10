# Firestore Database Usage Guide

This guide explains how to use Firestore Database for file uploads and management in the Shadow Scribe Vision application.

## Overview

The application now uses Firebase Firestore for storing file metadata and Firebase Storage for storing actual files. All Supabase dependencies have been removed.

## Key Components

### 1. FirestoreService (`src/lib/firestoreService.ts`)

A comprehensive service class that handles all Firestore operations:

#### File Upload Operations
```typescript
// Upload a file
const result = await FirestoreService.uploadFile(file, userId);

// Update file metadata
await FirestoreService.updateFileMetadata(fileId, { sha256Hash: "abc123..." });

// Get user's files
const files = await FirestoreService.getUserFiles(userId);

// Search files
const results = await FirestoreService.searchFiles(userId, "searchTerm");

// Delete file
await FirestoreService.deleteFile(fileId, userId);
```

#### File Metadata Structure
```typescript
interface FileMetadata {
  id: string;
  name: string;
  size: number;
  sha256Hash: string;
  downloadURL: string;
  filePath: string;
  userId: string;
  uploadTime: any; // serverTimestamp
  status: 'uploaded' | 'processing' | 'analyzed' | 'error';
  analysisResults?: any;
  createdAt?: any;
  updatedAt?: any;
}
```

### 2. useFirestore Hook (`src/hooks/useFirestore.ts`)

A React hook that provides easy access to Firestore operations:

```typescript
const {
  files,
  loading,
  error,
  uploadFile,
  deleteFile,
  updateFile,
  searchFiles,
  refreshFiles,
  fileStats
} = useFirestore();
```

### 3. Updated FileUpload Component (`src/components/FileUpload.tsx`)

The FileUpload component now uses FirestoreService for all operations:

- Files are uploaded to Firebase Storage
- Metadata is stored in Firestore
- SHA256 hash calculation and storage
- Progress tracking and error handling

### 4. FirestoreFileManager Component (`src/components/FirestoreFileManager.tsx`)

A comprehensive file management interface that provides:

- File listing with search functionality
- Bulk operations (select all, delete selected)
- File statistics and status tracking
- Download functionality
- Status indicators and progress tracking

## Firebase Configuration

The Firebase configuration is located in `src/config/firebase.ts`:

```typescript
import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';
import { getStorage } from 'firebase/storage';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
```

## Environment Variables

Make sure you have the following environment variables set:

```env
VITE_FIREBASE_API_KEY=your_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

## Firestore Collections

The application uses the following Firestore collections:

### `uploadedFiles`
Stores metadata for uploaded files:
- `id`: Unique file identifier
- `name`: Original filename
- `size`: File size in bytes
- `sha256Hash`: SHA256 hash of the file
- `downloadURL`: Firebase Storage download URL
- `filePath`: Path in Firebase Storage
- `userId`: ID of the user who uploaded the file
- `uploadTime`: Server timestamp of upload
- `status`: Current status of the file
- `analysisResults`: Optional analysis results
- `createdAt`: Creation timestamp
- `updatedAt`: Last update timestamp

## Usage Examples

### Uploading a File
```typescript
import { useFirestore } from '@/hooks/useFirestore';

const { uploadFile } = useFirestore();

const handleFileUpload = async (file: File) => {
  try {
    await uploadFile(file);
    console.log('File uploaded successfully');
  } catch (error) {
    console.error('Upload failed:', error);
  }
};
```

### Managing Files
```typescript
import FirestoreFileManager from '@/components/FirestoreFileManager';

// Use the component in your app
<FirestoreFileManager />
```

### Custom File Operations
```typescript
import FirestoreService from '@/lib/firestoreService';

// Get file statistics
const stats = await FirestoreService.getFileStats(userId);

// Search files
const results = await FirestoreService.searchFiles(userId, "malware.exe");

// Batch operations
await FirestoreService.batchUpdateFiles(fileIds, { status: 'analyzed' });
```

## Security Rules

Make sure your Firestore security rules are properly configured. Example rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only access their own files
    match /uploadedFiles/{document} {
      allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;
    }
  }
}
```

## Firebase Storage Rules

Example Firebase Storage security rules:

```javascript
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /malware-files/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

## Migration from Supabase

The following Supabase-related files and dependencies have been removed:

- `src/integrations/supabase/` directory
- `supabase/` directory
- `@supabase/supabase-js` package dependency
- All Supabase imports and usage

## Benefits of Firestore

1. **Real-time Updates**: Firestore provides real-time listeners for data changes
2. **Scalability**: Automatic scaling without configuration
3. **Offline Support**: Built-in offline persistence
4. **Security**: Fine-grained security rules
5. **Integration**: Seamless integration with other Firebase services
6. **Performance**: Optimized for mobile and web applications

## Troubleshooting

### Common Issues

1. **Authentication Required**: Make sure users are authenticated before uploading files
2. **Permission Denied**: Check Firestore and Storage security rules
3. **File Size Limits**: Firebase Storage has file size limits (check your plan)
4. **Network Issues**: Handle network connectivity issues gracefully

### Debug Mode

Enable Firestore debug mode in development:

```typescript
import { connectFirestoreEmulator } from 'firebase/firestore';

if (import.meta.env.DEV) {
  connectFirestoreEmulator(db, 'localhost', 8080);
}
```

## Next Steps

1. Set up Firebase project and configure environment variables
2. Deploy Firestore and Storage security rules
3. Test file upload and management functionality
4. Implement additional features like file analysis integration
5. Set up monitoring and logging for production use

