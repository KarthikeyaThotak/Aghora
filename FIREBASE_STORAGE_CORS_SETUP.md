# Firebase Storage CORS Setup Guide

## Issue Resolved: CORS Error with Firebase Storage

The error you encountered:
```
Access to fetch at 'https://firebasestorage.googleapis.com/v0/b/aghora-c506a.appspot.com/o?name=malware-files%2Fe5TzgeuoanSmg1e67XSAU6AV8223%2Frh4w2l-KarthikeyaThota.pdf' from origin 'http://localhost:8080' has been blocked by CORS policy
```

## Root Cause
1. **Incorrect Storage Bucket URL**: The bucket URL was pointing to `.appspot.com` instead of `.firebasestorage.app`
2. **Missing CORS Configuration**: Firebase Storage needed proper CORS settings for localhost development
3. **Vite Configuration**: The Vite dev server needed proper CORS headers and proxy configuration

## Solutions Applied

### 1. Updated Environment Variables
```env
# Before (incorrect)
VITE_FIREBASE_STORAGE_BUCKET="aghora-c506a.appspot.com"

# After (correct)
VITE_FIREBASE_STORAGE_BUCKET="aghora-c506a.firebasestorage.app"
```

### 2. Updated Vite Configuration (`vite.config.ts`)
```typescript
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
    cors: true,
    proxy: {
      // Proxy Firebase Storage requests to avoid CORS issues
      '/firebase-storage': {
        target: 'https://firebasestorage.googleapis.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/firebase-storage/, ''),
      },
    },
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
      'Cross-Origin-Embedder-Policy': 'unsafe-none',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    },
  },
  // ... rest of config
}));
```

### 3. Updated CORS Configuration (`cors.json`)
```json
[
  {
    "origin": [
      "http://localhost:8080",
      "http://localhost:5173",
      "http://127.0.0.1:8080",
      "http://127.0.0.1:5173",
      "https://lab.karthikeyathota.page",
      "https://aghora-c506a.web.app",
      "https://aghora-c506a.firebaseapp.com"
    ],
    "method": [
      "GET",
      "POST",
      "PUT",
      "HEAD",
      "DELETE",
      "OPTIONS"
    ],
    "responseHeader": [
      "Content-Type",
      "Access-Control-Allow-Origin",
      "Access-Control-Allow-Methods",
      "Access-Control-Allow-Headers",
      "Access-Control-Max-Age",
      "x-goog-meta-*"
    ],
    "maxAgeSeconds": 3600
  }
]
```

### 4. Firebase Storage Rules (`firebase-storage.rules`)
```javascript
rules_version = '2';

service firebase.storage {
  match /b/{bucket}/o {
    // Allow authenticated users to upload files to their own folder
    match /malware-files/{userId}/{fileName} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Allow authenticated users to read public analysis results
    match /analysis-results/{userId}/{fileName} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Deny all other access
    match /{allPaths=**} {
      allow read, write: if false;
    }
  }
}
```

## Firebase Project Setup

### 1. Initialize Firebase Storage
```bash
firebase init storage
```

### 2. Deploy Storage Rules
```bash
firebase deploy --only storage
```

### 3. Set CORS Configuration (if needed)
```bash
gsutil cors set cors.json gs://aghora-c506a.firebasestorage.app
```

## Testing the Fix

### 1. Restart Development Server
```bash
npm run dev
```

### 2. Test File Upload
- Navigate to the Firebase Debug tab
- Check authentication status
- Test storage upload functionality
- Upload files through the FileUpload component

### 3. Verify in Firebase Console
- Go to [Firebase Console](https://console.firebase.google.com/project/aghora-c506a/storage)
- Check that files are being uploaded correctly
- Verify security rules are working

## Common Issues and Solutions

### Issue: "Bucket does not exist"
**Solution**: Use the correct bucket URL format:
- ❌ `aghora-c506a.appspot.com`
- ✅ `aghora-c506a.firebasestorage.app`

### Issue: "Billing account disabled"
**Solution**: Enable billing in Firebase Console:
1. Go to Firebase Console
2. Navigate to Project Settings
3. Enable billing for Firebase Storage

### Issue: "Access denied"
**Solution**: Check Firebase Storage rules and authentication:
1. Ensure user is authenticated
2. Verify storage rules allow the operation
3. Check that the user ID matches the rule conditions

### Issue: "CORS policy error"
**Solution**: 
1. Update Vite configuration with proper CORS headers
2. Set up Firebase Storage CORS configuration
3. Restart development server

## Development vs Production

### Development (localhost)
- Use `http://localhost:8080` or `http://localhost:5173`
- CORS headers are handled by Vite configuration
- Firebase Storage rules allow authenticated users

### Production
- Deploy to Firebase Hosting
- CORS is handled by Firebase Storage configuration
- Same security rules apply

## Security Considerations

1. **Authentication Required**: All file operations require user authentication
2. **User Isolation**: Users can only access their own files
3. **File Validation**: Implement file type and size validation
4. **Rate Limiting**: Consider implementing upload rate limits

## Monitoring and Debugging

### Firebase Debug Component
The `FirebaseDebug` component provides:
- Authentication status
- Firebase configuration details
- Storage upload testing
- Error logging

### Browser Developer Tools
- Check Network tab for failed requests
- Look for CORS errors in Console
- Verify authentication tokens

### Firebase Console
- Monitor storage usage
- Check security rule violations
- View uploaded files

## Next Steps

1. ✅ Test file upload functionality
2. ✅ Verify CORS is working
3. ✅ Check Firebase Storage rules
4. 🔄 Implement file analysis features
5. 🔄 Add file management interface
6. 🔄 Set up production deployment

## Troubleshooting Commands

```bash
# Check Firebase project
firebase projects:list

# Deploy storage rules
firebase deploy --only storage

# Check storage buckets
gsutil ls

# Set CORS configuration
gsutil cors set cors.json gs://aghora-c506a.firebasestorage.app

# Restart development server
npm run dev
```

The CORS issue should now be resolved, and file uploads should work correctly with Firebase Storage.

