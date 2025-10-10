rules_version = '2';

service firebase.storage {
  match /b/{bucket}/o {
    // Allow authenticated users to upload files to their own folder
    match /malware-files/{userId}/{fileName} {
      // Users can only access their own files
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

### 3. Configure CORS (if needed)
If CORS issues persist, you may need to configure CORS for your Firebase Storage bucket:

1. Install Google Cloud SDK
2. Create a `cors.json` file:
```json
[
  {
    "origin": ["http://localhost:8080", "https://yourdomain.com"],
    "method": ["GET", "POST", "PUT", "DELETE"],
    "maxAgeSeconds": 3600
  }
]
```

3. Apply CORS configuration:
```bash
gsutil cors set cors.json gs://aghora-c506a.firebasestorage.app
```

### 4. Environment Variables
Create a `.env` file in your project root:

```env
VITE_FIREBASE_API_KEY=your_api_key_here
VITE_FIREBASE_AUTH_DOMAIN=aghora-c506a.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=aghora-c506a
VITE_FIREBASE_STORAGE_BUCKET=aghora-c506a.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

## Current Fallback Solution

The app now includes a fallback mechanism:
- If Firebase Storage fails, files are stored locally
- SHA256 hash calculation still works
- Main node creation still functions
- File metadata is stored in localStorage

## Testing

1. Upload a file - it should work with the fallback
2. Check browser console for any Firebase Storage errors
3. Verify SHA256 hash is calculated correctly
4. Confirm main node is created in Graph View

## Production Deployment

For production deployment:
1. Set up proper Firebase Storage rules
2. Configure CORS for your production domain
3. Remove the fallback mechanism
4. Test with real Firebase Storage

## Troubleshooting

### Common Issues:
1. **CORS Error**: Configure CORS for your domain
2. **Authentication Error**: Ensure user is logged in
3. **Storage Rules Error**: Update Firebase Storage rules
4. **Environment Variables**: Check `.env` file exists and is correct

### Debug Steps:
1. Check browser console for specific error messages
2. Verify Firebase project configuration
3. Test authentication flow
4. Check Firebase Storage rules in console
