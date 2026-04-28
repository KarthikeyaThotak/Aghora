# Complete Firebase Setup Guide

## Overview
This guide will help you set up Firebase Firestore (database) and Firebase Storage for the Malware Analysis Platform.

## Step 1: Firebase Project Setup

### 1.1 Create/Configure Firebase Project
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project or select existing project `aghora-c506a`
3. Enable the following services:
   - **Authentication** (Email/Password + Google)
   - **Firestore Database**
   - **Storage**

### 1.2 Environment Variables
Create a `.env` file in your project root:

```env
VITE_FIREBASE_API_KEY=your_api_key_here
VITE_FIREBASE_AUTH_DOMAIN=aghora-c506a.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=aghora-c506a
VITE_FIREBASE_STORAGE_BUCKET=aghora-c506a.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

## Step 2: Firestore Database Setup

### 2.1 Create Firestore Database
1. Go to **Firestore Database** in Firebase Console
2. Click **Create database**
3. Choose **Start in test mode** (we'll secure it later)
4. Select a location (choose closest to your users)

### 2.2 Configure Firestore Security Rules
1. Go to **Firestore Database** > **Rules**
2. Replace the default rules with content from `firestore.rules`:

```javascript
rules_version = '2';

service cloud.firestore {
  match /databases/{database}/documents {
    // Allow authenticated users to manage their own uploaded files
    match /uploadedFiles/{document} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
      
      allow create: if request.auth != null && 
        request.auth.uid == request.resource.data.userId &&
        request.resource.data.keys().hasAll(['id', 'name', 'size', 'sha256Hash', 'downloadURL', 'filePath', 'userId', 'uploadTime', 'status']);
    }
    
    // Allow authenticated users to manage their own analysis results
    match /analysisResults/{document} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
      
      allow create: if request.auth != null && 
        request.auth.uid == request.resource.data.userId;
    }
    
    // Allow authenticated users to manage their own graph nodes
    match /graphNodes/{document} {
      allow read, write: if request.auth != null && 
        request.auth.uid == resource.data.userId;
      
      allow create: if request.auth != null && 
        request.auth.uid == request.resource.data.userId;
    }
    
    // Deny all other access
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

3. Click **Publish**

## Step 3: Firebase Storage Setup

### 3.1 Configure Storage Rules
1. Go to **Storage** > **Rules** in Firebase Console
2. Replace the default rules with content from `firebase-storage.rules`:

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

3. Click **Publish**

### 3.2 Configure CORS (if needed)
If you still get CORS errors, configure CORS for your Storage bucket:

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

## Step 4: Authentication Setup

### 4.1 Enable Authentication Providers
1. Go to **Authentication** > **Sign-in method**
2. Enable **Email/Password**
3. Enable **Google** sign-in
4. Configure OAuth consent screen if needed

### 4.2 Add Authorized Domains
1. Go to **Authentication** > **Settings** > **Authorized domains**
2. Add your development domain: `localhost`
3. Add your production domain when ready

## Step 5: Testing

### 5.1 Test the Complete Flow
1. **Start your development server**: `npm run dev`
2. **Sign up/Sign in** with Firebase Authentication
3. **Upload a file** - should work without CORS errors
4. **Check Firestore** - file metadata should be stored
5. **Check Storage** - file should be uploaded
6. **Verify Graph View** - main node should be created

### 5.2 Debug Common Issues
- **CORS Error**: Check Storage rules and CORS configuration
- **Permission Denied**: Check Firestore rules
- **Authentication Error**: Check Auth configuration
- **Environment Variables**: Verify `.env` file

## Step 6: Production Deployment

### 6.1 Update Security Rules
For production, you may want to tighten security rules:

```javascript
// More restrictive rules for production
match /uploadedFiles/{document} {
  allow read, write: if request.auth != null && 
    request.auth.uid == resource.data.userId &&
    request.auth.token.email_verified == true;
}
```

### 6.2 Configure Production Domains
1. Add production domain to authorized domains
2. Update CORS configuration for production
3. Test thoroughly before going live

## Database Structure

### Firestore Collections
- `uploadedFiles` - File metadata and SHA256 hashes
- `analysisResults` - Analysis results and reports
- `graphNodes` - Graph node data for visualization

### Storage Structure
- `malware-files/{userId}/{fileId}-{filename}` - Uploaded files
- `analysis-results/{userId}/{resultId}-{filename}` - Analysis results

## Troubleshooting

### Common Issues and Solutions

1. **"Permission denied" errors**
   - Check Firestore rules
   - Verify user is authenticated
   - Check user ID matches in rules

2. **CORS errors**
   - Configure CORS for Storage bucket
   - Check Storage rules
   - Verify domain is authorized

3. **Authentication issues**
   - Check Firebase config
   - Verify environment variables
   - Check authorized domains

4. **Upload failures**
   - Check file size limits
   - Verify Storage rules
   - Check network connectivity

## Next Steps

1. Set up Firebase project with all services
2. Configure security rules
3. Test file upload flow
4. Deploy to production
5. Monitor usage and performance

Your app now uses Firebase Firestore for metadata storage and Firebase Storage for file uploads, providing a robust, scalable solution for your malware analysis platform!
