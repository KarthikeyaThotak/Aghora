import { useState, useEffect } from "react";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { useAuth } from "@/contexts/AuthContext";
import { auth, storage } from "@/config/firebase";
import { ref, uploadBytes, getDownloadURL } from "firebase/storage";
import { onAuthStateChanged } from "firebase/auth";

export const FirebaseDebug = () => {
  const [authState, setAuthState] = useState<any>(null);
  const [debugInfo, setDebugInfo] = useState<string[]>([]);
  const { user } = useAuth();

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setAuthState(user);
      setDebugInfo(prev => [...prev, `Auth state changed: ${user ? 'authenticated' : 'not authenticated'}`]);
    });

    return () => unsubscribe();
  }, []);

  const testStorageUpload = async () => {
    try {
      setDebugInfo(prev => [...prev, 'Testing storage upload...']);
      
      if (!user) {
        setDebugInfo(prev => [...prev, 'ERROR: No authenticated user']);
        return;
      }

      // Create a test file
      const testContent = 'This is a test file for debugging Firebase Storage';
      const testFile = new File([testContent], 'test.txt', { type: 'text/plain' });
      
      const filePath = `malware-files/${user.uid}/test-${Date.now()}.txt`;
      const storageRef = ref(storage, filePath);
      
      setDebugInfo(prev => [...prev, `Uploading to path: ${filePath}`]);
      setDebugInfo(prev => [...prev, `User ID: ${user.uid}`]);
      setDebugInfo(prev => [...prev, `Storage bucket: ${storage.app.options.storageBucket}`]);
      
      const snapshot = await uploadBytes(storageRef, testFile);
      const downloadURL = await getDownloadURL(snapshot.ref);
      
      setDebugInfo(prev => [...prev, `SUCCESS: File uploaded successfully`]);
      setDebugInfo(prev => [...prev, `Download URL: ${downloadURL}`]);
      
    } catch (error) {
      setDebugInfo(prev => [...prev, `ERROR: ${error instanceof Error ? error.message : 'Unknown error'}`]);
      console.error('Storage upload test failed:', error);
    }
  };

  const clearDebugInfo = () => {
    setDebugInfo([]);
  };

  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4">Firebase Debug Information</h3>
      
      <div className="space-y-4">
        <div>
          <h4 className="font-medium mb-2">Authentication Status:</h4>
          <p className="text-sm text-muted-foreground">
            Context User: {user ? `Authenticated (${user.uid})` : 'Not authenticated'}
          </p>
          <p className="text-sm text-muted-foreground">
            Auth State: {authState ? `Authenticated (${authState.uid})` : 'Not authenticated'}
          </p>
          <p className="text-sm text-muted-foreground">
            Auth Token: {authState?.accessToken ? 'Available' : 'Not available'}
          </p>
        </div>

        <div>
          <h4 className="font-medium mb-2">Firebase Configuration:</h4>
          <p className="text-sm text-muted-foreground">
            Project ID: {import.meta.env.VITE_FIREBASE_PROJECT_ID}
          </p>
          <p className="text-sm text-muted-foreground">
            Storage Bucket: {import.meta.env.VITE_FIREBASE_STORAGE_BUCKET}
          </p>
          <p className="text-sm text-muted-foreground">
            Auth Domain: {import.meta.env.VITE_FIREBASE_AUTH_DOMAIN}
          </p>
        </div>

        <div className="flex space-x-2">
          <Button onClick={testStorageUpload} disabled={!user}>
            Test Storage Upload
          </Button>
          <Button onClick={clearDebugInfo} variant="outline">
            Clear Debug Info
          </Button>
        </div>

        {debugInfo.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Debug Log:</h4>
            <div className="bg-muted p-3 rounded text-sm max-h-60 overflow-y-auto">
              {debugInfo.map((info, index) => (
                <div key={index} className="mb-1">
                  {info}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
};

export default FirebaseDebug;

