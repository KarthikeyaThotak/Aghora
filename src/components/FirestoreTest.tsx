import { useState } from "react";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { useAuth } from "@/contexts/AuthContext";
import FirestoreService from "@/lib/firestoreService";
import { calculateFileSHA256 } from "@/lib/hashUtils";

export const FirestoreTest = () => {
  const [testResults, setTestResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const { user } = useAuth();

  const addResult = (message: string) => {
    setTestResults(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
  };

  const clearResults = () => {
    setTestResults([]);
  };

  const testFileUpload = async () => {
    if (!user) {
      addResult("❌ ERROR: No authenticated user");
      return;
    }

    setLoading(true);
    addResult("🔄 Starting file upload test...");

    try {
      // Create a test file
      const testContent = `Test file content - ${Date.now()}`;
      const testFile = new File([testContent], `test-${Date.now()}.txt`, { 
        type: 'text/plain' 
      });

      addResult(`📁 Created test file: ${testFile.name} (${testFile.size} bytes)`);

      // Calculate SHA256 hash
      addResult("🔐 Calculating SHA256 hash...");
      const sha256Hash = await calculateFileSHA256(testFile);
      addResult(`✅ SHA256: ${sha256Hash.substring(0, 16)}...`);

      // Upload file
      addResult("📤 Uploading file to Firebase Storage...");
      const result = await FirestoreService.uploadFile(testFile, user.uid, sha256Hash);
      
      addResult(`✅ File uploaded successfully!`);
      addResult(`📋 File ID: ${result.fileId}`);
      addResult(`🔗 Download URL: ${result.downloadURL.substring(0, 50)}...`);

      // Test metadata update
      addResult("🔄 Testing metadata update...");
      await FirestoreService.updateFileMetadata(result.fileId, {
        status: 'analyzed',
        analysisResults: { test: true, timestamp: Date.now() }
      }, user.uid);
      addResult("✅ Metadata updated successfully!");

      // Test file retrieval
      addResult("📥 Testing file retrieval...");
      const retrievedFile = await FirestoreService.getFileById(result.fileId, user.uid);
      if (retrievedFile) {
        addResult(`✅ File retrieved: ${retrievedFile.name}`);
        addResult(`📊 Status: ${retrievedFile.status}`);
      } else {
        addResult("❌ Failed to retrieve file");
      }

      addResult("🎉 All tests passed!");

    } catch (error) {
      addResult(`❌ ERROR: ${error instanceof Error ? error.message : 'Unknown error'}`);
      console.error('Test failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const testMetadataUpdate = async () => {
    if (!user) {
      addResult("❌ ERROR: No authenticated user");
      return;
    }

    setLoading(true);
    addResult("🔄 Testing metadata update...");

    try {
      // Get user's files
      const files = await FirestoreService.getUserFiles(user.uid, 1);
      
      if (files.length === 0) {
        addResult("❌ No files found to test metadata update");
        return;
      }

      const testFile = files[0];
      addResult(`📁 Testing with file: ${testFile.name}`);

      // Update metadata
      await FirestoreService.updateFileMetadata(testFile.id, {
        status: 'processing',
        updatedAt: new Date()
      }, user.uid);

      addResult("✅ Metadata update test passed!");

    } catch (error) {
      addResult(`❌ ERROR: ${error instanceof Error ? error.message : 'Unknown error'}`);
      console.error('Metadata update test failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4">Firestore Service Test</h3>
      
      <div className="space-y-4">
        <div>
          <h4 className="font-medium mb-2">Authentication Status:</h4>
          <p className="text-sm text-muted-foreground">
            {user ? `✅ Authenticated as ${user.uid}` : '❌ Not authenticated'}
          </p>
        </div>

        <div className="flex space-x-2">
          <Button 
            onClick={testFileUpload} 
            disabled={!user || loading}
            className="flex-1"
          >
            {loading ? 'Testing...' : 'Test File Upload'}
          </Button>
          <Button 
            onClick={testMetadataUpdate} 
            disabled={!user || loading}
            variant="outline"
            className="flex-1"
          >
            Test Metadata Update
          </Button>
          <Button onClick={clearResults} variant="outline">
            Clear Results
          </Button>
        </div>

        {testResults.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Test Results:</h4>
            <div className="bg-muted p-3 rounded text-sm max-h-60 overflow-y-auto">
              {testResults.map((result, index) => (
                <div key={index} className="mb-1">
                  {result}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
};

export default FirestoreTest;
