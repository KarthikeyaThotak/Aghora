import { useState, useEffect } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { GraphView } from "./GraphView";
import { VideoPlayer } from "./VideoPlayer";
import { UserProfile } from "./UserProfile";
import { FileUpload } from "./FileUpload";
import { Report } from "./Report";
import { PreviousAnalysis } from "./PreviousAnalysis";
import { FirebaseDebug } from "./FirebaseDebug";
import { FirestoreTest } from "./FirestoreTest";
import { ConnectionStatus } from "./ConnectionStatus";
import FirestoreService, { AnalysisSession } from "@/lib/firestoreService";
import { useAuth } from "@/contexts/AuthContext";

export const Workspace = () => {
  const [activeTab, setActiveTab] = useState("upload");
  const [currentAnalysisSessionId, setCurrentAnalysisSessionId] = useState<string | null>(null);
  const [analysisSessions, setAnalysisSessions] = useState<AnalysisSession[]>([]);
  const { user } = useAuth();

  const handleSelectReport = (report: any) => {
    console.log("Selected report:", report);
    
    // Switch to graph view and load the analysis session if available
    if (report.analysisSessionId) {
      setCurrentAnalysisSessionId(report.analysisSessionId);
      setActiveTab("graph");
      console.log("Switching to graph view with session ID:", report.analysisSessionId);
    } else {
      // If no analysis session ID, switch to report view
      setActiveTab("report");
      console.log("No analysis session ID found, switching to report view");
    }
  };

  const handleFileUploaded = (file: { 
    id: string; 
    name: string; 
    sha256Hash: string;
    analysisSessionId: string;
  }) => {
    // Set the new analysis session as current and switch to graph view
    setCurrentAnalysisSessionId(file.analysisSessionId);
    setActiveTab("graph");
    
    // Refresh analysis sessions list
    loadAnalysisSessions();
  };

  const loadAnalysisSessions = async () => {
    if (!user) return;
    
    try {
      const sessions = await FirestoreService.getUserAnalysisSessions(user.uid);
      setAnalysisSessions(sessions);
    } catch (error) {
      console.error('Error loading analysis sessions:', error);
    }
  };

  // Load analysis sessions on mount
  useEffect(() => {
    loadAnalysisSessions();
  }, [user]);

  return (
    <div className="h-screen flex flex-col bg-gradient-subtle">
      {/* Connection Status */}
      <ConnectionStatus />
      
      {/* Header */}
      <header className="h-16 border-b border-border bg-background-secondary/50 backdrop-blur-sm flex items-center justify-between px-6">
        <div className="flex items-center gap-4">
          <img 
            src="/logo.png" 
            alt="Malware Analysis Platform" 
            className="w-8 h-8 object-contain"
          />
          <div>
            <h1 className="text-xl font-semibold text-foreground">Malware Analysis Platform</h1>
            <p className="text-sm text-muted-foreground">Advanced threat intelligence and visualization</p>
          </div>
        </div>
        <UserProfile />
      </header>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col">
        <div className="border-b border-border bg-background-secondary/30">
          <TabsList className="h-12 p-1 m-4 bg-background-tertiary">
            <TabsTrigger value="upload" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Upload Files
            </TabsTrigger>
            <TabsTrigger value="graph" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Graph View
            </TabsTrigger>
            <TabsTrigger value="video" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Execution Video
            </TabsTrigger>
            <TabsTrigger value="report" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Report
            </TabsTrigger>
            <TabsTrigger value="previous" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Previous Analysis
            </TabsTrigger>
            <TabsTrigger value="debug" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Firebase Debug
            </TabsTrigger>
            <TabsTrigger value="firestore-test" className="flex-1 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              Firestore Test
            </TabsTrigger>
          </TabsList>
        </div>

        <div className="flex-1">
          <TabsContent value="upload" className="h-full m-0 p-6">
            <FileUpload onFileUploaded={handleFileUploaded} />
          </TabsContent>
          <TabsContent value="graph" className="h-full m-0">
            <GraphView analysisSessionId={currentAnalysisSessionId} />
          </TabsContent>
          <TabsContent value="video" className="h-full m-0">
            <VideoPlayer />
          </TabsContent>
          <TabsContent value="report" className="h-full m-0">
            <Report />
          </TabsContent>
          <TabsContent value="previous" className="h-full m-0">
            <PreviousAnalysis onSelectReport={handleSelectReport} />
          </TabsContent>
          <TabsContent value="debug" className="h-full m-0 p-6">
            <FirebaseDebug />
          </TabsContent>
          <TabsContent value="firestore-test" className="h-full m-0 p-6">
            <FirestoreTest />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
};