import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Eye, Download, Trash2, Edit3, Check, X, Loader2, FileText } from "lucide-react";
import { z } from "zod";
import { useFirestore } from "@/hooks/useFirestore";
import { FileMetadata } from "@/lib/firestoreService";
import { useToast } from "@/hooks/use-toast";
import { IndividualReport } from "./IndividualReport";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "./ui/alert-dialog";

interface AnalysisReport {
  id: string;
  date: string;
  caseName: string;
  fileHash: string;
  threatLevel: "Low" | "Medium" | "High" | "Critical";
  status: "Completed" | "Processing" | "Failed";
  detections: number;
  size: string;
  analysisSessionId?: string; // Link to analysis session for graph view
}

interface PreviousAnalysisProps {
  onSelectReport?: (report: AnalysisReport) => void;
}

// Validation schema for case name
const caseNameSchema = z.string()
  .trim()
  .min(1, { message: "Case name cannot be empty" })
  .max(100, { message: "Case name must be less than 100 characters" })
  .regex(/^[a-zA-Z0-9\s\-_\.]+$/, { message: "Case name can only contain letters, numbers, spaces, hyphens, underscores, and periods" });

export const PreviousAnalysis = ({ onSelectReport }: PreviousAnalysisProps) => {
  const [selectedReport, setSelectedReport] = useState<string | null>(null);
  const [editingReport, setEditingReport] = useState<string | null>(null);
  const [editValue, setEditValue] = useState<string>("");
  const [viewingReport, setViewingReport] = useState<AnalysisReport | null>(null);
  
  // Use Firestore hook for real-time data
  const { files, loading, error, updateFile, deleteFile } = useFirestore();
  const { toast } = useToast();

  // Helper function to format file size
  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Helper function to format date
  const formatDate = (timestamp: any) => {
    if (!timestamp) return 'Unknown';
    const date = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);
    return date.toLocaleDateString();
  };

  // Convert FileMetadata to AnalysisReport
  const convertToAnalysisReport = (file: FileMetadata): AnalysisReport => ({
    id: file.id,
    date: formatDate(file.uploadTime),
    caseName: file.name, // Use filename as case name
    fileHash: file.sha256Hash || 'N/A',
    threatLevel: "Low", // Default threat level
    status: file.status === 'processing' ? 'Processing' : 
            file.status === 'analyzed' ? 'Completed' : 'Failed',
    detections: 0, // Default detections
    size: formatFileSize(file.size),
    analysisSessionId: file.analysisSessionId // Include analysis session ID
  });

  // Convert files to reports
  const reports = files.map(convertToAnalysisReport);

  const getThreatLevelVariant = (level: string) => {
    switch (level) {
      case "Critical": return "destructive";
      case "High": return "destructive";
      case "Medium": return "secondary";
      case "Low": return "outline";
      default: return "outline";
    }
  };

  const getStatusVariant = (status: string) => {
    switch (status) {
      case "Completed": return "default";
      case "Processing": return "secondary";
      case "Failed": return "destructive";
      default: return "outline";
    }
  };

  const handleRowClick = (report: AnalysisReport) => {
    setSelectedReport(report.id);
    onSelectReport?.(report);
  };

  const handleViewReport = (report: AnalysisReport, e: React.MouseEvent) => {
    e.stopPropagation();
    onSelectReport?.(report);
  };

  const handleViewIndividualReport = (report: AnalysisReport, e: React.MouseEvent) => {
    e.stopPropagation();
    setViewingReport(report);
  };

  const handleCloseIndividualReport = () => {
    setViewingReport(null);
  };

  const handleEditCaseName = (report: AnalysisReport, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingReport(report.id);
    setEditValue(report.caseName);
  };

  const handleSaveCaseName = async (reportId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    
    const validation = caseNameSchema.safeParse(editValue);
    if (!validation.success) {
      toast({
        title: "Validation Error",
        description: validation.error.issues[0].message,
        variant: "destructive",
      });
      return;
    }
    
    try {
      console.log('Updating case name for file:', reportId, 'to:', validation.data);
      // Update the file name in Firestore
      await updateFile(reportId, { name: validation.data });
      setEditingReport(null);
      setEditValue("");
      toast({
        title: "Case name updated",
        description: `Case name updated to "${validation.data}"`,
      });
    } catch (error) {
      console.error("Error updating case name:", error);
      toast({
        title: "Update failed",
        description: error instanceof Error ? error.message : "Failed to update case name",
        variant: "destructive",
      });
    }
  };

  const handleCancelEdit = (e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingReport(null);
    setEditValue("");
  };

  const handleDeleteFile = async (reportId: string, caseName: string) => {
    try {
      await deleteFile(reportId);
      toast({
        title: "File deleted",
        description: `"${caseName}" has been deleted successfully.`,
      });
    } catch (error) {
      console.error("Error deleting file:", error);
      toast({
        title: "Delete failed",
        description: error instanceof Error ? error.message : "Failed to delete file",
        variant: "destructive",
      });
    }
  };

  // If viewing an individual report, show that instead
  if (viewingReport) {
    return <IndividualReport report={viewingReport} onClose={handleCloseIndividualReport} />;
  }

  return (
    <div className="h-full flex flex-col bg-background p-6">
      <Card className="flex-1 bg-background-secondary border-border">
        <CardHeader className="border-b border-border">
          <CardTitle className="text-foreground uppercase tracking-wide text-sm font-bold">
            Previous Analysis Reports
          </CardTitle>
          <p className="text-muted-foreground text-sm">
            Select a report to view detailed analysis results or click the report icon for individual AI-generated reports
          </p>
        </CardHeader>
        <CardContent className="p-0">
          {loading && (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="h-6 w-6 animate-spin mr-2" />
              <span className="text-muted-foreground">Loading analysis reports...</span>
            </div>
          )}
          
          {error && (
            <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg m-4">
              <p className="text-destructive text-sm">Error loading reports: {error}</p>
            </div>
          )}
          
          {!loading && !error && reports.length === 0 && (
            <div className="flex items-center justify-center p-8">
              <div className="text-center">
                <p className="text-muted-foreground mb-2">No analysis reports found</p>
                <p className="text-sm text-muted-foreground">Upload files to see them appear here</p>
              </div>
            </div>
          )}
          
          {!loading && !error && reports.length > 0 && (
            <div className="overflow-auto max-h-[calc(100vh-200px)]">
              <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-background-tertiary/50">
                  <TableHead className="text-muted-foreground font-semibold">Date</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Case Name</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Hash (SHA256)</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Size</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Threat Level</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Status</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Detections</TableHead>
                  <TableHead className="text-muted-foreground font-semibold">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((report) => (
                  <TableRow
                    key={report.id}
                    className={`
                      border-border transition-colors
                      hover:bg-background-tertiary/50
                      ${selectedReport === report.id ? 'bg-primary/10 border-primary/20' : ''}
                    `}
                  >
                    <TableCell 
                      className="text-foreground font-mono text-sm cursor-pointer hover:text-primary transition-colors"
                      onClick={() => handleRowClick(report)}
                    >
                      {report.date}
                    </TableCell>
                     <TableCell 
                       className="text-foreground cursor-pointer hover:text-primary transition-colors"
                       onClick={() => handleRowClick(report)}
                     >
                       <div className="overflow-x-auto max-w-[200px]">
                         {editingReport === report.id ? (
                           <Input
                             value={editValue}
                             onChange={(e) => setEditValue(e.target.value)}
                             className="h-8 text-sm bg-background border-primary/50 focus:border-primary"
                             onClick={(e) => e.stopPropagation()}
                             onKeyDown={(e) => {
                               if (e.key === 'Enter') {
                                 handleSaveCaseName(report.id, e as any);
                               } else if (e.key === 'Escape') {
                                 handleCancelEdit(e as any);
                               }
                             }}
                             autoFocus
                           />
                         ) : (
                           <span className="whitespace-nowrap cursor-pointer hover:text-primary transition-colors" onClick={(e) => handleEditCaseName(report, e)}>
                             {report.caseName}
                           </span>
                         )}
                       </div>
                     </TableCell>
                    <TableCell 
                      className="text-muted-foreground font-mono text-xs cursor-pointer hover:text-primary transition-colors"
                      onClick={() => handleRowClick(report)}
                    >
                      <div className="overflow-x-auto max-w-[150px]">
                        <span className="whitespace-nowrap">{report.fileHash}</span>
                      </div>
                    </TableCell>
                    <TableCell 
                      className="text-foreground cursor-pointer hover:text-primary transition-colors"
                      onClick={() => handleRowClick(report)}
                    >
                      <div className="flex items-center gap-2">
                        <span>{report.size}</span>
                        {report.analysisSessionId && (
                          <Badge variant="outline" className="text-xs">
                            Graph Available
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell 
                      className="cursor-pointer hover:text-primary transition-colors"
                      onClick={() => handleRowClick(report)}
                    >
                      <Badge variant={getThreatLevelVariant(report.threatLevel) as any}>
                        {report.threatLevel}
                      </Badge>
                    </TableCell>
                    <TableCell 
                      className="cursor-pointer hover:text-primary transition-colors"
                      onClick={() => handleRowClick(report)}
                    >
                      <Badge variant={getStatusVariant(report.status) as any}>
                        {report.status}
                      </Badge>
                    </TableCell>
                    <TableCell 
                      className="text-foreground font-semibold cursor-pointer hover:text-primary transition-colors"
                      onClick={() => handleRowClick(report)}
                    >
                      {report.detections}
                    </TableCell>
                     <TableCell className="text-center">
                       <div className="flex gap-1 justify-center">
                         {editingReport === report.id ? (
                           <>
                             <Button
                               size="sm"
                               variant="ghost"
                               onClick={(e) => handleSaveCaseName(report.id, e)}
                               className="h-8 w-8 p-0 hover:bg-green-500/20 text-green-600"
                             >
                               <Check className="h-4 w-4" />
                             </Button>
                             <Button
                               size="sm"
                               variant="ghost"
                               onClick={handleCancelEdit}
                               className="h-8 w-8 p-0 hover:bg-destructive/20 text-destructive"
                             >
                               <X className="h-4 w-4" />
                             </Button>
                           </>
                         ) : (
                           <>
                             <Button
                               size="sm"
                               variant="ghost"
                               onClick={(e) => handleEditCaseName(report, e)}
                               className="h-8 w-8 p-0 hover:bg-primary/20"
                             >
                               <Edit3 className="h-4 w-4" />
                             </Button>
                             <Button
                               size="sm"
                               variant="ghost"
                               onClick={(e) => handleViewReport(report, e)}
                               className="h-8 w-8 p-0 hover:bg-primary/20"
                               title={report.analysisSessionId ? "View Graph Analysis" : "View Report"}
                             >
                               <Eye className="h-4 w-4" />
                             </Button>
                             <Button
                               size="sm"
                               variant="ghost"
                               onClick={(e) => handleViewIndividualReport(report, e)}
                               className="h-8 w-8 p-0 hover:bg-primary/20"
                               title="View Individual Report"
                             >
                               <FileText className="h-4 w-4" />
                             </Button>
                             <Button
                               size="sm"
                               variant="ghost"
                               onClick={(e) => e.stopPropagation()}
                               className="h-8 w-8 p-0 hover:bg-primary/20"
                             >
                               <Download className="h-4 w-4" />
                             </Button>
                             <AlertDialog>
                               <AlertDialogTrigger asChild>
                                 <Button
                                   size="sm"
                                   variant="ghost"
                                   onClick={(e) => e.stopPropagation()}
                                   className="h-8 w-8 p-0 hover:bg-destructive/20 text-destructive"
                                 >
                                   <Trash2 className="h-4 w-4" />
                                 </Button>
                               </AlertDialogTrigger>
                               <AlertDialogContent>
                                 <AlertDialogHeader>
                                   <AlertDialogTitle>Delete Analysis Report</AlertDialogTitle>
                                   <AlertDialogDescription>
                                     Are you sure you want to delete "{report.caseName}"? This action cannot be undone and will permanently remove the file and its analysis data.
                                   </AlertDialogDescription>
                                 </AlertDialogHeader>
                                 <AlertDialogFooter>
                                   <AlertDialogCancel>Cancel</AlertDialogCancel>
                                   <AlertDialogAction
                                     onClick={() => handleDeleteFile(report.id, report.caseName)}
                                     className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                   >
                                     Delete
                                   </AlertDialogAction>
                                 </AlertDialogFooter>
                               </AlertDialogContent>
                             </AlertDialog>
                           </>
                         )}
                       </div>
                     </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};