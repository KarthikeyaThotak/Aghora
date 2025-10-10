import { useState } from "react";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { ScrollArea } from "./ui/scroll-area";
import { Separator } from "./ui/separator";
import { Download, FileText, Hash, HardDrive, Eye, Zap } from "lucide-react";

export const Report = () => {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);

  // Mock data - in real implementation this would come from props or API
  const reportData = {
    title: "Malware Analysis Report",
    summary: "This report provides a comprehensive analysis of the submitted malware sample. The analysis was conducted using dynamic and static analysis techniques to identify malicious behaviors, network communications, and potential indicators of compromise. The sample exhibits characteristics consistent with advanced persistent threat (APT) malware with data exfiltration capabilities.",
    submittedFiles: [
      {
        name: "suspicious_file.exe",
        hash: "d41d8cd98f00b204e9800998ecf8427e",
        size: "2.4 MB",
        type: "PE32 Executable"
      },
      {
        name: "payload.dll",
        hash: "098f6bcd4621d373cade4e832627b4f6",
        size: "1.2 MB",
        type: "Dynamic Link Library"
      }
    ],
    findings: [
      "Registry modification detected in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Network communication to suspicious IP addresses (185.243.112.45, 192.168.1.100)",
      "File encryption activities targeting user documents",
      "Process injection into explorer.exe and svchost.exe",
      "Creation of persistence mechanisms via scheduled tasks",
      "Anti-analysis techniques including VM detection and debugger evasion"
    ],
    description: "The analyzed malware sample demonstrates sophisticated evasion techniques and multi-stage payload deployment. Initial execution triggers a dropper component that establishes persistence through registry modifications and scheduled tasks. The primary payload exhibits ransomware characteristics, systematically encrypting user files while maintaining command and control communications with remote servers. The malware employs advanced anti-analysis techniques including virtual machine detection, debugger evasion, and code obfuscation to hinder reverse engineering efforts.",
    screenshots: [
      { id: 1, title: "Process Tree Analysis", preview: "/api/placeholder/300/200" },
      { id: 2, title: "Network Communications", preview: "/api/placeholder/300/200" },
      { id: 3, title: "File System Changes", preview: "/api/placeholder/300/200" },
      { id: 4, title: "Registry Modifications", preview: "/api/placeholder/300/200" }
    ],
    tags: ["Ransomware", "APT", "Data Exfiltration", "Process Injection", "Network Activity", "Registry Modification", "Anti-Analysis", "Persistence"]
  };

  const handleDownloadPDF = () => {
    // In a real implementation, this would generate and download a PDF
    console.log("Downloading PDF report...");
    // You could use libraries like jsPDF or html2pdf here
  };

  const sections = [
    { title: "OVERVIEW", description: "Initial malware classification and threat assessment based on static analysis and signature matching." },
    { title: "BEHAVIOR", description: "Dynamic analysis results showing runtime behavior, system interactions, and malicious activities." },
    { title: "INDICATORS", description: "Identified indicators of compromise including file hashes, network artifacts, and system modifications." }
  ];

  return (
    <div className="h-full bg-gradient-subtle">
      {/* Header with Download Button */}
      <div className="flex justify-between items-center p-6 border-b border-border bg-background-secondary/30">
        <div>
          <h1 className="text-2xl font-bold text-foreground">{reportData.title}</h1>
          <p className="text-sm text-muted-foreground">Generated on {new Date().toLocaleDateString()}</p>
        </div>
        <Button onClick={handleDownloadPDF} className="bg-primary hover:bg-primary/90 text-primary-foreground">
          <Download className="w-4 h-4 mr-2" />
          Download PDF
        </Button>
      </div>

      <ScrollArea className="h-[calc(100%-5rem)]">
        <div className="max-w-4xl mx-auto p-6 space-y-8">
          
          {/* Summary Section */}
          <Card className="bg-background-tertiary border-border">
            <CardHeader>
              <CardTitle className="text-sm font-semibold text-foreground uppercase tracking-wide">
                EXECUTIVE SUMMARY
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-foreground leading-relaxed">{reportData.summary}</p>
            </CardContent>
          </Card>

          {/* Mini Head Titles */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {sections.map((section, index) => (
              <Card key={index} className="bg-background-tertiary border-border">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold text-primary uppercase tracking-wide">
                    {section.title}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground leading-relaxed">{section.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Submitted Files */}
          <Card className="bg-background-tertiary border-border">
            <CardHeader>
              <CardTitle className="text-sm font-semibold text-foreground uppercase tracking-wide flex items-center">
                <FileText className="w-4 h-4 mr-2" />
                SUBMITTED FILES
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {reportData.submittedFiles.map((file, index) => (
                  <div key={index} className="bg-background-secondary/50 rounded-lg p-4 border border-border">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground font-medium">Filename:</span>
                        <div className="overflow-x-auto">
                          <p className="text-foreground font-mono whitespace-nowrap">{file.name}</p>
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground font-medium">Hash:</span>
                        <div className="overflow-x-auto">
                          <p className="text-foreground font-mono whitespace-nowrap">{file.hash}</p>
                        </div>
                      </div>
                      <div>
                        <span className="text-muted-foreground font-medium">Size:</span>
                        <p className="text-foreground">{file.size}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground font-medium">Type:</span>
                        <p className="text-foreground">{file.type}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Findings */}
          <Card className="bg-background-tertiary border-border">
            <CardHeader>
              <CardTitle className="text-sm font-semibold text-foreground uppercase tracking-wide flex items-center">
                <Zap className="w-4 h-4 mr-2" />
                KEY FINDINGS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                {reportData.findings.map((finding, index) => (
                  <li key={index} className="flex items-start">
                    <div className="w-2 h-2 bg-primary rounded-full mt-2 mr-3 flex-shrink-0"></div>
                    <p className="text-foreground leading-relaxed">{finding}</p>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Description */}
          <Card className="bg-background-tertiary border-border">
            <CardHeader>
              <CardTitle className="text-sm font-semibold text-foreground uppercase tracking-wide">
                DETAILED DESCRIPTION
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-foreground leading-relaxed">{reportData.description}</p>
            </CardContent>
          </Card>

          {/* Screenshots/Video */}
          <Card className="bg-background-tertiary border-border">
            <CardHeader>
              <CardTitle className="text-sm font-semibold text-foreground uppercase tracking-wide flex items-center">
                <Eye className="w-4 h-4 mr-2" />
                VISUAL EVIDENCE
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {reportData.screenshots.map((screenshot) => (
                  <Card key={screenshot.id} className="bg-background-secondary border-border cursor-pointer hover:bg-background-secondary/80 transition-colors">
                    <CardContent className="p-4">
                      <div className="aspect-video bg-background rounded-lg flex items-center justify-center mb-3 border border-border">
                        <Eye className="w-8 h-8 text-muted-foreground" />
                      </div>
                      <p className="text-sm text-foreground font-medium">{screenshot.title}</p>
                      <p className="text-xs text-muted-foreground mt-1">Click to enlarge</p>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Tags */}
          <Card className="bg-background-tertiary border-border">
            <CardHeader>
              <CardTitle className="text-sm font-semibold text-foreground uppercase tracking-wide flex items-center">
                <Hash className="w-4 h-4 mr-2" />
                CLASSIFICATION TAGS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {reportData.tags.map((tag, index) => (
                  <Badge key={index} variant="secondary" className="bg-primary/20 text-primary hover:bg-primary/30 border-primary/30">
                    {tag}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>

        </div>
      </ScrollArea>
    </div>
  );
};