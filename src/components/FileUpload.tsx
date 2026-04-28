/**
 * FileUpload — drops a file directly to the Python backend.
 *
 * Flow:
 *   1. User drops / selects file
 *   2. SHA-256 computed in-browser
 *   3. Multipart POST to /api/analysis/upload  (fast, no Firebase round-trip)
 *   4. Backend runs analysis, pushes graph via WebSocket
 *   5. onFileUploaded() notifies Workspace → switches to Graph tab
 */

import { useState, useRef, useCallback } from "react";
import {
  Upload, FileWarning, CheckCircle2, AlertCircle,
  X, Loader2, ShieldAlert, Info, Archive, FileCode2,
} from "lucide-react";
import { Progress } from "./ui/progress";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Badge } from "./ui/badge";
import { useToast } from "@/hooks/use-toast";
import { calculateFileSHA256, formatSHA256ForDisplay } from "@/lib/hashUtils";
import { API_BASE_URL } from "@/hooks/useChartAgent";

const MAX_MB = 100;
const MAX_BYTES = MAX_MB * 1024 * 1024;

interface ZipInfo {
  original_zip: string;
  members: string[];
  target_file: string;
  password_used: string | null;
  member_count: number;
}

interface UploadedFile {
  id: string;
  name: string;
  size: number;
  progress: number;
  status: "hashing" | "extracting" | "uploading" | "analyzing" | "completed" | "error";
  sha256Hash?: string;
  errorMsg?: string;
  sessionId?: string;
  threatLevel?: string;
  zipInfo?: ZipInfo;
  analysisStep?: string;  // live step message from backend status.json
}

interface FileUploadProps {
  onFileUploaded?: (file: {
    id: string;
    name: string;
    sha256Hash: string;
    analysisSessionId: string;
  }) => void;
}

const formatSize = (bytes: number) => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

const SUGGESTED_QUESTIONS = [
  "What malware family is this from?",
  "What are the main IOCs?",
  "What persistence mechanisms does it use?",
  "How would I detect this on a network?",
];

export const FileUpload = ({ onFileUploaded }: FileUploadProps) => {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const updateFile = (id: string, patch: Partial<UploadedFile>) =>
    setFiles(prev => prev.map(f => f.id === id ? { ...f, ...patch } : f));

  const isZip = (file: File) =>
    file.name.toLowerCase().endsWith(".zip") || file.type === "application/zip";

  const uploadFile = async (file: File) => {
    const fileId = crypto.randomUUID();
    const sessionId = `session_${Date.now()}`;
    const fileIsZip = isZip(file);

    setFiles(prev => [...prev, {
      id: fileId,
      name: file.name,
      size: file.size,
      progress: 0,
      status: "hashing",
    }]);

    try {
      // ── Step 1: hash ─────────────────────────────────────
      const sha256Hash = await calculateFileSHA256(file);

      // For ZIPs show an "extracting" step to set expectations
      if (fileIsZip) {
        updateFile(fileId, { sha256Hash, status: "extracting", progress: 8 });
      } else {
        updateFile(fileId, { sha256Hash, status: "uploading", progress: 10 });
      }

      // ── Step 2: multipart upload to backend ──────────────
      const formData = new FormData();
      formData.append("file", file);

      // Poll /api/analysis/status for live progress while fetch is pending
      let prog = fileIsZip ? 8 : 10;
      let liveStatusMsg = "";
      const statusPoll = setInterval(async () => {
        try {
          const st = await fetch(`${API_BASE_URL}/api/analysis/status/${encodeURIComponent(sessionId)}`);
          if (st.ok) {
            const data = await st.json();
            if (data.step > 0) {
              // Map server step (1-5) to progress range 20-90
              const serverProg = 20 + Math.round((data.step / data.total) * 70);
              prog = Math.max(prog, serverProg);
              liveStatusMsg = data.message ?? "";
              updateFile(fileId, { progress: prog, status: "analyzing", analysisStep: liveStatusMsg });
            }
          }
        } catch { /* ignore poll errors */ }
      }, 2000);

      // Smooth progress animation (fallback while status.json doesn't exist yet)
      const tick = setInterval(() => {
        prog = Math.min(25, prog + (fileIsZip ? 3 : 4));
        if (prog < 25 && !liveStatusMsg) {
          updateFile(fileId, {
            progress: prog,
            ...(fileIsZip && prog > 15 ? { status: "uploading" } : {}),
          });
        }
      }, 400);

      let analysisResult: any;
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/analysis/upload?sessionId=${encodeURIComponent(sessionId)}&visualize=true`,
          { method: "POST", body: formData },
        );
        clearInterval(tick);
        clearInterval(statusPoll);

        if (!res.ok) {
          let errMsg = res.statusText;
          try { errMsg = (await res.json()).detail ?? errMsg; } catch { /* noop */ }
          throw new Error(errMsg);
        }

        analysisResult = await res.json();
      } catch (err) {
        clearInterval(tick);
        clearInterval(statusPoll);
        throw err;
      }

      updateFile(fileId, { progress: 95, status: "analyzing", analysisStep: "Finalising…" });

      // ── Step 3: surface results ───────────────────────────
      const threat  = analysisResult?.results?.ai_analysis?.threat_level;
      const zipInfo = analysisResult?.results?.zip_info as ZipInfo | undefined;

      updateFile(fileId, {
        progress: 100,
        status: "completed",
        sessionId,
        threatLevel: threat,
        zipInfo,
      });

      const displayName = zipInfo
        ? `${file.name} → ${zipInfo.target_file}`
        : file.name;

      toast({
        title: "Analysis complete",
        description: `${displayName} — Threat level: ${threat?.toUpperCase() ?? "unknown"}`,
      });

      onFileUploaded?.({
        id: fileId,
        name: zipInfo?.target_file ?? file.name,
        sha256Hash,
        analysisSessionId: sessionId,
      });

    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      updateFile(fileId, { status: "error", progress: 0, errorMsg: msg });

      toast({
        title: "Analysis failed",
        description: msg.includes("fetch")
          ? "Cannot reach the backend. Make sure `python server.py` is running."
          : msg,
        variant: "destructive",
      });
    }
  };

  const handleFiles = useCallback((fileList: FileList) => {
    Array.from(fileList).forEach(file => {
      if (file.size > MAX_BYTES) {
        toast({
          title: "File too large",
          description: `${file.name} exceeds the ${MAX_MB} MB limit.`,
          variant: "destructive",
        });
        return;
      }
      uploadFile(file);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files) handleFiles(e.dataTransfer.files);
  }, [handleFiles]);

  const handleDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragOver(true); }, []);
  const handleDragLeave = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragOver(false); }, []);

  const statusLabel: Record<UploadedFile["status"], string> = {
    hashing:   "Computing SHA-256…",
    extracting:"Extracting ZIP archive…",
    uploading: "Uploading to analysis engine…",
    analyzing: "Running static analysis…",
    completed: "Analysis complete",
    error:     "Failed",
  };

  const threatColor: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/40",
    high:     "bg-orange-500/20 text-orange-400 border-orange-500/40",
    medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
    low:      "bg-green-500/20 text-green-400 border-green-500/40",
  };

  return (
    <div className="space-y-6">

      {/* ── Drop zone ─────────────────────────────────────── */}
      <Card
        className={`border-2 border-dashed transition-all duration-200 cursor-pointer select-none ${
          isDragOver
            ? "border-primary bg-primary/5 shadow-lg scale-[1.01]"
            : "border-border hover:border-primary/50 hover:bg-muted/30"
        }`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="p-10 text-center">
          <div className={`w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-5 transition-colors ${isDragOver ? "bg-primary/20" : "bg-muted"}`}>
            {isDragOver
              ? <ShieldAlert className="h-8 w-8 text-primary" />
              : <Upload className="h-8 w-8 text-muted-foreground" />
            }
          </div>
          <h3 className="text-lg font-semibold text-foreground mb-2">
            {isDragOver ? "Drop to analyse" : "Drop a malware sample here"}
          </h3>
          <p className="text-sm text-muted-foreground mb-1">
            PE (.exe, .dll, .sys), scripts, and other binaries · Max {MAX_MB} MB
          </p>
          <p className="text-xs text-primary/70 mb-5 flex items-center justify-center gap-1.5">
            <Archive className="h-3.5 w-3.5" />
            ZIP archives supported — auto-extracts the executable inside
            <span className="opacity-60">(password "infected" tried automatically)</span>
          </p>
          <Button variant="outline" size="sm" onClick={e => { e.stopPropagation(); fileInputRef.current?.click(); }}>
            Browse files
          </Button>
        </div>
      </Card>

      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={e => e.target.files && handleFiles(e.target.files)}
        className="hidden"
        accept="*/*"
      />

      {/* ── What happens next ─────────────────────────────── */}
      {files.length === 0 && (
        <div className="bg-muted/30 border border-border rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-foreground">
            <Info className="h-4 w-4 text-primary" />
            What the platform does
          </div>
          <ul className="text-sm text-muted-foreground space-y-1.5 ml-6 list-disc">
            <li>Accepts executables directly <span className="text-foreground/60">or ZIP archives</span> — password "infected" tried automatically</li>
            <li>Extracts strings, IPs, domains, registry keys (static analysis)</li>
            <li>Computes SHA-256 and identifies file type via Detect-it-Easy</li>
            <li>Generates a live threat graph with IOC relationships</li>
            <li>Uses a local Gemma LLM to assess threat level and answer questions</li>
          </ul>
          <div className="mt-3 pt-3 border-t border-border">
            <p className="text-xs text-muted-foreground font-medium mb-2">Try asking the AI:</p>
            <div className="flex flex-wrap gap-2">
              {SUGGESTED_QUESTIONS.map(q => (
                <span key={q} className="text-xs bg-primary/10 text-primary border border-primary/20 rounded-full px-3 py-1">
                  {q}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── File list ─────────────────────────────────────── */}
      {files.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-foreground">Analysis Queue</h4>

          {files.map(file => (
            <Card key={file.id} className="p-4 space-y-3">
              {/* Header row */}
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                    file.status === "completed"  ? "bg-green-500/10"    :
                    file.status === "error"      ? "bg-destructive/10"  :
                    file.status === "extracting" ? "bg-amber-500/10"    :
                    "bg-primary/10"
                  }`}>
                    {file.status === "completed"  && <CheckCircle2 className="h-4 w-4 text-green-500" />}
                    {file.status === "error"      && <AlertCircle  className="h-4 w-4 text-destructive" />}
                    {file.status === "extracting" && <Archive className="h-4 w-4 text-amber-400 animate-pulse" />}
                    {["hashing","uploading","analyzing"].includes(file.status) && (
                      <Loader2 className="h-4 w-4 text-primary animate-spin" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">{file.name}</p>
                    <p className="text-xs text-muted-foreground">{formatSize(file.size)}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                  {file.threatLevel && (
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${threatColor[file.threatLevel] ?? threatColor.low}`}>
                      {file.threatLevel.toUpperCase()}
                    </span>
                  )}
                  <Button
                    variant="ghost" size="icon"
                    className="h-7 w-7"
                    onClick={() => setFiles(p => p.filter(f => f.id !== file.id))}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>

              {/* Progress */}
              {["hashing","extracting","uploading","analyzing"].includes(file.status) && (
                <div className="space-y-1.5">
                  <Progress value={file.progress} className="h-1.5" />
                  <p className="text-xs text-muted-foreground">
                    {file.analysisStep || statusLabel[file.status]}
                  </p>
                </div>
              )}

              {/* Error */}
              {file.status === "error" && (
                <p className="text-xs text-destructive bg-destructive/5 border border-destructive/20 rounded-lg px-3 py-2">
                  {file.errorMsg ?? "Upload failed — please try again."}
                </p>
              )}

              {/* Success — ZIP extraction summary */}
              {file.status === "completed" && file.zipInfo && (
                <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-2.5 space-y-1">
                  <div className="flex items-center gap-1.5 text-xs font-medium text-amber-400">
                    <Archive className="h-3.5 w-3.5" />
                    Extracted from ZIP · {file.zipInfo.member_count} file{file.zipInfo.member_count !== 1 ? "s" : ""} inside
                    {file.zipInfo.password_used && (
                      <span className="ml-auto text-amber-400/60 font-mono">
                        pw: {file.zipInfo.password_used}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-foreground">
                    <FileCode2 className="h-3 w-3 text-primary flex-shrink-0" />
                    Analysing: <span className="font-mono text-primary ml-1">{file.zipInfo.target_file}</span>
                  </div>
                  {file.zipInfo.members.length > 1 && (
                    <p className="text-xs text-muted-foreground mt-1">
                      Other members: {file.zipInfo.members.filter(m => m !== file.zipInfo!.target_file).slice(0, 4).join(", ")}
                      {file.zipInfo.members.length > 5 ? ` +${file.zipInfo.members.length - 5} more` : ""}
                    </p>
                  )}
                </div>
              )}

              {/* Success — show hash */}
              {file.status === "completed" && file.sha256Hash && (
                <div className="bg-muted/50 rounded-lg p-2.5">
                  <p className="text-xs text-muted-foreground mb-1 font-medium">SHA-256</p>
                  <p className="text-xs font-mono break-all text-foreground">
                    {formatSHA256ForDisplay(file.sha256Hash)}
                  </p>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};
