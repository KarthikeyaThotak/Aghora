/**
 * PreviousAnalysis — fetches session history from the local Python backend
 * (SQLite database) instead of Firebase/Firestore.
 */

import { useState, useEffect, useCallback } from "react";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "./ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import {
  Eye, Trash2, Edit3, Check, X, Loader2, RefreshCcw, Database,
} from "lucide-react";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from "./ui/alert-dialog";
import { useToast } from "@/hooks/use-toast";
import { API_BASE_URL } from "@/hooks/useChartAgent";

// ── Types ────────────────────────────────────────────────────────────────────

interface Session {
  id: string;
  file_name: string;
  file_size: number;
  sha256_hash: string;
  threat_level: string;
  threat_summary: string;
  key_findings: string[];
  iocs: Record<string, string[]>;
  behavioral: string;
  recommendations: string[];
  status: string;
  created_at: string;
  log_directory: string;
}

interface PreviousAnalysisProps {
  onSelectReport?: (report: {
    caseName?: string;
    fileHash?: string;
    analysisSessionId?: string;
  }) => void;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const formatSize = (bytes: number) => {
  if (!bytes) return "—";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

const formatDate = (iso: string) => {
  if (!iso) return "—";
  return new Date(iso).toLocaleString([], {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
};

const threatVariant = (level: string) => {
  switch (level?.toLowerCase()) {
    case "critical": return "destructive";
    case "high":     return "destructive";
    case "medium":   return "secondary";
    default:         return "outline";
  }
};

const threatColor = (level: string) => {
  switch (level?.toLowerCase()) {
    case "critical": return "text-red-500";
    case "high":     return "text-orange-500";
    case "medium":   return "text-yellow-500";
    case "low":      return "text-green-500";
    default:         return "text-muted-foreground";
  }
};

// ── Component ─────────────────────────────────────────────────────────────────

export const PreviousAnalysis = ({ onSelectReport }: PreviousAnalysisProps) => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing]   = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const { toast } = useToast();

  // ── Fetch sessions from backend ──────────────────────────────────────────

  const loadSessions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/sessions`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSessions(data.sessions ?? []);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load";
      setError(msg.includes("fetch")
        ? "Cannot reach backend — make sure `python server.py` is running."
        : msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadSessions(); }, [loadSessions]);

  // ── Actions ──────────────────────────────────────────────────────────────

  const handleSelect = (s: Session) => {
    setSelected(s.id);
    onSelectReport?.({ caseName: s.file_name, fileHash: s.sha256_hash, analysisSessionId: s.id });
  };

  const handleRename = async (id: string) => {
    const name = editValue.trim();
    if (!name) return;
    try {
      const res = await fetch(`${API_BASE_URL}/api/sessions/${id}/rename`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setSessions(prev => prev.map(s => s.id === id ? { ...s, file_name: name } : s));
      toast({ title: "Renamed", description: `Session renamed to "${name}"` });
    } catch (err) {
      toast({ title: "Rename failed", description: String(err), variant: "destructive" });
    } finally {
      setEditing(null);
      setEditValue("");
    }
  };

  const handleDelete = async (id: string, name: string) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/sessions/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setSessions(prev => prev.filter(s => s.id !== id));
      if (selected === id) setSelected(null);
      toast({ title: "Deleted", description: `"${name}" removed.` });
    } catch (err) {
      toast({ title: "Delete failed", description: String(err), variant: "destructive" });
    }
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="h-full flex flex-col">
      <Card className="flex-1 bg-background-secondary border-border overflow-hidden flex flex-col">
        <CardHeader className="border-b border-border flex-row items-center justify-between py-3 px-5 flex-shrink-0">
          <div>
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Database className="h-4 w-4 text-primary" />
              Analysis History
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Stored locally in SQLite · {sessions.length} session{sessions.length !== 1 ? "s" : ""}
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={loadSessions} disabled={loading} className="gap-1.5 h-8">
            <RefreshCcw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </CardHeader>

        <CardContent className="p-0 flex-1 overflow-auto">
          {/* Loading */}
          {loading && (
            <div className="flex items-center justify-center p-10 gap-2 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              Loading sessions…
            </div>
          )}

          {/* Error */}
          {!loading && error && (
            <div className="m-4 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
              {error}
            </div>
          )}

          {/* Empty */}
          {!loading && !error && sessions.length === 0 && (
            <div className="flex flex-col items-center justify-center p-12 text-center gap-2">
              <Database className="h-10 w-10 text-muted-foreground/30" />
              <p className="text-muted-foreground text-sm">No sessions yet</p>
              <p className="text-xs text-muted-foreground">Upload a malware sample to get started.</p>
            </div>
          )}

          {/* Table */}
          {!loading && !error && sessions.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="text-xs font-semibold text-muted-foreground w-36">Date</TableHead>
                  <TableHead className="text-xs font-semibold text-muted-foreground">File name</TableHead>
                  <TableHead className="text-xs font-semibold text-muted-foreground hidden md:table-cell">SHA-256</TableHead>
                  <TableHead className="text-xs font-semibold text-muted-foreground hidden sm:table-cell">Size</TableHead>
                  <TableHead className="text-xs font-semibold text-muted-foreground">Threat</TableHead>
                  <TableHead className="text-xs font-semibold text-muted-foreground text-center">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map(s => (
                  <TableRow
                    key={s.id}
                    className={`border-border cursor-pointer transition-colors hover:bg-muted/40 ${selected === s.id ? "bg-primary/5" : ""}`}
                    onClick={() => handleSelect(s)}
                  >
                    {/* Date */}
                    <TableCell className="text-xs text-muted-foreground font-mono whitespace-nowrap">
                      {formatDate(s.created_at)}
                    </TableCell>

                    {/* File name / editable */}
                    <TableCell className="max-w-[180px]" onClick={e => e.stopPropagation()}>
                      {editing === s.id ? (
                        <div className="flex items-center gap-1">
                          <Input
                            value={editValue}
                            onChange={e => setEditValue(e.target.value)}
                            onKeyDown={e => {
                              if (e.key === "Enter") handleRename(s.id);
                              if (e.key === "Escape") { setEditing(null); setEditValue(""); }
                            }}
                            className="h-7 text-xs"
                            autoFocus
                          />
                          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => handleRename(s.id)}>
                            <Check className="h-3.5 w-3.5 text-green-500" />
                          </Button>
                          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => { setEditing(null); setEditValue(""); }}>
                            <X className="h-3.5 w-3.5 text-destructive" />
                          </Button>
                        </div>
                      ) : (
                        <span
                          className="text-sm font-medium truncate block hover:text-primary transition-colors"
                          title={s.file_name}
                          onClick={() => handleSelect(s)}
                        >
                          {s.file_name}
                        </span>
                      )}
                    </TableCell>

                    {/* SHA-256 */}
                    <TableCell className="hidden md:table-cell">
                      <span className="text-xs font-mono text-muted-foreground">
                        {s.sha256_hash ? `${s.sha256_hash.slice(0, 16)}…` : "—"}
                      </span>
                    </TableCell>

                    {/* Size */}
                    <TableCell className="hidden sm:table-cell text-xs text-muted-foreground">
                      {formatSize(s.file_size)}
                    </TableCell>

                    {/* Threat level */}
                    <TableCell>
                      <span className={`text-xs font-semibold uppercase ${threatColor(s.threat_level)}`}>
                        {s.threat_level ?? "—"}
                      </span>
                    </TableCell>

                    {/* Actions */}
                    <TableCell className="text-center" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-center gap-1">
                        <Button
                          size="icon" variant="ghost" className="h-7 w-7"
                          title="View graph"
                          onClick={() => handleSelect(s)}
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon" variant="ghost" className="h-7 w-7"
                          title="Rename"
                          onClick={() => { setEditing(s.id); setEditValue(s.file_name); }}
                        >
                          <Edit3 className="h-3.5 w-3.5" />
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button size="icon" variant="ghost" className="h-7 w-7 text-destructive hover:text-destructive" title="Delete">
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Delete session?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This will permanently remove <strong>{s.file_name}</strong> from the local database. The analysis log files on disk are not affected.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                onClick={() => handleDelete(s.id, s.file_name)}
                              >
                                Delete
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
