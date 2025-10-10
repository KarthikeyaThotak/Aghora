import { GraphNode, GraphConnection } from "@/types/graph";

export const mockNodes: GraphNode[] = [
  {
    id: "1",
    type: "file",
    label: "malware.exe",
    x: 200,
    y: 150,
    connections: ["2", "3"],
    details: {
      description: "Suspicious executable file detected",
      riskLevel: "critical",
      metadata: {
        "File Size": "2.3 MB",
        "Hash (SHA256)": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "First Seen": "2024-01-15 14:30:22"
      }
    }
  },
  {
    id: "2",
    type: "network",
    label: "TCP 443",
    x: 400,
    y: 100,
    connections: ["4"],
    details: {
      description: "Outbound HTTPS connection",
      riskLevel: "high",
      metadata: {
        "Destination": "185.123.45.67",
        "Port": "443",
        "Protocol": "HTTPS"
      }
    }
  },
  {
    id: "3",
    type: "registry",
    label: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    x: 300,
    y: 300,
    connections: [],
    details: {
      description: "Registry modification for persistence",
      riskLevel: "high",
      metadata: {
        "Action": "Write",
        "Value": "malware.exe",
        "Type": "REG_SZ"
      }
    }
  },
  {
    id: "4",
    type: "threat",
    label: "C&C Server",
    x: 600,
    y: 150,
    connections: [],
    details: {
      description: "Command and control server communication",
      riskLevel: "critical",
      metadata: {
        "IP": "185.123.45.67",
        "Geolocation": "Russia",
        "Known Threat": "APT29"
      }
    }
  }
];

export const mockConnections: GraphConnection[] = [
  {
    id: "conn-1-2",
    sourceId: "1",
    targetId: "2",
    type: "direct"
  },
  {
    id: "conn-1-3",
    sourceId: "1",
    targetId: "3",
    type: "direct"
  },
  {
    id: "conn-2-4",
    sourceId: "2",
    targetId: "4",
    type: "direct"
  }
];
