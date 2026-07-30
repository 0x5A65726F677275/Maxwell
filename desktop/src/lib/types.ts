export type Tab = "proxy" | "binary" | "operator" | "findings";

export type ProxyStatus = {
  platform: string;
  version: string;
  running: boolean;
  sessionId: string | null;
  listen: string | null;
  caPath: string | null;
  mitm: boolean;
  captureCount: number;
  pendingFindings: number;
};

export type CaptureRecord = {
  id: string;
  createdAt: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: number[];
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body: number[];
  } | null;
  anomalySignal: string | null;
};

export type Instruction = { address: number; bytes: string; text: string };

export type FunctionInfo = {
  name: string | null;
  address: number;
  size: number | null;
  disasm: Instruction[];
};

export type BinaryInfo = {
  path: string;
  format: string;
  entryPoint: number | null;
  architecture: string | null;
  functions: FunctionInfo[];
};

export type Finding = {
  id: string;
  createdAt: string;
  target: string;
  rationale: string;
  status: "pending" | "approved" | "rejected";
  note: string | null;
};

export type OperatorSnapshot = {
  sessionId: string | null;
  running: boolean;
  listen: string | null;
  caPath: string | null;
  mitm: boolean;
  participants: { name: string; role: string }[];
  findings: Finding[];
};

export type ProxyEvent = {
  id: string;
  source: string;
  severity: string;
  kind: { kind: string; signal?: string; request?: { url: string } };
};
