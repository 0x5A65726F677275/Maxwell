import { invoke } from "@tauri-apps/api/core";
import type {
  BinaryInfo,
  CaptureRecord,
  Finding,
  OperatorSnapshot,
  ProxyStatus,
} from "./types";

export const api = {
  getStatus: () => invoke<ProxyStatus>("get_status"),
  startProxy: (listen: string, mitm: boolean) =>
    invoke("start_proxy", { listen, mitm }),
  stopProxy: () => invoke("stop_proxy"),
  listCaptures: () => invoke<CaptureRecord[]>("list_captures"),
  replayCapture: (id: string) =>
    invoke<CaptureRecord>("replay_capture", { id }),
  analyzeBinary: (path: string) =>
    invoke<BinaryInfo>("analyze_binary", { path }),
  operatorSnapshot: () => invoke<OperatorSnapshot>("operator_snapshot"),
  decideFinding: (findingId: string, approved: boolean, note: string) =>
    invoke<Finding>("decide_finding", { findingId, approved, note }),
  addFinding: (target: string, rationale: string) =>
    invoke<Finding>("add_finding", { target, rationale }),
};

export function bodyPreview(bytes: number[] | undefined, max = 400): string {
  if (!bytes || bytes.length === 0) return "";
  try {
    return new TextDecoder().decode(Uint8Array.from(bytes.slice(0, max)));
  } catch {
    return bytes
      .slice(0, 64)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }
}
