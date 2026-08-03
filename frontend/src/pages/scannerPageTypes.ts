import type { Severity } from "../types";

export type ThemeMode = "light" | "dark";
export type InputTab = "url" | "body";
export type ConnectionStatus =
  | "disconnected"
  | "connecting"
  | "connected"
  | "invalid-token"
  | "unreachable";
export type HistoryStatus = "idle" | "loading" | "ready" | "error";
export type ScanStatus = "idle" | "running" | "completed" | "cancelled" | "error";
export type SeverityFilter = "all" | Severity;

export interface ConfirmState {
  message: string;
  onConfirm: () => void | Promise<void>;
}
