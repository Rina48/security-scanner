export type ThemeMode = "light" | "dark";
export type InputTab = "url" | "body";
export type ActiveTab = "executive" | "technical";

export interface ConfirmState {
  message: string;
  onConfirm: () => void | Promise<void>;
}
