import { useState } from "react";
import type { ThemeMode } from "./scannerPageTypes";

function getInitialTheme(): ThemeMode {
  const saved = localStorage.getItem("theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme: ThemeMode): void {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
}

export function useTheme(): { theme: ThemeMode; toggleTheme: () => void } {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const initial = getInitialTheme();
    applyTheme(initial);
    return initial;
  });

  function toggleTheme(): void {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    applyTheme(next);
  }

  return { theme, toggleTheme };
}
