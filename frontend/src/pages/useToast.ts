import { useEffect, useState } from "react";

const TOAST_DURATION_MS = 3000;

export function useToast(): {
  toastMessage: string;
  showToast: (message: string) => void;
} {
  const [toastMessage, setToastMessage] = useState("");

  useEffect(() => {
    if (!toastMessage) return;
    const timer = setTimeout(() => setToastMessage(""), TOAST_DURATION_MS);
    return () => clearTimeout(timer);
  }, [toastMessage]);

  return { toastMessage, showToast: setToastMessage };
}
