"use client";

import { useEffect, useState } from "react";

type ToastKind = "success" | "error" | "info";

type ToastDetail = {
  kind?: ToastKind;
  message: string;
};

type ToastItem = Required<ToastDetail> & {
  id: number;
};

declare global {
  interface WindowEventMap {
    "tawny-toast": CustomEvent<ToastDetail>;
  }
}

export function notify(message: string, kind: ToastKind = "info") {
  window.dispatchEvent(new CustomEvent("tawny-toast", { detail: { kind, message } }));
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => {
    function onToast(event: WindowEventMap["tawny-toast"]) {
      const id = Date.now() + Math.random();
      const toast: ToastItem = {
        id,
        kind: event.detail.kind ?? "info",
        message: event.detail.message,
      };
      setToasts((current) => [...current.slice(-2), toast]);
      window.setTimeout(() => {
        setToasts((current) => current.filter((item) => item.id !== id));
      }, 4200);
    }

    window.addEventListener("tawny-toast", onToast);
    return () => window.removeEventListener("tawny-toast", onToast);
  }, []);

  return (
    <>
      {children}
      <div className="toast-region" aria-live="polite" aria-label="Notifications">
        {toasts.map((toast) => (
          <div className={`toast toast-${toast.kind}`} key={toast.id}>
            {toast.message}
          </div>
        ))}
      </div>
    </>
  );
}
