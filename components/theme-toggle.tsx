"use client";

import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

export function ThemeToggle() {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("tawny-soc-theme");
    const nextDark = stored === "dark";
    document.documentElement.classList.toggle("dark", nextDark);
    const timer = window.setTimeout(() => setDark(nextDark), 0);
    return () => window.clearTimeout(timer);
  }, []);

  function toggle() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("tawny-soc-theme", next ? "dark" : "light");
  }

  return (
    <button className="theme-toggle" type="button" onClick={toggle} aria-label="Toggle dark mode">
      {dark ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
      <span>{dark ? "Light" : "Dark"}</span>
    </button>
  );
}
