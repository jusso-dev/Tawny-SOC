import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Tawny-SOC",
  description: "AI SOC and SIEM workspace for Tawny telemetry.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `try{document.documentElement.classList.toggle('dark',localStorage.getItem('tawny-soc-theme')==='dark')}catch{}`,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
