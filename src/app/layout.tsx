import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ProofGate | Telegraph Agent Firewall",
  description:
    "A pre-execution firewall that routes URL safety checks through Telegraph before autonomous agents act.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full">
      <body>{children}</body>
    </html>
  );
}
