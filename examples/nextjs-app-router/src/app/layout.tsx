import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Navigation } from "../components/Navigation";
import "./globals.css";

export const metadata: Metadata = {
  title: "mrjim-auth Next.js example",
  description: "A self-hosted App Router integration for mrjim-auth",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <Navigation />
        <main className="shell">{children}</main>
      </body>
    </html>
  );
}
