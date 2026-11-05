import Link from "next/link";
import { DSH_BRAND } from "@/lib/constants/theme";

export default function Home() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#FAFAF7] flex flex-col justify-between p-6 sm:p-12">
      <header className="flex justify-between items-center border-b border-[#262626] pb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-[#C9A227] flex items-center justify-center font-bold text-black text-xl shadow-md">
            D
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-[#FAFAF7]">
              {DSH_BRAND.name}
            </h1>
            <p className="text-xs text-[#C9A227] tracking-wider uppercase font-semibold">
              {DSH_BRAND.tagline}
            </p>
          </div>
        </div>
        <nav className="flex items-center gap-4 text-sm">
          <Link
            href="/connect"
            className="px-4 py-2 rounded-lg bg-[#C9A227] hover:bg-[#FFD700] text-black font-semibold transition"
          >
            Wi-Fi Portal
          </Link>
        </nav>
      </header>

      <main className="my-auto py-12 max-w-2xl">
        <span className="inline-block px-3 py-1 text-xs font-semibold rounded-full bg-[#C9A227]/10 text-[#C9A227] border border-[#C9A227]/30 mb-6">
          Milestone 02 • Foundation Active
        </span>
        <h2 className="text-4xl sm:text-5xl font-extrabold tracking-tight mb-4">
          Connect. Create. <span className="text-[#C9A227]">Get Things Done.</span>
        </h2>
        <p className="text-base sm:text-lg text-zinc-400 mb-8 leading-relaxed">
          The next-generation digital services hub and high-speed Wi-Fi network engine. Built with Next.js, PostgreSQL, and Safaricom Daraja integration.
        </p>
        <div className="flex flex-wrap gap-4">
          <Link
            href="/connect"
            className="px-6 py-3 rounded-lg bg-[#C9A227] hover:bg-[#FFD700] text-black font-semibold transition"
          >
            Open Captive Portal
          </Link>
          <div className="px-6 py-3 rounded-lg bg-[#141414] border border-[#262626] text-zinc-400 font-mono text-sm">
            Status: Standards &amp; Structure Ready
          </div>
        </div>
      </main>

      <footer className="border-t border-[#262626] pt-6 flex flex-col sm:flex-row justify-between text-xs text-zinc-500 gap-4">
        <p>&copy; 2026 {DSH_BRAND.name}. All rights reserved.</p>
        <p>Built with Next.js, PostgreSQL &amp; Tailwind CSS</p>
      </footer>
    </div>
  );
}
