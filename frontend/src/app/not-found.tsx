import Link from "next/link";
import { DSH_BRAND } from "@/lib/constants/theme";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#FAFAF7] flex flex-col items-center justify-center p-6 text-center">
      <div className="max-w-md w-full bg-[#141414] border border-[#262626] rounded-xl p-8 shadow-xl">
        <span className="text-xs font-mono uppercase tracking-wider text-[#C9A227] block mb-2">
          404 &bull; Page Not Found
        </span>
        <h1 className="text-3xl font-extrabold text-[#FAFAF7] mb-3">
          Lost in the Network?
        </h1>
        <p className="text-zinc-400 text-sm mb-6">
          The requested page could not be found or has been relocated.
        </p>
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <Link
            href="/"
            className="px-5 py-2.5 rounded-lg bg-[#C9A227] hover:bg-[#FFD700] text-black font-semibold text-sm transition"
          >
            Return Home
          </Link>
          <Link
            href="/connect"
            className="px-5 py-2.5 rounded-lg bg-[#1F1F1F] hover:bg-[#2A2A2A] text-[#FAFAF7] font-medium text-sm border border-[#333333] transition"
          >
            Wi-Fi Portal
          </Link>
        </div>
      </div>
      <p className="mt-8 text-xs text-zinc-600">
        {DSH_BRAND.name} &bull; {DSH_BRAND.tagline}
      </p>
    </div>
  );
}
