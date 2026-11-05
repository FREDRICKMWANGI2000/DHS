"use client";

import { useEffect } from "react";
import Link from "next/link";
import { DSH_BRAND } from "@/lib/constants/theme";

interface ErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function ErrorBoundary({ error, reset }: ErrorProps) {
  useEffect(() => {
    // Log unexpected errors securely without leaking confidential data
    console.error("Application error boundary triggered:", error.message);
  }, [error]);

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#FAFAF7] flex flex-col items-center justify-center p-6 text-center">
      <div className="max-w-md w-full bg-[#141414] border border-[#262626] rounded-xl p-8 shadow-xl">
        <span className="text-xs font-mono uppercase tracking-wider text-[#C9A227] block mb-2">
          System Notice &bull; Unexpected State
        </span>
        <h1 className="text-2xl font-bold text-[#FAFAF7] mb-3">
          Something went wrong
        </h1>
        <p className="text-zinc-400 text-sm mb-6">
          We encountered an issue processing your request. Please try again or return to the main dashboard.
        </p>
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <button
            type="button"
            onClick={() => reset()}
            className="px-5 py-2.5 rounded-lg bg-[#C9A227] hover:bg-[#FFD700] text-black font-semibold text-sm transition"
          >
            Try Again
          </button>
          <Link
            href="/"
            className="px-5 py-2.5 rounded-lg bg-[#1F1F1F] hover:bg-[#2A2A2A] text-[#FAFAF7] font-medium text-sm border border-[#333333] transition"
          >
            Return Home
          </Link>
        </div>
      </div>
      <p className="mt-8 text-xs text-zinc-600">
        {DSH_BRAND.name} &bull; Resilient Architecture
      </p>
    </div>
  );
}
