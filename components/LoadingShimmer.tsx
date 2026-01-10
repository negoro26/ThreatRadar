'use client';

import { cn } from '@/lib/utils';

interface LoadingShimmerProps {
  className?: string;
}

export function LoadingShimmer({ className }: LoadingShimmerProps) {
  return (
    <div
      className={cn(
        'relative overflow-hidden bg-slate-900 border border-slate-800',
        className
      )}
    >
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-slate-700/20 to-transparent" />
    </div>
  );
}
