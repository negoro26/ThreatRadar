'use client';

import { cn } from '@/lib/utils';

interface LoadingShimmerProps {
  className?: string;
}

export function LoadingShimmer({ className }: LoadingShimmerProps) {
  return (
    <div
      className={cn(
        'relative overflow-hidden bg-card border border-border',
        className
      )}
    >
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-secondary/40 to-transparent" />
    </div>
  );
}
