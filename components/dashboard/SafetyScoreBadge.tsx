"use client";

import { cva, type VariantProps } from "class-variance-authority";
import { ShieldCheck, ShieldAlert, ShieldX, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs font-semibold font-mono-data transition-colors",
  {
    variants: {
      level: {
        safe: "bg-success/10 text-success border-success/20",
        low: "bg-success/10 text-success border-success/20",
        moderate: "bg-warning/10 text-warning border-warning/20",
        high: "bg-destructive/10 text-orange-400 border-orange-400/20",
        critical: "bg-destructive/10 text-destructive border-destructive/20",
      },
    },
    defaultVariants: {
      level: "safe",
    },
  }
);

interface SafetyScoreBadgeProps extends VariantProps<typeof badgeVariants> {
  score: number;
  showLabel?: boolean;
  className?: string;
}

function getScoreLevel(score: number) {
  if (score >= 80) return { level: "safe" as const, label: "Safe", Icon: ShieldCheck };
  if (score >= 60) return { level: "low" as const, label: "Low Risk", Icon: ShieldCheck };
  if (score >= 40) return { level: "moderate" as const, label: "Suspicious", Icon: ShieldAlert };
  if (score >= 20) return { level: "high" as const, label: "High Risk", Icon: ShieldX };
  return { level: "critical" as const, label: "Malicious", Icon: ShieldX };
}

export function SafetyScoreBadge({ score, showLabel = true, className }: SafetyScoreBadgeProps) {
  const { level, label, Icon } = getScoreLevel(score);

  return (
    <span className={cn(badgeVariants({ level }), className)}>
      <Icon className="w-4 h-4" />
      <span className="font-mono-data">{score}</span>
      {showLabel && <span className="text-[11px] uppercase tracking-wider">{label}</span>}
    </span>
  );
}
