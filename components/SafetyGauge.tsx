"use client";

import { useEffect, useState } from "react";

interface SafetyGaugeProps {
  score: number;
}

export function SafetyGauge({ score }: SafetyGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(score);
    }, 100);
    return () => clearTimeout(timer);
  }, [score]);

  const getColor = (score: number) => {
    if (score >= 80) return "#10b981";
    if (score >= 60) return "#22c55e";
    if (score >= 40) return "#eab308";
    if (score >= 20) return "#f97316";
    return "#f43f5e";
  };

  const getStrokeColor = (score: number) => {
    if (score >= 80) return "stroke-emerald-500";
    if (score >= 60) return "stroke-emerald-500";
    if (score >= 40) return "stroke-yellow-500";
    if (score >= 20) return "stroke-orange-500";
    return "stroke-rose-500";
  };

  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="relative w-full aspect-square max-w-[200px] mx-auto">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 160 160">
        <circle
          cx="80"
          cy="80"
          r={radius}
          className="stroke-slate-800"
          strokeWidth="12"
          fill="none"
        />

        <circle
          cx="80"
          cy="80"
          r={radius}
          className={`${getStrokeColor(score)} transition-all duration-1000 ease-out`}
          strokeWidth="12"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{
            filter: `drop-shadow(0 0 8px ${getColor(score)}40)`,
          }}
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <p className="text-4xl font-bold" style={{ color: getColor(score) }}>
          {animatedScore}
        </p>
        <p className="text-xs text-slate-400 mt-1">Safety Score</p>
      </div>
    </div>
  );
}
