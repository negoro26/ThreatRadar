"use client";

import { cn } from "@/lib/utils";

interface TechStackItem {
  app: string;
  confidence?: number;
  categories?: string[];
}

interface TechStackListProps {
  technologies: TechStackItem[];
  className?: string;
}

export function TechStackList({ technologies, className }: TechStackListProps) {
  if (technologies.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No technologies detected</p>
    );
  }

  return (
    <ul className={cn("divide-y divide-border", className)}>
      {technologies.map((tech, idx) => (
        <li key={idx} className="flex items-center justify-between py-2 first:pt-0 last:pb-0">
          <span className="font-mono-data text-sm text-foreground">{tech.app}</span>
          {tech.confidence != null && (
            <span
              className="font-mono-data text-xs text-muted-foreground"
              style={{ opacity: Math.max(0.4, tech.confidence / 100) }}
            >
              {tech.confidence}%
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
