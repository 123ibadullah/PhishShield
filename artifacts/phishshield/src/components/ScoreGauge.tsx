// Semi-circular gauge showing the 0–100 risk score. The arc fills left-to-right
// and changes colour based on whether the email is safe, suspicious, or phishing.
import React from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface ScoreGaugeProps {
  score: number; // 0–100
  classification: 'safe' | 'suspicious' | 'phishing';
}

export function ScoreGauge({ score, classification }: ScoreGaugeProps) {
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const arcLength = circumference / 2; // half-circle = 180°

  // How far the arc has progressed (0 = empty, arcLength = full)
  const strokeDasharray = `${arcLength} ${circumference}`;
  const strokeDashoffset = arcLength - (score / 100) * arcLength;

  const colors = {
    safe:       { stroke: 'stroke-safe',        text: 'text-safe' },
    suspicious: { stroke: 'stroke-warning',      text: 'text-warning' },
    phishing:   { stroke: 'stroke-destructive',  text: 'text-destructive' },
  };

  const { stroke, text } = colors[classification] ?? colors.safe;

  return (
    <div className="relative flex flex-col items-center justify-center pt-2">
      <svg 
        width="200" 
        height="100" 
        viewBox="0 0 160 90" 
        className="overflow-visible relative z-10"
      >
        {/* Background Track */}
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className="stroke-muted"
          strokeDasharray={strokeDasharray}
          strokeDashoffset="0"
          transform="rotate(180 80 80)"
          strokeLinecap="round"
        />
        
        {/* Subtle CSS glow via duplicated blurry track */}
        <motion.circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className={cn(stroke, "transition-colors duration-500 blur-md opacity-50")}
          strokeDasharray={strokeDasharray}
          initial={{ strokeDashoffset: arcLength }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          transform="rotate(180 80 80)"
          strokeLinecap="round"
        />

        {/* Progress Track */}
        <motion.circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className={cn(stroke, "transition-colors duration-500")}
          strokeDasharray={strokeDasharray}
          initial={{ strokeDashoffset: arcLength }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          transform="rotate(180 80 80)"
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute bottom-0 flex flex-col items-center text-center z-20">
        <motion.span 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className={cn("text-4xl font-bold tracking-tight", text)}
        >
          {score}
        </motion.span>
        <span className="text-xs uppercase tracking-wide text-muted-foreground mt-1">
          Risk Score
        </span>
      </div>
    </div>
  );
}
