import React from 'react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { type SuspiciousSpan } from '@workspace/api-client-react';

interface HighlightTextProps {
  text: string;
  spans: SuspiciousSpan[];
}

// Helper to parse URLs in text
function TextWithUrls({ text }: { text: string }) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const parts = text.split(urlRegex);
  
  return (
    <>
      {parts.map((part, i) => {
        if (part.match(urlRegex)) {
          return (
            <span key={i} className="text-blue-400/80 underline cursor-default italic">
              {part}
            </span>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

export function HighlightText({ text, spans }: HighlightTextProps) {
  if (!spans || spans.length === 0) {
    return (
      <div className="whitespace-pre-wrap text-foreground/70 leading-relaxed font-mono text-sm">
        <TextWithUrls text={text} />
      </div>
    );
  }

  // Sort spans by start index
  const sortedSpans = [...spans].sort((a, b) => a.start - b.start);
  const elements: React.ReactNode[] = [];
  let lastIndex = 0;

  sortedSpans.forEach((span, i) => {
    // Add text before the span
    if (span.start > lastIndex) {
      elements.push(
        <span key={`text-${i}`} className="text-foreground/70 leading-relaxed">
          <TextWithUrls text={text.slice(lastIndex, span.start)} />
        </span>
      );
    }
    
    // Add the highlighted span
    const spanText = text.slice(span.start, span.end);
    if (spanText) {
      elements.push(
        <TooltipProvider key={`span-${i}`}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="underline underline-offset-2 decoration-warning/60 decoration-wavy text-warning/90 cursor-help transition-colors hover:text-warning inline-block">
                {spanText}
              </span>
            </TooltipTrigger>
            <TooltipContent className="bg-popover border border-popover-border text-foreground shadow-sm font-medium max-w-[250px]">
              <p>{span.reason}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    }
    lastIndex = Math.max(lastIndex, span.end);
  });

  // Add remaining text
  if (lastIndex < text.length) {
    elements.push(
      <span key="text-last" className="text-foreground/70 leading-relaxed">
        <TextWithUrls text={text.slice(lastIndex)} />
      </span>
    );
  }

  return <div className="whitespace-pre-wrap font-mono text-sm">{elements}</div>;
}
