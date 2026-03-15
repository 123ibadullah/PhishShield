import React from 'react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { type SuspiciousSpan } from '@workspace/api-client-react';

interface HighlightTextProps {
  text: string;
  spans: SuspiciousSpan[];
}

export function HighlightText({ text, spans }: HighlightTextProps) {
  if (!spans || spans.length === 0) {
    return <p className="whitespace-pre-wrap text-muted-foreground leading-relaxed">{text}</p>;
  }

  // Sort spans by start index
  const sortedSpans = [...spans].sort((a, b) => a.start - b.start);
  const elements: React.ReactNode[] = [];
  let lastIndex = 0;

  sortedSpans.forEach((span, i) => {
    // Add text before the span
    if (span.start > lastIndex) {
      elements.push(
        <span key={`text-${i}`} className="text-muted-foreground leading-relaxed">
          {text.slice(lastIndex, span.start)}
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
              <mark className="bg-destructive/20 text-destructive-foreground font-medium px-1 rounded-sm border-b border-destructive/50 cursor-help transition-colors hover:bg-destructive/30 inline-block">
                {spanText}
              </mark>
            </TooltipTrigger>
            <TooltipContent className="bg-destructive text-destructive-foreground border-none font-medium max-w-[250px]">
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
      <span key="text-last" className="text-muted-foreground leading-relaxed">
        {text.slice(lastIndex)}
      </span>
    );
  }

  return <div className="whitespace-pre-wrap">{elements}</div>;
}
