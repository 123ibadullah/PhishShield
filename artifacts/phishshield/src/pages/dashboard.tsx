import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, ShieldAlert, AlertTriangle, Fingerprint, Network, Link as LinkIcon, CheckCircle, Info, ChevronDown, RefreshCw, Send, Loader2, Mail, Eye, Flag } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScoreGauge } from '@/components/ScoreGauge';
import { HighlightText } from '@/components/HighlightText';
import { useAnalyzeEmail } from '@workspace/api-client-react';
import { cn } from '@/lib/utils';

const PRELOADED_EMAILS = [
  {
    id: 'sbi',
    label: 'SBI Bank Alert (Phishing)',
    text: "Dear Customer, Your SBI account has been suspended due to suspicious activity. Click here immediately to verify: http://sbi-secure-update.xyz/verify?token=abc123 Your account will be permanently blocked in 24 hours. Call 1800-XXX-XXXX urgently. -- SBI Customer Care"
  },
  {
    id: 'upi',
    label: 'UPI Reward Claim (Scam)',
    text: "Congratulations! You have won Rs. 50,000 in GPay reward program. To claim your prize, verify your UPI ID at http://gpay-reward.tk/claim and complete KYC. Offer expires in 2 hours! Transaction ID: TXN8823991"
  },
  {
    id: 'paytm',
    label: 'Paytm KYC (Scam)',
    text: "URGENT: Your Paytm wallet has been blocked. Complete KYC verification immediately at http://paytm-kyc.ml/update or lose Rs. 12,500 wallet balance. Enter OTP sent to your number. Support: 1800-258-38XX"
  },
  {
    id: 'office',
    label: 'Office Meeting (Safe)',
    text: "Hi Team, Please join the project sync meeting tomorrow at 3 PM IST in the main conference room. Agenda has been shared on Google Calendar. Let me know if you have any questions. Best, Priya"
  },
  {
    id: 'amazon',
    label: 'Amazon Order (Safe)',
    text: "Your Amazon order #402-8837291-XXXXXX has been shipped. Expected delivery: March 18. Track your package at amazon.in/orders. Thank you for shopping with Amazon."
  }
];

export default function Dashboard() {
  const [emailText, setEmailText] = useState('');
  const [showDemos, setShowDemos] = useState(false);
  
  const { mutate: analyzeEmail, data: result, isPending, error, reset } = useAnalyzeEmail();

  const handleScan = () => {
    if (!emailText.trim()) return;
    analyzeEmail({ data: { emailText } });
  };

  const loadDemo = (text: string) => {
    setEmailText(text);
    setShowDemos(false);
    reset();
  };

  // Category mapping for human readability
  const categoryMap: Record<string, string> = {
    urgency: "Creates urgency",
    social_engineering: "Manipulation tactics",
    india_specific: "Brand impersonation",
    url: "Suspicious links",
    financial: "Financial threats",
    language: "Regional language scam"
  };

  const getHumanCategory = (cat: string) => categoryMap[cat] || cat.replace('_', ' ');

  return (
    <div className="min-h-screen bg-background relative overflow-x-hidden pb-12 selection:bg-primary/30 selection:text-primary-foreground">
      {/* Header */}
      <nav className="sticky top-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="max-w-3xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center border border-primary/20">
              <ShieldCheck className="w-5 h-5 text-primary" />
            </div>
            <div className="flex flex-col">
              <h1 className="font-semibold text-lg text-foreground flex items-center gap-2 leading-none">
                PhishShield
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-primary text-primary-foreground font-bold tracking-wider">AI</span>
              </h1>
              <p className="text-[10px] text-muted-foreground tracking-wide mt-0.5">Detect. Explain. Protect.</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <span className="text-xs text-muted-foreground hidden sm:inline-block">Built for Indian users 🇮🇳</span>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground bg-secondary/50 px-2 py-1 rounded-md border border-border/50">
              <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse"/>
              Engine Active
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative z-10 max-w-3xl mx-auto px-4 py-8 space-y-8">
        
        {/* INPUT SECTION */}
        <motion.div 
          layout
          className="rounded-2xl border border-card-border bg-card p-6 shadow-sm"
        >
          <div className="flex justify-between items-center mb-4">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-secondary/50 text-xs font-medium text-muted-foreground border border-border/50">
              <Mail className="w-3.5 h-3.5" />
              Analyze Email
            </div>
            
            {/* Demo Selector */}
            <div className="relative">
              <Button 
                variant="outline" 
                size="sm" 
                className="text-xs h-8 bg-transparent border-muted hover:bg-muted"
                onClick={() => setShowDemos(!showDemos)}
              >
                Load Demo <ChevronDown className="w-3 h-3 ml-1" />
              </Button>
              
              <AnimatePresence>
                {showDemos && (
                  <motion.div 
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 5 }}
                    className="absolute right-0 mt-2 w-56 bg-popover border border-popover-border rounded-xl shadow-lg z-50 overflow-hidden"
                  >
                    <div className="p-1.5">
                      {PRELOADED_EMAILS.map(demo => (
                        <button
                          key={demo.id}
                          onClick={() => loadDemo(demo.text)}
                          className="w-full text-left px-3 py-2 text-sm rounded-lg hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground flex items-center justify-between group"
                        >
                          {demo.label}
                          <RefreshCw className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </button>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          <div className="relative">
            <textarea
              value={emailText}
              onChange={(e) => {
                setEmailText(e.target.value);
                if (result) reset();
              }}
              placeholder="Paste suspicious email content here..."
              className={cn(
                "w-full min-h-[200px] bg-background/50 border border-input rounded-xl p-4 text-foreground font-mono text-sm resize-y transition-all focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 placeholder:text-muted-foreground/40",
                isPending && "opacity-60"
              )}
              disabled={isPending}
            />
          </div>

          <div className="mt-4 flex flex-col sm:flex-row gap-4 justify-between items-center">
            <div className="text-[11px] text-muted-foreground flex items-center gap-1.5">
              <span>🔒 Offline &middot; No data stored</span>
            </div>
            
            <Button 
              onClick={handleScan}
              disabled={isPending || !emailText.trim()}
              size="lg"
              className="w-full sm:w-auto min-w-[140px] font-medium"
            >
              {isPending ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  Scan Email
                </>
              )}
            </Button>
          </div>
          
          {error && (
            <div className="mt-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
              <span>Failed to analyze email. Please try again.</span>
            </div>
          )}
        </motion.div>

        {/* RESULTS SECTION */}
        <AnimatePresence mode="wait">
          {result && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.4 }}
              className="space-y-6"
            >
              
              {/* 1. Verdict Card */}
              <div className={cn(
                "rounded-xl border shadow-sm overflow-hidden relative",
                result.classification === 'safe' ? "bg-safe/5 border-safe/20" : 
                result.classification === 'suspicious' ? "bg-warning/5 border-warning/20" : 
                "bg-destructive/5 border-destructive/20"
              )}>
                {/* Left color bar */}
                <div className={cn(
                  "absolute left-0 top-0 bottom-0 w-1",
                  result.classification === 'safe' ? "bg-safe" : 
                  result.classification === 'suspicious' ? "bg-warning" : 
                  "bg-destructive"
                )} />
                
                <div className="p-6 sm:px-8 flex flex-col sm:flex-row items-center justify-between gap-6 pl-8">
                  <div className="flex flex-col items-center sm:items-start text-center sm:text-left">
                    <h2 className={cn(
                      "text-3xl font-bold uppercase tracking-tight",
                      result.classification === 'safe' ? "text-safe" : 
                      result.classification === 'suspicious' ? "text-warning" : 
                      "text-destructive"
                    )}>
                      {result.classification}
                    </h2>
                    <p className="text-sm text-muted-foreground mt-1">Confidence: {(result.confidence * 100).toFixed(0)}%</p>
                  </div>
                  
                  <div className="flex items-center gap-6">
                    <ScoreGauge score={result.riskScore} classification={result.classification} />
                  </div>
                </div>
              </div>

              {/* 2. Score Breakdown */}
              <div className="flex flex-col sm:flex-row gap-6 pt-2 pb-4 border-b border-border/50">
                <div className="flex-1 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground font-medium">Behavioural Analysis</span>
                    <span className="text-foreground font-mono">{result.mlScore.toFixed(0)}%</span>
                  </div>
                  <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
                    <div className="h-full bg-primary" style={{ width: `${result.mlScore}%` }} />
                  </div>
                </div>
                
                <div className="flex-1 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground font-medium">Pattern Matching</span>
                    <span className="text-foreground font-mono">{result.ruleScore.toFixed(0)}%</span>
                  </div>
                  <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
                    <div className="h-full bg-accent" style={{ width: `${result.ruleScore}%` }} />
                  </div>
                </div>
                
                <div className="flex-1 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground font-medium">Link Risk</span>
                    <span className="text-foreground font-mono">{result.urlScore.toFixed(0)}%</span>
                  </div>
                  <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
                    <div className="h-full bg-warning" style={{ width: `${result.urlScore}%` }} />
                  </div>
                </div>
              </div>

              {/* 3. Warnings */}
              {result.warnings.length > 0 && (
                <div className="space-y-2">
                  {result.warnings.map((warn, i) => (
                    <div key={i} className="bg-destructive/10 rounded-lg px-4 py-3 flex items-start gap-3">
                      <AlertTriangle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                      <p className="text-sm text-foreground leading-relaxed">{warn}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* 4. Why We Flagged This */}
              {result.reasons.length > 0 && (
                <div className="space-y-4 pt-4">
                  <h3 className="text-lg font-semibold text-foreground">Why we flagged this</h3>
                  <div className="space-y-3">
                    {result.reasons.map((reason, i) => (
                      <div key={i} className="flex items-start gap-3">
                        <div className={cn(
                          "w-2 h-2 rounded-full mt-2 shrink-0",
                          reason.severity === 'high' ? 'bg-destructive' : reason.severity === 'medium' ? 'bg-warning' : 'bg-safe'
                        )} />
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm font-medium text-foreground">
                              {getHumanCategory(reason.category)}
                            </span>
                            <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 border-border text-muted-foreground font-normal">
                              {reason.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground leading-relaxed">
                            {reason.description}
                          </p>
                          {reason.matchedTerms.length > 0 && (
                            <div className="flex flex-wrap gap-1.5 mt-2">
                              {reason.matchedTerms.map((term, j) => (
                                <span key={j} className="text-[11px] font-mono bg-secondary text-secondary-foreground px-2 py-0.5 rounded-md">
                                  {term}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 5. Links Found */}
              {result.urlAnalyses.length > 0 && (
                <div className="space-y-4 pt-4">
                  <h3 className="text-lg font-semibold text-foreground">Links in this email</h3>
                  <div className="space-y-3">
                    {result.urlAnalyses.map((url, i) => {
                      let domain = url.url;
                      try {
                        domain = new URL(url.url).hostname;
                      } catch (e) {
                        // ignore
                      }
                      
                      return (
                        <div key={i} className="flex flex-col sm:flex-row items-start gap-3 sm:items-center py-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-semibold text-sm text-foreground truncate">{domain}</span>
                              <Badge variant={url.isSuspicious ? 'destructive' : 'secondary'} className={cn("text-[10px] px-1.5 py-0 h-4 font-normal", !url.isSuspicious && "bg-safe/10 text-safe hover:bg-safe/20")}>
                                {url.isSuspicious ? 'Suspicious' : 'Safe'}
                              </Badge>
                            </div>
                            <p className="text-xs font-mono text-muted-foreground truncate" title={url.url}>{url.url}</p>
                            {url.isSuspicious && url.flags.length > 0 && (
                              <div className="flex items-center gap-1.5 mt-1.5 text-xs text-muted-foreground">
                                <Flag className="w-3 h-3 text-destructive" />
                                <span>{url.flags.join(', ')}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* 6. Email Content */}
              {result.suspiciousSpans.length > 0 && (
                <div className="space-y-4 pt-4">
                  <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                    <Eye className="w-5 h-5 text-muted-foreground" />
                    Email Content
                  </h3>
                  <div className="bg-card border border-border/60 rounded-xl p-5 shadow-sm">
                    <HighlightText text={emailText} spans={result.suspiciousSpans} />
                  </div>
                </div>
              )}

              {/* 7. Safety Guidance */}
              {result.safetyTips.length > 0 && (
                <div className="space-y-4 pt-4 border-t border-border/50">
                  <h3 className="text-lg font-semibold text-foreground">Before you act</h3>
                  <div className="space-y-3">
                    {result.safetyTips.slice(0, 4).map((tip, i) => (
                      <div key={i} className="flex items-start gap-3">
                        <ShieldCheck className="w-4 h-4 text-safe shrink-0 mt-0.5" />
                        <p className="text-sm text-foreground/90">{tip}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </motion.div>
          )}
        </AnimatePresence>
      </main>
      
      {/* Footer footer */}
      <footer className="mt-12 py-6 border-t border-border/50 text-center">
        <p className="text-xs text-muted-foreground/60 tracking-wide font-medium">
          PhishShield AI — built for India 🇮🇳
        </p>
      </footer>
    </div>
  );
}
