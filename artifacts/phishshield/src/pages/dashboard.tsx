import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, ShieldAlert, AlertTriangle, Fingerprint, Network, Link as LinkIcon, CheckCircle, Info, ChevronDown, RefreshCw, Send, Loader2, FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScoreGauge } from '@/components/ScoreGauge';
import { HighlightText } from '@/components/HighlightText';
import { useAnalyzeEmail } from '@workspace/api-client-react';

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
    reset(); // Clear previous results
  };

  return (
    <div className="min-h-screen bg-background relative overflow-x-hidden selection:bg-primary/30 selection:text-primary-foreground">
      {/* Background Image Setup */}
      <div 
        className="fixed inset-0 z-0 opacity-20 pointer-events-none bg-cover bg-center mix-blend-screen"
        style={{ backgroundImage: `url(${import.meta.env.BASE_URL}images/cyber-bg.png)` }}
      />
      
      {/* Navbar */}
      <nav className="relative z-10 border-b border-white/5 bg-background/50 backdrop-blur-xl sticky top-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.15)]">
              <ShieldCheck className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="font-display font-bold text-xl tracking-wide text-foreground flex items-center">
                PHISH<span className="text-primary">SHIELD</span><span className="ml-2 text-xs bg-primary/20 text-primary px-1.5 py-0.5 rounded font-mono">AI</span>
              </h1>
              <p className="text-[10px] text-muted-foreground uppercase tracking-widest -mt-1 font-mono">Security for Indian Users</p>
            </div>
          </div>
          
          <div className="hidden md:flex items-center space-x-6 text-sm font-medium text-muted-foreground">
            <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-safe animate-pulse"/> System Online</span>
            <span>v1.0 Engine</span>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* LEFT COLUMN: INPUT */}
          <div className={`col-span-1 transition-all duration-500 ${result ? 'lg:col-span-5' : 'lg:col-start-3 lg:col-span-8'}`}>
            <motion.div 
              layout
              className="glass-panel rounded-2xl p-1 relative overflow-hidden"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent pointer-events-none" />
              
              <div className="bg-background/80 rounded-xl p-5 sm:p-6 relative z-10">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-lg font-display font-semibold flex items-center gap-2">
                    <FileText className="w-5 h-5 text-primary" />
                    Target Email Source
                  </h2>
                  
                  {/* Demo Selector */}
                  <div className="relative">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-xs font-mono h-8 border-dashed border-muted-foreground/30 hover:border-primary/50"
                      onClick={() => setShowDemos(!showDemos)}
                    >
                      Load Demo <ChevronDown className="w-3 h-3 ml-1" />
                    </Button>
                    
                    <AnimatePresence>
                      {showDemos && (
                        <motion.div 
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: 10 }}
                          className="absolute right-0 mt-2 w-56 bg-popover border border-popover-border rounded-xl shadow-2xl z-50 overflow-hidden"
                        >
                          <div className="p-2 space-y-1">
                            {PRELOADED_EMAILS.map(demo => (
                              <button
                                key={demo.id}
                                onClick={() => loadDemo(demo.text)}
                                className="w-full text-left px-3 py-2 text-sm rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-foreground flex items-center justify-between group"
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

                <div className="relative group">
                  <textarea
                    value={emailText}
                    onChange={(e) => {
                      setEmailText(e.target.value);
                      if (result) reset();
                    }}
                    placeholder="Paste the raw email content or URL here to analyze..."
                    className={`w-full h-[300px] bg-black/40 border-2 rounded-xl p-4 text-foreground/90 font-mono text-sm resize-none transition-all duration-300 focus:outline-none focus:border-primary/50 focus:ring-4 focus:ring-primary/10 placeholder:text-muted-foreground/50 ${isPending ? 'opacity-50' : ''}`}
                    disabled={isPending}
                  />
                  {isPending && (
                    <div className="absolute inset-0 pointer-events-none scanning-beam rounded-xl" />
                  )}
                </div>

                <div className="mt-6 flex flex-col sm:flex-row gap-4 justify-between items-center">
                  <div className="text-xs text-muted-foreground/60 font-mono flex items-center gap-2">
                    <Info className="w-3 h-3" />
                    Fully offline. No data stored.
                  </div>
                  
                  <Button 
                    onClick={handleScan}
                    disabled={isPending || !emailText.trim()}
                    variant="cyber"
                    size="lg"
                    className="w-full sm:w-auto min-w-[160px]"
                  >
                    {isPending ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-5 h-5 mr-2" />
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
              </div>
            </motion.div>
          </div>

          {/* RIGHT COLUMN: RESULTS */}
          <AnimatePresence mode="wait">
            {result && (
              <motion.div 
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.5, staggerChildren: 0.1 }}
                className="col-span-1 lg:col-span-7 space-y-6"
              >
                {/* Top Row: Score & Breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Score Card */}
                  <motion.div className="glass-panel rounded-2xl p-6 flex flex-col items-center justify-center relative overflow-hidden">
                    <div className="absolute top-4 right-4">
                      {result.classification === 'safe' && <Badge variant="safe" className="px-3 py-1 text-sm"><ShieldCheck className="w-4 h-4 mr-1"/> Safe</Badge>}
                      {result.classification === 'suspicious' && <Badge variant="warning" className="px-3 py-1 text-sm"><AlertTriangle className="w-4 h-4 mr-1"/> Suspicious</Badge>}
                      {result.classification === 'phishing' && <Badge variant="destructive" className="px-3 py-1 text-sm"><ShieldAlert className="w-4 h-4 mr-1"/> Phishing</Badge>}
                    </div>
                    
                    <ScoreGauge score={result.riskScore} classification={result.classification} />
                    
                    <div className="w-full mt-6 bg-black/40 rounded-lg p-3 border border-white/5 flex items-center justify-between">
                      <span className="text-sm font-medium text-muted-foreground">AI Confidence</span>
                      <div className="flex-1 mx-4 h-2 bg-secondary rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-primary transition-all duration-1000" 
                          style={{ width: `${result.confidence * 100}%` }}
                        />
                      </div>
                      <span className="text-sm font-mono font-bold text-foreground">
                        {(result.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </motion.div>

                  {/* Breakdown Cards */}
                  <div className="flex flex-col gap-4 justify-between">
                    <div className="glass-panel rounded-xl p-4 flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
                        <Fingerprint className="w-5 h-5 text-primary" />
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">ML Model</span>
                          <span className="text-sm font-mono text-primary">{result.mlScore.toFixed(0)}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                          <div className="h-full bg-primary opacity-80" style={{ width: `${result.mlScore}%` }} />
                        </div>
                      </div>
                    </div>
                    
                    <div className="glass-panel rounded-xl p-4 flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center shrink-0">
                        <Network className="w-5 h-5 text-accent" />
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">Rules Engine</span>
                          <span className="text-sm font-mono text-accent">{result.ruleScore.toFixed(0)}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                          <div className="h-full bg-accent opacity-80" style={{ width: `${result.ruleScore}%` }} />
                        </div>
                      </div>
                    </div>

                    <div className="glass-panel rounded-xl p-4 flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-warning/10 border border-warning/20 flex items-center justify-center shrink-0">
                        <LinkIcon className="w-5 h-5 text-warning" />
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">URL Risk</span>
                          <span className="text-sm font-mono text-warning">{result.urlScore.toFixed(0)}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                          <div className="h-full bg-warning opacity-80" style={{ width: `${result.urlScore}%` }} />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Warnings */}
                {result.warnings.length > 0 && (
                  <motion.div className="space-y-3">
                    {result.warnings.map((warn, i) => (
                      <div key={i} className="bg-destructive/10 border border-destructive/30 rounded-xl p-4 flex items-start gap-3 shadow-[0_0_15px_rgba(239,68,68,0.1)]">
                        <AlertTriangle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                        <p className="text-sm text-destructive-foreground/90 font-medium">{warn}</p>
                      </div>
                    ))}
                  </motion.div>
                )}

                {/* Reasons List */}
                {result.reasons.length > 0 && (
                  <motion.div className="glass-panel rounded-2xl p-6">
                    <h3 className="text-lg font-display font-semibold mb-4 flex items-center gap-2">
                      <Info className="w-5 h-5 text-primary" />
                      Detection Signatures
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {result.reasons.map((reason, i) => (
                        <div key={i} className="bg-black/30 border border-white/5 rounded-xl p-4 hover:border-primary/30 transition-colors">
                          <div className="flex items-start justify-between mb-2">
                            <span className="text-sm font-semibold capitalize text-foreground/90 flex items-center gap-2">
                              {reason.category.replace('_', ' ')}
                            </span>
                            <Badge variant={reason.severity === 'high' ? 'destructive' : reason.severity === 'medium' ? 'warning' : 'secondary'} className="text-[10px] px-1.5 py-0">
                              {reason.severity}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mb-3">{reason.description}</p>
                          {reason.matchedTerms.length > 0 && (
                            <div className="flex flex-wrap gap-1.5">
                              {reason.matchedTerms.map((term, j) => (
                                <span key={j} className="text-[10px] font-mono bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded">
                                  "{term}"
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}

                {/* URL Analysis */}
                {result.urlAnalyses.length > 0 && (
                  <motion.div className="glass-panel rounded-2xl p-6">
                    <h3 className="text-lg font-display font-semibold mb-4 flex items-center gap-2">
                      <Network className="w-5 h-5 text-primary" />
                      Link Analysis
                    </h3>
                    <div className="space-y-3">
                      {result.urlAnalyses.map((url, i) => (
                        <div key={i} className="bg-black/40 border border-white/5 rounded-xl p-4 flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-mono text-foreground/90 truncate mb-1" title={url.url}>{url.url}</p>
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge variant={url.isSuspicious ? 'destructive' : 'safe'} className="text-[10px]">
                                {url.isSuspicious ? 'Suspicious' : 'Safe'}
                              </Badge>
                              {url.flags.map((flag, j) => (
                                <span key={j} className="text-[10px] text-muted-foreground bg-secondary px-1.5 py-0.5 rounded">{flag}</span>
                              ))}
                            </div>
                          </div>
                          <div className="w-full sm:w-24 shrink-0 flex flex-col items-end">
                            <span className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Risk</span>
                            <div className="w-full h-1.5 bg-secondary rounded-full overflow-hidden">
                              <div className={cn("h-full", url.isSuspicious ? "bg-destructive" : "bg-safe")} style={{ width: `${url.riskScore}%` }} />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}

                {/* Highlighted Text */}
                {result.suspiciousSpans.length > 0 && (
                  <motion.div className="glass-panel rounded-2xl p-6 border-l-4 border-l-warning">
                    <h3 className="text-sm font-semibold text-warning mb-3 flex items-center gap-2 uppercase tracking-wider">
                      <AlertTriangle className="w-4 h-4" />
                      Suspicious Content Detected
                    </h3>
                    <div className="bg-black/50 p-4 rounded-xl font-mono text-sm border border-white/5">
                      <HighlightText text={emailText} spans={result.suspiciousSpans} />
                    </div>
                  </motion.div>
                )}

                {/* Safety Tips */}
                {result.safetyTips.length > 0 && (
                  <motion.div className="glass-panel rounded-2xl p-6">
                    <h3 className="text-lg font-display font-semibold mb-4 flex items-center gap-2">
                      <ShieldCheck className="w-5 h-5 text-safe" />
                      Recommendation
                    </h3>
                    <ul className="space-y-3">
                      {result.safetyTips.map((tip, i) => (
                        <li key={i} className="flex items-start gap-3 text-sm text-muted-foreground">
                          <CheckCircle className="w-4 h-4 text-safe shrink-0 mt-0.5" />
                          <span>{tip}</span>
                        </li>
                      ))}
                    </ul>
                  </motion.div>
                )}

              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
      
      {/* Bottom Analytics Bar */}
      <footer className="fixed bottom-0 w-full border-t border-white/5 bg-background/80 backdrop-blur-md z-20 py-2">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex justify-between items-center text-[10px] font-mono text-muted-foreground/60 uppercase tracking-widest">
          <div className="flex gap-6">
            <span>Powered by PhishShield AI</span>
            <span className="hidden sm:inline">|</span>
            <span className="hidden sm:inline">Engine: Local Heuristics + ML</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            Active
          </div>
        </div>
      </footer>
    </div>
  );
}
