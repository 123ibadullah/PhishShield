import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, ShieldAlert, AlertTriangle,
  CheckCircle, ChevronDown, RefreshCw, Loader2,
  Mail, Eye, Flag, BarChart3, History, Trash2, Globe, Languages,
  TrendingUp, Scan
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScoreGauge } from '@/components/ScoreGauge';
import { HighlightText } from '@/components/HighlightText';
import { useAnalyzeEmail, useGetScanHistory, useGetModelMetrics, useClearScanHistory } from '@workspace/api-client-react';
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
    id: 'hindi',
    label: 'Hindi Bank Scam (Phishing)',
    text: "प्रिय ग्राहक, आपका SBI बैंक खाता तुरंत बंद हो जाएगा। अभी सत्यापन करें: http://sbi-verify.xyz/kyc?id=12345 OTP किसी के साथ साझा न करें। अभी क्लिक करें! -- SBI ग्राहक सेवा"
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

const LANG_LABELS: Record<string, string> = {
  en: 'English',
  hi: 'Hindi',
  te: 'Telugu',
  mixed: 'Mixed',
};

const LANG_FLAGS: Record<string, string> = {
  en: '🇬🇧',
  hi: '🇮🇳',
  te: '🇮🇳',
  mixed: '🌐',
};

const categoryMap: Record<string, string> = {
  urgency: "Creates urgency",
  social_engineering: "Manipulation tactics",
  india_specific: "Brand impersonation",
  url: "Suspicious links",
  financial: "Financial threats",
  language: "Regional language scam",
  ml_score: "AI detection",
  domain: "Domain risk",
};

const getHumanCategory = (cat: string) => categoryMap[cat] || cat.replace(/_/g, ' ');

function classificationColor(c: string) {
  if (c === 'safe') return { text: 'text-safe', bg: 'bg-safe/5', border: 'border-safe/20', bar: 'bg-safe' };
  if (c === 'suspicious') return { text: 'text-warning', bg: 'bg-warning/5', border: 'border-warning/20', bar: 'bg-warning' };
  return { text: 'text-destructive', bg: 'bg-destructive/5', border: 'border-destructive/20', bar: 'bg-destructive' };
}

function formatTime(iso: string) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function formatDate(iso: string) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
  } catch {
    return '';
  }
}

type Tab = 'analyze' | 'dashboard';

export default function Dashboard() {
  const [emailText, setEmailText] = useState('');
  const [showDemos, setShowDemos] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('analyze');

  const { mutate: analyzeEmail, data: result, isPending, error, reset } = useAnalyzeEmail();
  const { data: history = [], refetch: refetchHistory } = useGetScanHistory({ query: { refetchOnWindowFocus: false } });
  const { data: metrics, refetch: refetchMetrics } = useGetModelMetrics({ query: { refetchOnWindowFocus: false } });
  const { mutate: clearHistory } = useClearScanHistory();

  const handleScan = () => {
    if (!emailText.trim()) return;
    analyzeEmail({ data: { emailText } }, {
      onSuccess: () => {
        refetchHistory();
        refetchMetrics();
      }
    });
  };

  const loadDemo = (text: string) => {
    setEmailText(text);
    setShowDemos(false);
    reset();
  };

  const handleClearHistory = () => {
    clearHistory(undefined, {
      onSuccess: () => {
        refetchHistory();
        refetchMetrics();
      }
    });
  };

  return (
    <div className="min-h-screen bg-background relative overflow-x-hidden pb-16 selection:bg-primary/30 selection:text-primary-foreground">

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

          <div className="flex items-center gap-3">
            {/* Tab switcher */}
            <div className="flex items-center bg-secondary/50 border border-border/50 rounded-lg p-0.5 gap-0.5">
              <button
                onClick={() => setActiveTab('analyze')}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === 'analyze'
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <Mail className="w-3.5 h-3.5" />
                Analyze
              </button>
              <button
                onClick={() => { setActiveTab('dashboard'); refetchHistory(); refetchMetrics(); }}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === 'dashboard'
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <BarChart3 className="w-3.5 h-3.5" />
                Dashboard
                {history.length > 0 && (
                  <span className="w-4 h-4 rounded-full bg-primary/20 text-primary text-[9px] font-bold flex items-center justify-center">
                    {history.length}
                  </span>
                )}
              </button>
            </div>

            <div className="hidden sm:flex items-center gap-1.5 text-xs text-muted-foreground bg-secondary/50 px-2 py-1 rounded-md border border-border/50">
              <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
              Engine Active
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative z-10 max-w-3xl mx-auto px-4 py-8">

        {/* ─── ANALYZE TAB ─── */}
        <AnimatePresence mode="wait">
          {activeTab === 'analyze' && (
            <motion.div
              key="analyze"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
              className="space-y-8"
            >
              {/* INPUT SECTION */}
              <div className="rounded-2xl border border-card-border bg-card p-6 shadow-sm">
                <div className="flex justify-between items-center mb-4">
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-secondary/50 text-xs font-medium text-muted-foreground border border-border/50">
                    <Mail className="w-3.5 h-3.5" />
                    Analyze Email
                  </div>

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
                          className="absolute right-0 mt-2 w-60 bg-popover border border-popover-border rounded-xl shadow-lg z-50 overflow-hidden"
                        >
                          <div className="p-1.5">
                            {PRELOADED_EMAILS.map(demo => (
                              <button
                                key={demo.id}
                                onClick={() => loadDemo(demo.text)}
                                className="w-full text-left px-3 py-2 text-sm rounded-lg hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground flex items-center justify-between group"
                              >
                                <span>{demo.label}</span>
                                <RefreshCw className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity shrink-0 ml-2" />
                              </button>
                            ))}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>

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

                <div className="mt-4 flex flex-col sm:flex-row gap-4 justify-between items-center">
                  <div className="text-[11px] text-muted-foreground">
                    🔒 Offline &middot; No data stored
                  </div>
                  <Button
                    onClick={handleScan}
                    disabled={isPending || !emailText.trim()}
                    size="lg"
                    className="w-full sm:w-auto min-w-[140px] font-medium"
                  >
                    {isPending ? (
                      <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</>
                    ) : (
                      'Scan Email'
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

              {/* RESULTS */}
              <AnimatePresence mode="wait">
                {result && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.4 }}
                    className="space-y-6"
                  >
                    {/* 1. Verdict Card */}
                    {(() => {
                      const c = classificationColor(result.classification);
                      return (
                        <div className={cn("rounded-xl border shadow-sm overflow-hidden relative", c.bg, c.border)}>
                          <div className={cn("absolute left-0 top-0 bottom-0 w-1", c.bar)} />
                          <div className="p-6 sm:px-8 flex flex-col sm:flex-row items-center justify-between gap-6 pl-8">
                            <div className="flex flex-col items-center sm:items-start text-center sm:text-left">
                              <h2 className={cn("text-3xl font-bold uppercase tracking-tight", c.text)}>
                                {result.classification}
                              </h2>
                              <p className="text-sm text-muted-foreground mt-1">
                                Confidence: {(result.confidence * 100).toFixed(0)}%
                              </p>
                              {/* Language badge */}
                              <div className="flex items-center gap-1.5 mt-2 text-xs text-muted-foreground">
                                <Languages className="w-3.5 h-3.5" />
                                <span>{LANG_FLAGS[result.detectedLanguage] ?? '🌐'} {LANG_LABELS[result.detectedLanguage] ?? result.detectedLanguage} detected</span>
                              </div>
                            </div>
                            <ScoreGauge score={result.riskScore} classification={result.classification} />
                          </div>
                        </div>
                      );
                    })()}

                    {/* 2. Score Breakdown */}
                    <div className="flex flex-col sm:flex-row gap-6 pt-2 pb-4 border-b border-border/50">
                      {[
                        { label: 'Behavioural Analysis', value: result.mlScore, color: 'bg-primary' },
                        { label: 'Pattern Matching', value: result.ruleScore, color: 'bg-accent' },
                        { label: 'Link Risk', value: result.urlScore, color: 'bg-warning' },
                      ].map(({ label, value, color }) => (
                        <div key={label} className="flex-1 space-y-2">
                          <div className="flex justify-between text-xs">
                            <span className="text-muted-foreground font-medium">{label}</span>
                            <span className="text-foreground font-mono">{value.toFixed(0)}%</span>
                          </div>
                          <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
                            <div className={cn("h-full transition-all duration-700", color)} style={{ width: `${value}%` }} />
                          </div>
                        </div>
                      ))}
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
                                <p className="text-sm text-muted-foreground leading-relaxed">{reason.description}</p>
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
                            try { domain = new URL(url.url).hostname; } catch { /* */ }
                            return (
                              <div key={i} className="py-2">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="font-semibold text-sm text-foreground truncate">{domain}</span>
                                  <Badge
                                    variant={url.isSuspicious ? 'destructive' : 'secondary'}
                                    className={cn("text-[10px] px-1.5 py-0 h-4 font-normal shrink-0", !url.isSuspicious && "bg-safe/10 text-safe")}
                                  >
                                    {url.isSuspicious ? 'Suspicious' : 'Safe'}
                                  </Badge>
                                </div>
                                <p className="text-xs font-mono text-muted-foreground truncate" title={url.url}>{url.url}</p>
                                {url.isSuspicious && url.flags.length > 0 && (
                                  <div className="flex items-center gap-1.5 mt-1.5 text-xs text-muted-foreground">
                                    <Flag className="w-3 h-3 text-destructive shrink-0" />
                                    <span>{url.flags.join(' · ')}</span>
                                  </div>
                                )}
                              </div>
                            );
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
                        <div className="bg-card border border-border/60 rounded-xl p-5">
                          <HighlightText text={emailText} spans={result.suspiciousSpans} />
                        </div>
                      </div>
                    )}

                    {/* 7. Before You Act */}
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
            </motion.div>
          )}

          {/* ─── DASHBOARD TAB ─── */}
          {activeTab === 'dashboard' && (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
              className="space-y-8"
            >
              {/* ── Scan Summary Stats ── */}
              <section>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <Scan className="w-4 h-4 text-primary" />
                    Session Overview
                  </h2>
                  {history.length > 0 && (
                    <button
                      onClick={handleClearHistory}
                      className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-destructive transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Reset session
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                  {[
                    { label: 'Total Scanned', value: metrics?.totalScans ?? 0, color: 'text-foreground', sub: 'emails this session' },
                    { label: 'Phishing', value: metrics?.phishingDetected ?? 0, color: 'text-destructive', sub: 'high-risk detected' },
                    { label: 'Suspicious', value: metrics?.suspiciousDetected ?? 0, color: 'text-warning', sub: 'need caution' },
                    { label: 'Safe', value: metrics?.safeDetected ?? 0, color: 'text-safe', sub: 'clean emails' },
                  ].map(({ label, value, color, sub }) => (
                    <div key={label} className="rounded-xl border border-card-border bg-card p-4 text-center">
                      <p className={cn("text-3xl font-bold font-mono", color)}>{value}</p>
                      <p className="text-xs font-medium text-foreground mt-1">{label}</p>
                      <p className="text-[10px] text-muted-foreground mt-0.5">{sub}</p>
                    </div>
                  ))}
                </div>

                {/* Donut chart + risk scale side by side */}
                <div className="rounded-xl border border-card-border bg-card p-5">
                  {(metrics?.totalScans ?? 0) === 0 ? (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                      <BarChart3 className="w-10 h-10 text-muted-foreground/20 mb-3" />
                      <p className="text-sm text-muted-foreground">Scan some emails to see the breakdown chart.</p>
                    </div>
                  ) : (
                    <div className="flex flex-col sm:flex-row items-center gap-6">
                      {/* Donut chart */}
                      <div className="w-full sm:w-64 h-52 shrink-0">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={[
                                { name: 'Phishing', value: metrics?.phishingDetected ?? 0 },
                                { name: 'Suspicious', value: metrics?.suspiciousDetected ?? 0 },
                                { name: 'Safe', value: metrics?.safeDetected ?? 0 },
                              ].filter(d => d.value > 0)}
                              cx="50%"
                              cy="50%"
                              innerRadius={55}
                              outerRadius={80}
                              paddingAngle={3}
                              dataKey="value"
                            >
                              <Cell fill="hsl(var(--destructive))" />
                              <Cell fill="hsl(var(--warning))" />
                              <Cell fill="hsl(var(--safe))" />
                            </Pie>
                            <Tooltip
                              contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: '8px', fontSize: '12px' }}
                              itemStyle={{ color: 'hsl(var(--foreground))' }}
                            />
                            <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '11px' }} />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>

                      {/* Threat breakdown bars */}
                      <div className="flex-1 w-full space-y-4">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Threat breakdown</p>
                        {[
                          { label: 'Phishing', value: metrics?.phishingDetected ?? 0, total: metrics?.totalScans ?? 1, barClass: 'bg-destructive' },
                          { label: 'Suspicious', value: metrics?.suspiciousDetected ?? 0, total: metrics?.totalScans ?? 1, barClass: 'bg-warning' },
                          { label: 'Safe', value: metrics?.safeDetected ?? 0, total: metrics?.totalScans ?? 1, barClass: 'bg-safe' },
                        ].map(({ label, value, total, barClass }) => {
                          const pct = total > 0 ? Math.round((value / total) * 100) : 0;
                          return (
                            <div key={label} className="space-y-1.5">
                              <div className="flex justify-between text-xs">
                                <span className="text-muted-foreground font-medium">{label}</span>
                                <span className="text-foreground font-mono">{value} <span className="text-muted-foreground">({pct}%)</span></span>
                              </div>
                              <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                                <motion.div
                                  className={cn("h-full rounded-full", barClass)}
                                  initial={{ width: 0 }}
                                  animate={{ width: `${pct}%` }}
                                  transition={{ duration: 0.8, ease: "easeOut" }}
                                />
                              </div>
                            </div>
                          );
                        })}

                        <div className="pt-2 border-t border-border/50 text-[11px] text-muted-foreground">
                          <span className="text-warning font-medium">{
                            (metrics?.totalScans ?? 0) > 0
                              ? `${Math.round(((metrics?.phishingDetected ?? 0) + (metrics?.suspiciousDetected ?? 0)) / (metrics?.totalScans ?? 1) * 100)}% of scanned emails were flagged`
                              : 'Scan emails to see statistics'
                          }</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </section>

              {/* ── Risk Scale Reference ── */}
              <section>
                <h2 className="text-base font-semibold text-foreground flex items-center gap-2 mb-4">
                  <TrendingUp className="w-4 h-4 text-primary" />
                  Risk Score Reference
                </h2>
                <div className="rounded-xl border border-card-border bg-card p-5">
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    {[
                      { range: '0 – 30', label: 'Safe', desc: 'No significant threat signals detected', color: 'text-safe', bg: 'bg-safe/10', border: 'border-safe/20' },
                      { range: '31 – 70', label: 'Suspicious', desc: 'Some risk signals — proceed with caution', color: 'text-warning', bg: 'bg-warning/10', border: 'border-warning/20' },
                      { range: '71 – 100', label: 'Phishing', desc: 'High-confidence threat — do not interact', color: 'text-destructive', bg: 'bg-destructive/10', border: 'border-destructive/20' },
                    ].map(({ range, label, desc, color, bg, border }) => (
                      <div key={label} className={cn("rounded-lg border p-3 text-center", bg, border)}>
                        <p className={cn("text-lg font-bold font-mono", color)}>{range}</p>
                        <p className={cn("text-sm font-semibold mt-0.5", color)}>{label}</p>
                        <p className="text-[10px] text-muted-foreground mt-1 leading-relaxed">{desc}</p>
                      </div>
                    ))}
                  </div>
                  <div className="h-3 w-full rounded-full overflow-hidden flex">
                    <div className="flex-[30] bg-safe" />
                    <div className="flex-[40] bg-warning" />
                    <div className="flex-[30] bg-destructive" />
                  </div>
                  <div className="flex justify-between text-[10px] text-muted-foreground mt-1 font-mono">
                    <span>0</span><span>30</span><span>70</span><span>100</span>
                  </div>
                </div>
              </section>

              {/* ── Model Performance ── */}
              <section>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-primary" />
                    Model Performance
                  </h2>
                  <span className="text-xs text-muted-foreground">TF-IDF + Logistic Regression · 11,000+ emails</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'Accuracy', value: metrics?.accuracy, color: 'text-primary', desc: 'Overall correct predictions' },
                    { label: 'Precision', value: metrics?.precision, color: 'text-safe', desc: 'Of flagged emails, truly phishing' },
                    { label: 'Recall', value: metrics?.recall, color: 'text-safe', desc: 'Phishing emails actually caught' },
                    { label: 'F1 Score', value: metrics?.f1Score, color: 'text-accent', desc: 'Precision–recall balance' },
                  ].map(({ label, value, color, desc }) => (
                    <div key={label} className="rounded-xl border border-card-border bg-card p-4">
                      <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wide">{label}</p>
                      <p className={cn("text-2xl font-bold font-mono", color)}>
                        {value !== undefined ? `${(value * 100).toFixed(1)}%` : '—'}
                      </p>
                      <p className="text-[10px] text-muted-foreground mt-1 leading-relaxed">{desc}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-3 rounded-xl border border-card-border bg-card p-4">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs text-muted-foreground font-medium">False Positive Rate</span>
                    <span className="text-xs font-mono text-warning">
                      {metrics ? `${(metrics.falsePositiveRate * 100).toFixed(1)}%` : '—'} <span className="text-muted-foreground">(lower is better)</span>
                    </span>
                  </div>
                  <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-warning rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${(metrics?.falsePositiveRate ?? 0) * 100}%` }}
                      transition={{ duration: 0.8 }}
                    />
                  </div>
                </div>

                {metrics && (
                  <div className="mt-3 space-y-1.5">
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>Overall accuracy</span>
                      <span className="font-mono text-foreground">{(metrics.accuracy * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-primary rounded-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${metrics.accuracy * 100}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                      />
                    </div>
                  </div>
                )}
              </section>

              {/* ── Recent Scans ── */}
              <section>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <History className="w-4 h-4 text-primary" />
                    Recent Scans
                    {history.length > 0 && (
                      <span className="text-xs text-muted-foreground font-normal">({history.length})</span>
                    )}
                  </h2>
                </div>

                {history.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-border/50 p-10 text-center">
                    <ShieldCheck className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">No scans yet this session.</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">Switch to Analyze and scan an email to see history here.</p>
                  </div>
                ) : (
                  <div className="rounded-xl border border-card-border bg-card overflow-hidden">
                    <div className="divide-y divide-border/50">
                      {history.map((item) => {
                        const c = classificationColor(item.classification);
                        return (
                          <div key={item.id} className="flex items-center gap-4 px-4 py-3.5 hover:bg-secondary/30 transition-colors">
                            <div className={cn("w-2 h-2 rounded-full shrink-0", c.bar)} />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-foreground truncate font-mono">{item.emailPreview}</p>
                              <div className="flex items-center gap-3 mt-1 text-[11px] text-muted-foreground">
                                <span>{formatDate(item.timestamp)} · {formatTime(item.timestamp)}</span>
                                <span>{LANG_FLAGS[item.detectedLanguage] ?? '🌐'} {LANG_LABELS[item.detectedLanguage] ?? item.detectedLanguage}</span>
                                {item.urlCount > 0 && <span>{item.urlCount} link{item.urlCount !== 1 ? 's' : ''}</span>}
                              </div>
                            </div>
                            <div className="text-right shrink-0">
                              <p className={cn("text-sm font-bold font-mono", c.text)}>{item.riskScore}</p>
                              <p className={cn("text-[10px] uppercase font-medium tracking-wide", c.text)}>{item.classification}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </section>

              {/* ── Multilingual + India Intelligence ── */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-primary" />
                    Multilingual Detection
                  </h3>
                  <div className="space-y-3">
                    {[
                      { flag: '🇬🇧', lang: 'English', status: 'Full support', desc: 'Urgency, financial, social engineering' },
                      { flag: '🇮🇳', lang: 'Hindi', status: 'Active', desc: 'Devanagari — तुरंत, बंद, इनाम' },
                      { flag: '🇮🇳', lang: 'Telugu', status: 'Active', desc: 'Unicode range matching' },
                    ].map(({ flag, lang, status, desc }) => (
                      <div key={lang} className="flex items-start gap-2">
                        <span className="text-base shrink-0">{flag}</span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm font-medium text-foreground">{lang}</span>
                            <span className="text-[9px] text-safe bg-safe/10 px-1.5 py-0.5 rounded-full">{status}</span>
                          </div>
                          <p className="text-[11px] text-muted-foreground">{desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                    🇮🇳 India-specific patterns
                  </h3>
                  <div className="grid grid-cols-1 gap-1.5 text-xs text-muted-foreground">
                    {[
                      'SBI, HDFC, ICICI, PNB impersonation',
                      'Paytm, PhonePe, GPay reward scams',
                      'UPI KYC fraud patterns',
                      'IRCTC, Aadhaar, PAN phishing',
                      'Hindi & Telugu scam phrases',
                      'Lookalike .xyz, .tk, .ml domains',
                    ].map((item) => (
                      <div key={item} className="flex items-start gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5 text-safe shrink-0 mt-0.5" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="mt-8 py-6 border-t border-border/50 text-center">
        <p className="text-xs text-muted-foreground/60 tracking-wide">
          PhishShield AI — built for India 🇮🇳
        </p>
      </footer>
    </div>
  );
}
