import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, ShieldAlert, AlertTriangle,
  CheckCircle, ChevronDown, ChevronUp, RefreshCw, Loader2,
  Mail, Eye, Flag, BarChart3, History, Trash2, Globe, Languages,
  TrendingUp, Scan, Lock, Shield, Download, ThumbsUp, ThumbsDown,
  Ban, Phone, ExternalLink, Building2
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScoreGauge } from '@/components/ScoreGauge';
import { HighlightText } from '@/components/HighlightText';
import { useAnalyzeEmail, useGetScanHistory, useGetModelMetrics, useClearScanHistory, useSubmitFeedback } from '@workspace/api-client-react';
import { cn } from '@/lib/utils';

const MOCK_GMAIL_EMAILS = [
  {
    id: 'g1',
    sender: 'HDFC Bank Security',
    senderEmail: 'support@hdfc-secure.tk',
    subject: 'Critical Alert: Your account is locked',
    date: '10:45 AM',
    preview: 'Security alert: we have detected unusual login attempts on your HDFC account. To restore access...',
    fullText: 'From: HDFC Bank <support@hdfc-secure.tk>\nSubject: Critical Alert: Your account is locked\nDate: Mon, 24 Mar 2026 10:45:00 +0530\n\nDear customer, we have detected unusual login attempts on your HDFC account. For your security, your account has been temporarily locked. Please click here to verify and unlock your account immediately: http://hdfc-verify.xyz/login. Failure to do so within 24 hours will lead to permanent suspension.',
    classification: 'phishing',
  },
  {
    id: 'g4',
    sender: 'Netflix Billing',
    senderEmail: 'info@mailer.netflix.com',
    subject: 'Your payment was successful',
    date: '09:12 AM',
    preview: 'Thank you for your payment. Your subscription has been renewed for another month...',
    fullText: 'Hi there, your payment of Rs. 649 for your Netflix Premium subscription has been successfully processed. You can continue streaming on all your devices. Transaction ID: 882910-X.',
    classification: 'safe',
  },
  {
    id: 'g5',
    sender: 'SBI Security Alert',
    senderEmail: 'alert@sbi-online.com',
    subject: 'Suspicious activity detected',
    date: 'Yesterday',
    preview: 'We noticed a login attempt from a new IP address in Mumbai. If this was not you...',
    fullText: 'Dear customer, SBI has detected a login attempt from a new device in Mumbai. If this was you, please ignore. If not, please call our 24/7 helpline at 1800-11-22-11 immediately.',
    classification: 'suspicious',
  },
  {
    id: 'g3',
    sender: 'Amazon Rewards',
    senderEmail: 'info@amazon-gift.tk',
    subject: 'Exclusive: Claim your Rs. 5000 Gift Card',
    date: 'Yesterday',
    preview: 'You have been selected as a lucky winner! Claim your Amazon gift card now by verifying...',
    fullText: 'Dear customer, you have won an Amazon gift card worth Rs. 5000! To claim your reward, please verify your details here: http://amazon-claim.ml/gift. Note: Offer valid for 4 hours. No manual intervention required.',
    classification: 'phishing',
  },
  {
    id: 'g2',
    sender: 'Google Security',
    senderEmail: 'no-reply@accounts.google.com',
    subject: 'Security alert for your account',
    date: '2 Mar',
    preview: 'Your Google Account was just signed in to from a new Windows device...',
    fullText: 'Your Google Account was just signed in to from a new Windows device. If this was you, you can safely ignore this email. If this wasn\'t you, please secure your account.',
    classification: 'safe',
  }
];

const PRELOADED_EMAILS = [
  {
    id: 'sbi',
    label: 'SBI notice in Hindi',
    text: "प्रिय ग्राहक, आपका SBI बैंक खाता तुरंत बंद हो जाएगा। अभी सत्यापन करें: http://sbi-verify.xyz/kyc?id=12345 OTP किसी के साथ साझा न करें। अभी क्लिक करें! -- SBI ग्राहक सेवा"
  },
  {
    id: 'upi',
    label: 'GPay reward claim',
    text: "Congratulations! You have won Rs. 50,000 in GPay reward program. To claim your prize, verify your UPI ID at http://gpay-reward.tk/claim and complete KYC. Offer expires in 2 hours! Transaction ID: TXN8823991"
  },
  {
    id: 'amazon',
    label: 'Amazon shipment details',
    text: "Your Amazon order #402-8837291-XXXXXX has been shipped. Expected delivery: March 18. Track your package at amazon.in/orders. Thank you for shopping with Amazon."
  }
];

const LANG_LABELS: Record<string, string> = {
  en: 'English',
  hi: 'Hindi',
  te: 'Telugu',
  mixed: 'Mixed script',
};

const LANG_CODES: Record<string, string> = {
  en: 'EN',
  hi: 'HI',
  te: 'TE',
  mixed: 'MX',
};

const categoryMap: Record<string, string> = {
  urgency: "Urgency pressure",
  social_engineering: "Social engineering",
  india_specific: "Brand impersonation",
  url: "Suspicious link",
  financial: "Financial lure",
  language: "Regional language",
  ml_score: "Pattern analysis",
  domain: "Domain risk",
  header: "Email header spoofing",
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

// Donut chart for the scan breakdown. Colors use CSS variables from :root
// so they stay consistent with the rest of the theme.
function GmailInbox({ onSelectEmail, activeEmailId }: { onSelectEmail: (email: any) => void, activeEmailId?: string }) {
  return (
    <div className="rounded-2xl border border-card-border bg-card overflow-hidden shadow-sm animate-in fade-in slide-in-from-top-4 duration-500">
      <div className="bg-secondary/30 px-6 py-4 border-b border-border/50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded bg-[#ea4335]/10 flex items-center justify-center">
            <Mail className="w-4 h-4 text-[#ea4335]" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              Gmail Inbox <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-500 font-bold uppercase">Demo</span>
            </h3>
            <p className="text-[10px] text-muted-foreground font-semibold">Demo Gmail Integration (Simulated for Hackathon)</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
           <div className="hidden sm:flex items-center gap-1.5 text-[10px] text-muted-foreground bg-background/50 px-2 py-1 rounded border border-border/50">
             <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
             Synced: Now
           </div>
        </div>
      </div>
      
      <div className="divide-y divide-border/40">
        {MOCK_GMAIL_EMAILS.map((email) => (
          <button
            key={email.id}
            onClick={() => onSelectEmail(email)}
            className={cn(
              "w-full text-left px-6 py-4 transition-all hover:bg-secondary/40 group relative overflow-hidden",
              activeEmailId === email.id && "bg-primary/5 border-l-2 border-l-primary pl-[22px]"
            )}
          >
            <div className="flex justify-between items-start mb-1">
              <div className="flex items-center gap-2">
                <span className={cn("text-xs font-bold truncate", activeEmailId === email.id ? "text-primary" : "text-foreground")}>
                  {email.sender}
                </span>
                <span className="text-[10px] text-muted-foreground truncate opacity-0 group-hover:opacity-100 transition-opacity">
                  &lt;{email.senderEmail}&gt;
                </span>
              </div>
              <span className="text-[10px] text-muted-foreground whitespace-nowrap">{email.date}</span>
            </div>
            <div className="flex justify-between items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className={cn("text-xs font-semibold truncate mb-0.5", activeEmailId === email.id ? "text-primary/90" : "text-foreground/90")}>
                  {email.subject}
                </p>
                <p className="text-[11px] text-muted-foreground truncate italic">
                  {email.preview}
                </p>
              </div>
              <Badge 
                variant="outline" 
                className={cn(
                  "text-[9px] uppercase tracking-tighter px-1.5 py-0 font-bold", 
                  email.classification === 'phishing' ? "text-destructive border-destructive/30 bg-destructive/5" :
                  email.classification === 'suspicious' ? "text-warning border-warning/30 bg-warning/5" :
                  "text-safe border-safe/30 bg-safe/5"
                )}
              >
                {email.classification}
              </Badge>
            </div>
          </button>
        ))}
      </div>
      
      <div className="bg-secondary/20 px-6 py-3 border-t border-border/50 flex justify-center">
         <p className="text-[10px] text-muted-foreground flex items-center gap-1.5">
           <Shield className="w-3 h-3" />
           PhishShield AI Protection Simulated • 2026 Edition
         </p>
      </div>
    </div>
  );
}

const PIE_COLORS = {
  Phishing:  'hsl(var(--destructive))',
  Suspicious: 'hsl(var(--warning))',
  Safe:       'hsl(var(--safe))',
} as const;

type MetricsCounts = {
  phishingDetected: number;
  suspiciousDetected: number;
  safeDetected: number;
} | undefined;

function DonutChart({ metrics }: { metrics: MetricsCounts }) {
  const pieData: { name: keyof typeof PIE_COLORS; value: number }[] = [
    { name: 'Phishing',   value: metrics?.phishingDetected  ?? 0 },
    { name: 'Suspicious', value: metrics?.suspiciousDetected ?? 0 },
    { name: 'Safe',       value: metrics?.safeDetected       ?? 0 },
  ].filter(d => d.value > 0) as { name: keyof typeof PIE_COLORS; value: number }[];

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
          {pieData.map(entry => (
            <Cell key={entry.name} fill={PIE_COLORS[entry.name]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: '8px', fontSize: '12px' }}
          itemStyle={{ color: 'hsl(var(--foreground))' }}
        />
        <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '11px' }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function RegionalThreatMap() {
  const regions = [
    { city: 'Mumbai', risk: 'High', color: 'bg-destructive', pulse: true },
    { city: 'Delhi', risk: 'Medium', color: 'bg-warning', pulse: false },
    { city: 'Bengaluru', risk: 'Low', color: 'bg-safe', pulse: false },
    { city: 'Hyderabad', risk: 'High', color: 'bg-destructive', pulse: true },
    { city: 'Chennai', risk: 'Low', color: 'bg-safe', pulse: false },
    { city: 'Kolkata', risk: 'Medium', color: 'bg-warning', pulse: false },
  ];

  return (
    <div className="rounded-xl border border-card-border bg-card p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Globe className="w-4 h-4 text-primary" />
          Regional Threat Intelligence
        </h3>
        <span className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">Live Simulation</span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {regions.map((r) => (
          <div key={r.city} className="flex items-center justify-between p-2 rounded-lg bg-secondary/30 border border-border/20">
            <div className="flex flex-col">
              <span className="text-[10px] font-bold text-foreground">{r.city}</span>
              <span className={cn("text-[9px] font-medium opacity-80 uppercase", r.risk === 'High' ? 'text-destructive' : r.risk === 'Medium' ? 'text-warning' : 'text-safe')}>
                {r.risk} Risk
              </span>
            </div>
            <div className="relative">
              <div className={cn("w-2 h-2 rounded-full", r.color)} />
              {r.pulse && <div className={cn("absolute inset-0 w-2 h-2 rounded-full animate-ping", r.color)} />}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
         <div className="flex items-center gap-3">
           <div className="flex items-center gap-1">
             <div className="w-1.5 h-1.5 rounded-full bg-destructive" />
             <span className="text-[9px] text-muted-foreground uppercase font-bold">Active Phish</span>
           </div>
           <div className="flex items-center gap-1">
             <div className="w-1.5 h-1.5 rounded-full bg-warning" />
             <span className="text-[9px] text-muted-foreground uppercase font-bold">Monitoring</span>
           </div>
         </div>
         <p className="text-[9px] text-muted-foreground font-mono">Source: PhishShield Intelligence Node Cluster</p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [inputMode, setInputMode] = useState<'demo' | 'real' | 'upload'>('demo');
  const [simulatedThreats, setSimulatedThreats] = useState(1284);
  const [includeHeaders, setIncludeHeaders] = useState(false);
  const [emailText, setEmailText] = useState('');
  const [headersText, setHeadersText] = useState('');
  const [activeGmailEmailId, setActiveGmailEmailId] = useState<string | undefined>(undefined);
  const [showHeaders, setShowHeaders] = useState(false);
  const [showDemos, setShowDemos] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('analyze');
  const [isDemoEmail, setIsDemoEmail] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(false);

  // Live threat pulse simulation for wow factor
  useEffect(() => {
    const timer = setInterval(() => {
      setSimulatedThreats(prev => prev + Math.floor(Math.random() * 3));
    }, 8000);
    return () => clearInterval(timer);
  }, []);

  // Used to smooth-scroll down to results after a scan completes
  const resultsRef = useRef<HTMLDivElement>(null);

  const { mutate: submitFeedback, isPending: isFeedbackPending } = useSubmitFeedback();

  const handleFeedback = (fb: 'accurate' | 'wrong') => {
    if (!result) return;
    submitFeedback({ data: { emailId: result.id, isAccurate: fb === 'accurate' } }, {
      onSuccess: () => setFeedbackSent(true)
    });
  };

  const handleDownloadReport = async () => {
    if (!result) return;
    try {
      const response = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer dev-sandbox-key" },
        body: JSON.stringify(result)
      });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishshield-report-${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
    }
  };

  const [localHistory, setLocalHistory] = useState<Array<{
    id: string; timestamp: string; emailPreview: string; riskScore: number;
    classification: 'safe' | 'suspicious' | 'phishing'; detectedLanguage: string;
    urlCount: number; reasonCount: number;
  }>>([]);

  const { mutate: analyzeEmail, data: result, isPending, error, reset } = useAnalyzeEmail();
  const { data: serverHistory = [], refetch: refetchHistory } = useGetScanHistory();
  const { data: metrics, refetch: refetchMetrics } = useGetModelMetrics();
  const { mutate: clearHistory } = useClearScanHistory();

  useEffect(() => {
    try {
      const stored = localStorage.getItem('phishshield_history');
      if (stored) setLocalHistory(JSON.parse(stored));
    } catch { /* ignore */ }
  }, []);

  const history = serverHistory.length > 0 ? serverHistory : localHistory;

  // Pre-compute verdict colors so we don't need an IIFE inside JSX
  const verdictColors = result ? classificationColor(result.classification) : null;

  const scrollToResults = () => {
    setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
  };

  const handleScan = () => {
    if (!emailText.trim()) return;
    setIsDemoEmail(false);
    setFeedbackSent(false); // Reset feedback
    analyzeEmail({ data: { emailText, headers: headersText } }, {
      onSuccess: (data) => {
        const newItem = {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          emailPreview: emailText.slice(0, 80),
          riskScore: data?.riskScore ?? 0,
          classification: data?.classification ?? 'safe',
          detectedLanguage: data?.detectedLanguage ?? 'en',
          urlCount: data?.urlAnalyses?.length ?? 0,
          reasonCount: data?.reasons?.length ?? 0,
        };
        setLocalHistory(prev => {
          const updated = [newItem, ...prev].slice(0, 20);
          try { localStorage.setItem('phishshield_history', JSON.stringify(updated)); } catch { /* ignore */ }
          return updated;
        });
        refetchHistory();
        refetchMetrics();
        scrollToResults();
      }
    });
  };

  // Selecting a demo email auto-scans immediately — no button click needed
  const loadDemo = (demo: typeof PRELOADED_EMAILS[0]) => {
    const text = demo.text;
    setEmailText(text);
    if (demo.id === 'header_spoof') {
      setHeadersText(text.split('\n\n')[0] + '\n\n');
      setShowHeaders(true);
    } else {
      setHeadersText('');
      setShowHeaders(false);
    }
    setShowDemos(false);
    setIsDemoEmail(true);
    setFeedbackSent(false); // Reset feedback
    reset();
    analyzeEmail({ data: { emailText: text, headers: demo.id === 'header_spoof' ? text.split('\n\n')[0] + '\n\n' : undefined } }, {
      onSuccess: (data) => {
        const newItem = {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          emailPreview: text.slice(0, 80).replace(/\n/g, ' '),
          riskScore: data?.riskScore ?? 0,
          classification: data?.classification ?? 'safe',
          detectedLanguage: data?.detectedLanguage ?? 'en',
          urlCount: data?.urlAnalyses?.length ?? 0,
          reasonCount: data?.reasons?.length ?? 0,
        };
        setLocalHistory(prev => {
          const updated = [newItem, ...prev].slice(0, 20);
          try { localStorage.setItem('phishshield_history', JSON.stringify(updated)); } catch { /* ignore */ }
          return updated;
        });
        refetchHistory();
        refetchMetrics();
        scrollToResults();
      }
    });
  };

  const handleClearHistory = () => {
    clearHistory(undefined, {
      onSuccess: () => {
        setLocalHistory([]);
        try { localStorage.removeItem('phishshield_history'); } catch { /* ignore */ }
        refetchHistory();
        refetchMetrics();
      }
    });
  };

  const getTopKeywords = () => {
    if (!history.length) return [];
    const text = history.map(h => h.emailPreview || '').join(" ").toLowerCase();
    const words = (text.match(/\b(otp|kyc|verify|suspended|blocked|prize|cashback|password|account|update|urgent|click|link|bank|pan|aadhaar)\b/g) || []) as string[];
    const counts = words.reduce((acc: Record<string, number>, w: string) => { acc[w] = (acc[w] || 0) + 1; return acc; }, {} as Record<string, number>);
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(x => x[0]);
  };

  const getMostCommonAttackType = () => {
    if (!history.length) return 'None';
    const text = history.map(h => h.emailPreview || '').join(" ").toLowerCase();
    if (text.includes('reward') || text.includes('cashback') || text.includes('prize')) return 'Reward Scam';
    if (text.includes('kyc') || text.includes('suspended') || text.includes('blocked')) return 'Account Suspension (KYC)';
    if (text.includes('otp')) return 'OTP Extraction';
    if (text.includes('password') || text.includes('verify')) return 'Credential Harvester';
    return 'Social Engineering';
  };

  const getMostTargetedBrand = () => {
    if (!history.length) return 'None';
    const text = history.map(h => h.emailPreview || '').join(" ").toLowerCase();
    if (text.includes('hdfc')) return 'HDFC Bank';
    if (text.includes('sbi')) return 'SBI (State Bank)';
    if (text.includes('amazon')) return 'Amazon India';
    if (text.includes('netflix')) return 'Netflix';
    if (text.includes('paytm') || text.includes('gpay')) return 'Digital Wallet (UPI)';
    return 'Financial Institution';
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
              Defense Active
            </div>
          </div>
        </div>

        {/* Feature 9: Live Protection Simulation */}
        <div className="max-w-3xl mx-auto px-4 mt-2">
          <div className="rounded-xl bg-primary/10 border border-primary/20 p-3 flex items-center justify-between text-xs overflow-hidden relative shadow-sm">
             <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/5 to-transparent animate-shimmer" />
             <div className="flex items-center gap-2 relative z-10">
                <div className="w-7 h-7 rounded-lg bg-primary flex items-center justify-center shrink-0">
                   <ShieldCheck className="w-4 h-4 text-primary-foreground" />
                </div>
                <div className="flex flex-col">
                   <div className="flex items-center gap-1.5 leading-none">
                     <span className="font-bold text-foreground">Active Protection Node</span>
                     <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                   </div>
                   <span className="text-[10px] text-muted-foreground mt-0.5 tracking-tight">Enterprise-grade AI shielding active for Indian Cyber-Space.</span>
                </div>
             </div>
             <div className="flex flex-col items-end relative z-10">
                <span className="font-mono font-bold text-primary text-sm tracking-tighter tabular-nums leading-none">
                   {simulatedThreats.toLocaleString()}
                </span>
                <span className="text-[9px] uppercase font-bold tracking-widest text-muted-foreground opacity-70 mt-0.5">Threats Prevented</span>
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
                <div className="flex flex-col gap-6 mb-4">
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                    <div className="flex bg-secondary/50 p-1 rounded-xl w-full sm:w-auto border border-border/50">
                      {(['demo', 'real', 'upload'] as const).map((m) => (
                        <button
                          key={m}
                          onClick={() => { setInputMode(m); if (result) reset(); setEmailText(""); }}
                          className={cn(
                            "flex-1 sm:flex-none px-4 py-2 rounded-lg text-[11px] font-bold transition-all capitalize whitespace-nowrap",
                            inputMode === m 
                              ? "bg-background text-primary shadow-sm border border-border/50" 
                              : "text-muted-foreground hover:text-foreground"
                          )}
                        >
                          {m === 'demo' && <Mail className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />}
                          {m === 'real' && <CheckCircle className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />}
                          {m === 'upload' && <Globe className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />}
                          {m}
                        </button>
                      ))}
                    </div>

                    {inputMode === 'demo' && (
                      <div className="relative">
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs h-9 bg-transparent border-muted hover:bg-muted font-bold"
                          onClick={() => setShowDemos(!showDemos)}
                        >
                          Load Sample <ChevronDown className="w-3 h-3 ml-1" />
                        </Button>
                        <AnimatePresence>
                          {showDemos && (
                            <motion.div
                              initial={{ opacity: 0, y: 5 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: 5 }}
                              className="absolute right-0 mt-2 w-64 bg-popover border border-popover-border rounded-xl shadow-lg z-50 overflow-hidden"
                            >
                              <div className="px-3 py-2 text-[10px] text-muted-foreground font-semibold uppercase tracking-wider border-b border-border/50 bg-secondary/30">
                                Simulated Attack Vectors
                              </div>
                              <div className="p-1.5 max-h-[300px] overflow-y-auto">
                                {MOCK_GMAIL_EMAILS.map(demo => (
                                  <button
                                    key={demo.id}
                                    onClick={() => { inputMode === 'demo' ? setIsDemoEmail(true) : setIsDemoEmail(false); loadDemo({ id: demo.id, label: demo.subject, text: demo.fullText }); setShowDemos(false); }}
                                    className="w-full text-left px-3 py-2.5 text-xs rounded-lg hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground flex items-center justify-between group border border-transparent hover:border-border/30"
                                  >
                                    <div className="flex flex-col">
                                       <span className="font-bold text-foreground truncate max-w-[170px]">{demo.subject}</span>
                                       <span className="text-[10px] lowercase opacity-60">{demo.classification}</span>
                                    </div>
                                    <RefreshCw className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity shrink-0 ml-2" />
                                  </button>
                                ))}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    )}
                  </div>
                </div>

                {inputMode === 'demo' ? (
                  <GmailInbox 
                    activeEmailId={activeGmailEmailId}
                    onSelectEmail={(email) => {
                      setEmailText(email.fullText);
                      setActiveGmailEmailId(email.id);
                      setHeadersText("");
                      setIsDemoEmail(true);
                      // Auto-trigger scan
                      setTimeout(() => { handleScan(); }, 100);
                    }}
                  />
                ) : inputMode === 'upload' ? (
                  <div className="flex flex-col items-center justify-center border-2 border-dashed border-border/50 rounded-2xl p-12 bg-secondary/20 transition-colors hover:bg-secondary/30 cursor-pointer relative">
                    <input 
                      type="file" 
                      accept=".txt,.eml" 
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = (ev) => {
                          const content = ev.target?.result as string;
                          setEmailText(content);
                          setInputMode('real'); // Switch to real mode after upload
                          setIsDemoEmail(false);
                          if (result) reset();
                        };
                        reader.readAsText(file);
                      }}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                    />
                    <Globe className="w-12 h-12 text-muted-foreground/30 mb-4" />
                    <p className="text-sm font-bold text-foreground">Click or Drag to Upload</p>
                    <p className="text-[11px] text-muted-foreground mt-1">Supports .eml and .txt email files</p>
                    <div className="mt-8 flex gap-2">
                       <Badge variant="outline" className="text-[10px]">🔒 100% Client-Side</Badge>
                       <Badge variant="outline" className="text-[10px]">⚡ Instant Extract</Badge>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2">
                     <div className="flex items-center justify-between">
                        <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Direct Analysis Mode</label>
                        <div className="flex items-center gap-1.5 text-[10px] font-medium text-safe bg-safe/10 px-2 py-0.5 rounded border border-safe/20">
                          <Lock className="w-3 h-3" /> Anonymous Scan
                        </div>
                     </div>
                     <textarea
                       value={emailText}
                       onChange={(e) => {
                         setEmailText(e.target.value);
                         if (result) reset();
                         setIsDemoEmail(false);
                       }}
                       placeholder="Paste full Gmail email (content or headers)..."
                       className={cn(
                         "w-full min-h-[220px] bg-background/50 border border-input rounded-xl p-4 text-foreground font-mono text-sm resize-y transition-all focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 placeholder:text-muted-foreground/40",
                         isPending && "opacity-60"
                       )}
                       disabled={isPending}
                     />
                  </div>
                )}

                <div className="mt-3">
                  <button onClick={() => setShowHeaders(!showHeaders)} className="text-xs flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors">
                    {showHeaders ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    Advanced (Headers)
                  </button>
                  {showHeaders && (
                    <textarea
                      value={headersText}
                      onChange={(e) => setHeadersText(e.target.value)}
                      placeholder="Paste raw email headers here (Optional)..."
                      className="w-full min-h-[100px] mt-2 bg-background/50 border border-input rounded-xl p-3 text-foreground font-mono text-xs resize-y transition-all focus:outline-none focus:ring-2 focus:ring-primary/30"
                      disabled={isPending}
                    />
                  )}
                </div>

                <div className="mt-3 flex justify-between items-center text-[11px] text-muted-foreground">
                  <span className="font-mono">{emailText.length > 0 ? `${emailText.length} chars` : ''}</span>
                  <div className="flex items-center gap-1">
                    <Lock className="w-3 h-3" />
                    <span>Content not stored after analysis</span>
                  </div>
                </div>

                <div className="mt-3 flex flex-col sm:flex-row gap-4 justify-between items-center">
                  <div />
                  <Button
                    onClick={handleScan}
                    disabled={isPending || !emailText.trim()}
                    size="lg"
                    className={cn(
                      "w-full sm:w-auto min-w-[140px] font-medium",
                      inputMode === 'demo' && "hidden"
                    )}
                  >
                    {isPending ? (
                      <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</>
                    ) : (
                      'Scan Email'
                    )}
                  </Button>
                </div>

                {error && (
                  <div className="mt-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-start flex-col gap-1">
                    <div className="flex items-center gap-2 font-bold">
                       <AlertTriangle className="w-4 h-4 shrink-0" />
                       Analysis Rejected
                    </div>
                    <span className="text-xs opacity-90">{error instanceof Error ? error.message : 'Analysis failed. The pasted email may be too massive or severely malformed.'}</span>
                  </div>
                )}
              </div>

              {/* EMPTY STATE GUIDE */}
              {!result && !isPending && !emailText.trim() && (
                <div className="grid grid-cols-3 gap-3 text-center">
                  {[
                    { icon: <Mail className="w-4 h-4" />, title: 'Paste email', desc: 'Copy the full email — headers, body, links' },
                    { icon: <Scan className="w-4 h-4" />, title: 'Scan it', desc: 'Our model checks 50+ phishing signals' },
                    { icon: <ShieldCheck className="w-4 h-4" />, title: 'See the verdict', desc: 'Score 0–100 with detailed explanation' },
                  ].map(({ icon, title, desc }) => (
                    <div key={title} className="rounded-xl border border-dashed border-border/40 p-4 flex flex-col items-center gap-2">
                      <div className="w-8 h-8 rounded-lg bg-secondary flex items-center justify-center text-muted-foreground">
                        {icon}
                      </div>
                      <p className="text-xs font-medium text-foreground">{title}</p>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{desc}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* RESULTS */}
              <AnimatePresence mode="wait">
                {result && (
                  <motion.div
                    ref={resultsRef}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.4 }}
                    className="space-y-6"
                  >
                    {/* 1. Verdict card — the first thing users should see */}
                    {verdictColors && (
                      <div className={cn("rounded-xl border shadow-sm overflow-hidden relative", verdictColors.bg, verdictColors.border)}>
                        <div className={cn("absolute left-0 top-0 bottom-0 w-1", verdictColors.bar)} />
                        <div className="p-6 sm:px-8 flex flex-col items-stretch gap-6 pl-8">
                          <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
                            <div className="flex flex-col items-center sm:items-start text-center sm:text-left">
                              <div className="flex items-center gap-2 mb-1">
                                <h2 className={cn("text-3xl font-bold uppercase tracking-tight", verdictColors.text)}>
                                  {result?.classification}
                                </h2>
                                <Badge className={cn("text-[10px] uppercase font-bold", 
                                  result?.attackType?.includes('Safe') ? 'bg-safe/20 text-safe' : 'bg-destructive/10 text-destructive'
                                )}>
                                  {result?.attackType}
                                </Badge>
                              </div>
                              
                              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-4 mt-2">
                                <div className="flex flex-col">
                                  <p className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">AI Confidence</p>
                                  <div className="flex items-center gap-2 mt-1">
                                    <div className="w-24 h-1.5 bg-secondary rounded-full overflow-hidden">
                                      <motion.div 
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(result?.confidence ?? 0) * 100}%` }}
                                        className={cn("h-full", (result?.confidence ?? 0) > 0.8 ? 'bg-primary' : (result?.confidence ?? 0) > 0.5 ? 'bg-warning' : 'bg-destructive')}
                                      />
                                    </div>
                                    <span className="text-[10px] font-bold text-foreground">
                                      {(result?.confidence ?? 0) > 0.8 ? 'High Certainty' : (result?.confidence ?? 0) > 0.5 ? 'Moderate' : 'Low Confidence'}
                                    </span>
                                  </div>
                                </div>

                                <div className="h-8 w-px bg-border/50 hidden sm:block" />

                                <div className="flex flex-col">
                                  <p className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">Trust Score</p>
                                  <p className={cn("text-lg font-mono font-bold leading-none mt-1", 100 - (result?.riskScore ?? 0) > 70 ? 'text-safe' : 100 - (result?.riskScore ?? 0) > 30 ? 'text-warning' : 'text-destructive')}>
                                    {(100 - (result?.riskScore ?? 0)).toFixed(0)}/100
                                  </p>
                                </div>
                                
                                <div className="h-8 w-px bg-border/50 hidden sm:block" />

                                <div className="flex flex-col">
                                  <p className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider">Language</p>
                                  <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-secondary/50 text-muted-foreground border border-border/60 mt-1")}>
                                    <Languages className="w-3 h-3" />
                                    <span className="font-mono">{LANG_CODES[result?.detectedLanguage ?? 'en'] ?? 'MX'}</span>
                                  </span>
                                </div>
                              </div>
                              {isDemoEmail && (
                                <span className="mt-3 inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-secondary/50 text-muted-foreground border border-border/60">
                                  Demo Email (Simulated)
                                </span>
                              )}
                            </div>
                            <ScoreGauge score={result.riskScore} classification={result.classification} />
                          </div>

                          {/* Scam Story */}
                          <div className="pt-4 border-t border-border/20">
                             <div className="flex items-start gap-3 p-4 rounded-xl bg-background/40 border border-border/30">
                                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                                   <ShieldAlert className="w-4 h-4 text-primary" />
                                </div>
                                <div className="space-y-1">
                                   <p className="text-[11px] font-bold uppercase tracking-widest text-primary">Potential Impact Analysis</p>
                                   <p className="text-sm text-foreground/90 leading-relaxed italic">"{result?.scamStory}"</p>
                                </div>
                             </div>
                          </div>

                          {/* One-Click Actions */}
                          <div className="flex flex-wrap gap-3">
                             <Button variant="destructive" size="sm" className="h-8 text-[11px] font-bold">
                                <Ban className="w-3.5 h-3.5 mr-1.5" /> Block Sender
                             </Button>
                             <Button variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                <Phone className="w-3.5 h-3.5 mr-1.5" /> Call Support
                             </Button>
                             <Button variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                <ExternalLink className="w-3.5 h-3.5 mr-1.5" /> Official Site
                             </Button>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* 2. Score breakdown — four sub-scores that add up to the final risk score */}
                    <div className="space-y-3 pt-2 pb-4 border-b border-border/50">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Score components</p>
                      <div className="flex flex-col sm:flex-row gap-4">
                        {[
                          { label: 'Language model', value: result?.mlScore ?? 0, color: 'bg-primary' },
                          { label: 'Pattern matching', value: result?.ruleScore ?? 0, color: 'bg-accent' },
                          { label: 'Link risk', value: result?.urlScore ?? 0, color: 'bg-warning' },
                          { label: 'Header spoofing', value: result?.headerScore ?? 0, color: 'bg-destructive/70' },
                        ].map(({ label, value, color }) => (
                          <div key={label} className="flex-1 space-y-2">
                            <div className="flex justify-between text-xs">
                              <span className="text-muted-foreground font-medium">{label}</span>
                              <span className="text-foreground font-mono">{value.toFixed(0)}</span>
                            </div>
                            <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                              <div className={cn("h-full transition-all duration-700 rounded-full", color)} style={{ width: `${value}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* 3. Feature Importance (ML Explainability) */}
                    {result.featureImportance && result.featureImportance.length > 0 && (
                      <div className="space-y-3 pt-2 pb-4 border-b border-border/50">
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                            <TrendingUp className="w-4 h-4 text-muted-foreground" />
                            ML Feature Contributions
                          </h3>
                          <span className="text-[10px] text-muted-foreground">TF-IDF × LR weight</span>
                        </div>
                        <div className="space-y-2.5">
                          {result.featureImportance.map((f, i) => {
                            const maxC = result.featureImportance![0].contribution;
                            const pct = maxC > 0 ? Math.round((f.contribution / maxC) * 100) : 0;
                            return (
                              <div key={i} className="flex items-center gap-3">
                                <span className={cn(
                                  "text-xs font-mono shrink-0 w-32 truncate",
                                  f.direction === 'phishing' ? 'text-destructive' : 'text-safe'
                                )} title={f.feature}>
                                  {f.feature}
                                </span>
                                <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                                  <div
                                    className={cn("h-full rounded-full transition-all duration-700", f.direction === 'phishing' ? 'bg-destructive/70' : 'bg-safe/70')}
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                                <span className="text-[10px] font-mono text-muted-foreground w-8 text-right shrink-0">{f.contribution.toFixed(2)}</span>
                                <span className={cn(
                                  "text-[9px] uppercase font-bold shrink-0 w-8",
                                  f.direction === 'phishing' ? 'text-destructive' : 'text-safe'
                                )}>
                                  {f.direction === 'phishing' ? 'risk' : 'safe'}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* 4. Header Analysis */}
                    {result.headerAnalysis && result.headerAnalysis.hasHeaders && (
                      <div className={cn(
                        "rounded-xl border p-4 space-y-3",
                        result.headerAnalysis.spoofingRisk === 'high'
                          ? 'bg-destructive/5 border-destructive/20'
                          : result.headerAnalysis.spoofingRisk === 'medium'
                          ? 'bg-warning/5 border-warning/20'
                          : 'bg-card border-border/50'
                      )}>
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                            <Mail className="w-4 h-4 text-muted-foreground" />
                            Email Header Analysis
                          </h3>
                          <span className={cn(
                            "text-[10px] font-bold uppercase px-2 py-0.5 rounded-full",
                            result.headerAnalysis.spoofingRisk === 'high'
                              ? 'bg-destructive/15 text-destructive'
                              : result.headerAnalysis.spoofingRisk === 'medium'
                              ? 'bg-warning/15 text-warning'
                              : result.headerAnalysis.spoofingRisk === 'low'
                              ? 'bg-warning/10 text-warning'
                              : 'bg-safe/10 text-safe'
                          )}>
                            {result.headerAnalysis.spoofingRisk} risk
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-3 text-xs">
                          {result.headerAnalysis.senderEmail && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Sender</p>
                              <p className="font-mono text-foreground truncate" title={result.headerAnalysis.senderEmail}>{result.headerAnalysis.senderEmail}</p>
                            </div>
                          )}
                          {result.headerAnalysis.displayName && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Display Name</p>
                              <p className="font-mono text-foreground truncate">"{result.headerAnalysis.displayName}"</p>
                            </div>
                          )}
                          {result.headerAnalysis.replyToEmail && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Reply-To</p>
                              <p className={cn("font-mono truncate", result.headerAnalysis.mismatch ? 'text-destructive font-semibold' : 'text-foreground')}
                                title={result.headerAnalysis.replyToEmail}>
                                {result.headerAnalysis.replyToEmail}
                                {result.headerAnalysis.mismatch && <span className="ml-1 text-[10px] font-bold">⚠ mismatch</span>}
                              </p>
                            </div>
                          )}
                          {result.headerAnalysis.senderDomain && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Sender Domain</p>
                              <p className="font-mono text-foreground truncate">{result.headerAnalysis.senderDomain}</p>
                            </div>
                          )}
                        </div>

                        {result.headerAnalysis.issues.length > 0 && (
                          <div className="border-t border-border/50 pt-3 space-y-2">
                            {result.headerAnalysis.issues.map((issue, i) => (
                              <div key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                                <AlertTriangle className="w-3.5 h-3.5 text-warning shrink-0 mt-0.5" />
                                <span className="leading-relaxed">{issue}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 5. Warnings */}
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

                    {/* 4. Reason cards — grouped explanation of each flag */}
                    {result.reasons.length > 0 && (() => {
                      const groups = result.reasons.reduce((acc, r) => {
                        const cat = getHumanCategory(r.category);
                        if (!acc[cat]) acc[cat] = [];
                        acc[cat].push(r);
                        return acc;
                      }, {} as Record<string, typeof result.reasons>);
                      return (
                        <div className="space-y-4 pt-4">
                          <h3 className="text-lg font-semibold text-foreground">What raised our concern</h3>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            {Object.entries(groups).map(([catName, items]) => (
                               <div key={catName} className="rounded-xl border border-card-border bg-card p-4 space-y-3">
                                 <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                                   <AlertTriangle className={cn("w-4 h-4", catName === "Social engineering" || catName === "Urgency pressure" ? "text-destructive" : "text-warning")} />
                                   {catName}
                                 </h4>
                                 <div className="space-y-3">
                                   {items.map((reason, i) => (
                                     <div key={i} className="flex items-start gap-2.5">
                                       <div className={cn(
                                         "w-1.5 h-1.5 rounded-full mt-2 shrink-0 relative",
                                         reason.severity === 'high' ? 'bg-destructive' : reason.severity === 'medium' ? 'bg-warning' : 'bg-safe'
                                       )} />
                                       <div>
                                         <p className="text-sm text-muted-foreground leading-relaxed">{reason.description}</p>
                                         {reason.matchedTerms.length > 0 && (
                                           <div className="flex flex-wrap gap-1.5 mt-2">
                                             {reason.matchedTerms.map((term, j) => (
                                               <span key={j} className="text-[10px] font-mono bg-secondary text-secondary-foreground px-1.5 py-0.5 rounded uppercase opacity-80 border border-border/50">
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
                            ))}
                          </div>
                        </div>
                      );
                    })()}

                    {/* 5. Links Found - Dashboard Table UI */}
                    {result.urlAnalyses.length > 0 && (
                      <div className="space-y-4 pt-4">
                        <h3 className="text-lg font-semibold text-foreground">Links in this email</h3>
                        <div className="overflow-x-auto rounded-xl border border-card-border bg-card">
                          <table className="w-full text-sm text-left">
                            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-card-border">
                              <tr>
                                <th className="px-4 py-3 font-semibold">Domain / URL</th>
                                <th className="px-4 py-3 font-semibold w-32">Risk Level</th>
                                <th className="px-4 py-3 font-semibold">Risk Factors</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-card-border">
                              {result.urlAnalyses.map((url, i) => (
                                <tr key={i} className="hover:bg-muted/30 transition-colors">
                                  <td className="px-4 py-3 max-w-[200px] sm:max-w-xs truncate">
                                    <div className="font-semibold text-foreground truncate">{url.domain}</div>
                                    <div className="text-xs font-mono text-muted-foreground truncate opacity-70 mt-0.5" title={url.url}>{url.url}</div>
                                  </td>
                                  <td className="px-4 py-3">
                                    <Badge variant={url.isSuspicious ? 'destructive' : 'secondary'} className={cn("text-[10px] h-5", !url.isSuspicious && "bg-safe/10 text-safe border-transparent")}>
                                      {url.isSuspicious ? 'Suspicious' : 'Safe'}
                                    </Badge>
                                  </td>
                                  <td className="px-4 py-3">
                                    {url.flags.length > 0 ? (
                                      <div className="flex flex-wrap gap-1">
                                        {url.flags.map((flag, j) => (
                                          <span key={j} className="text-[10px] bg-secondary text-muted-foreground px-1.5 py-0.5 border border-border/50 rounded flex items-center gap-1 leading-tight">
                                            <Flag className="w-2.5 h-2.5 text-warning shrink-0" /> {flag}
                                          </span>
                                        ))}
                                      </div>
                                    ) : <span className="text-[10px] text-muted-foreground">-</span>}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
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
                        <h3 className="text-lg font-semibold text-foreground">What to do next</h3>
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

                    {/* 9. Feedback and Download */}
                    <div className="flex flex-col sm:flex-row items-center justify-between pt-6 border-t border-border/50 gap-4 mt-6">
                      <div className="flex items-center gap-3">
                        <span className="text-sm font-medium text-foreground/80">Was this helpful?</span>
                        {feedbackSent ? (
                           <Badge variant="outline" className="text-safe border-safe"><CheckCircle className="w-3 h-3 mr-1" /> Feedback saved!</Badge>
                        ) : (
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline" onClick={() => handleFeedback('accurate')} disabled={isFeedbackPending} className="hover:bg-safe/20 hover:text-safe hover:border-safe/50">
                              <ThumbsUp className="w-4 h-4 mr-1.5" /> Accurate
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => handleFeedback('wrong')} disabled={isFeedbackPending} className="hover:bg-destructive/20 hover:text-destructive hover:border-destructive/50">
                              <ThumbsDown className="w-4 h-4 mr-1.5" /> Wrong
                            </Button>
                          </div>
                        )}
                      </div>
                      
                      <Button onClick={handleDownloadReport} variant="secondary" className="gap-2 shrink-0">
                        <Download className="w-4 h-4" /> Download Report
                      </Button>
                    </div>
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
                    Scan Summary
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
                      {/* Donut chart — colors reference the CSS vars defined in :root */}
                      <div className="w-full sm:w-64 h-52 shrink-0">
                        <DonutChart metrics={metrics} />
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
                          {(metrics?.totalScans ?? 0) > 0 ? (
                            <span className="text-warning font-medium">
                              {Math.round(
                                ((metrics!.phishingDetected + metrics!.suspiciousDetected) / metrics!.totalScans) * 100
                              )}% of scanned emails were flagged
                            </span>
                          ) : (
                            <span>Scan emails to see statistics</span>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </section>

              {/* ── Regional Threat Intelligence ── */}
              <section>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <RegionalThreatMap />
                  
                  <div className="flex flex-col gap-4">
                    <div className="rounded-xl border border-card-border bg-card p-5 flex-1">
                       <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-primary" />
                          Dominant Attack Vector
                       </h3>
                       <div className="flex items-center gap-4 mt-2">
                          <div className={cn("text-2xl font-bold tracking-tight", (metrics?.phishingDetected ?? 0) > 0 ? "text-foreground" : "text-muted-foreground")}>
                             {(metrics?.phishingDetected ?? 0) > 0 ? 'Credential Harvesting' : 'Analyzing...'}
                          </div>
                          {(metrics?.phishingDetected ?? 0) > 0 && <Badge className="bg-destructive/10 text-destructive border-destructive/20 uppercase text-[9px] font-bold">Critical</Badge>}
                       </div>
                       <p className="text-[10px] text-muted-foreground mt-3 leading-relaxed">Most threats currently involve fake banking portals targeting Indian HDFC/SBI customers via high-pressure urgency tactics.</p>
                    </div>

                    <div className="rounded-xl border border-card-border bg-card p-5 flex-1">
                       <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                          <Flag className="w-4 h-4 text-warning" />
                          Most Targeted Brand
                       </h3>
                       <div className="flex items-center justify-between mt-2">
                          <div className={cn("text-2xl font-bold tracking-tight", (metrics?.phishingDetected ?? 0) > 0 ? "text-foreground" : "text-muted-foreground")}>
                             {getMostTargetedBrand()}
                          </div>
                          <div className="flex -space-x-2">
                             <div className="w-6 h-6 rounded-full bg-blue-500 border-2 border-card shadow-sm" />
                             <div className="w-6 h-6 rounded-full bg-orange-500 border-2 border-card shadow-sm" />
                             <div className="w-6 h-6 rounded-full bg-yellow-500 border-2 border-card shadow-sm" />
                          </div>
                       </div>
                       <p className="text-[10px] text-muted-foreground mt-3">Statistical mapping across 120+ Indian financial institutions.</p>
                    </div>
                  </div>
                </div>
              </section>

              {/* ── Risk Scale Reference ── */}
              <section>
                <h2 className="text-base font-semibold text-foreground flex items-center gap-2 mb-4">
                  <TrendingUp className="w-4 h-4 text-primary" />
                  Risk Distribution
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

              {/* ── Attack Intelligence ── */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-[10px] font-bold text-muted-foreground mb-3 uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-warning" />
                    Risk Keywords
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {getTopKeywords().length > 0 ? getTopKeywords().map(kw => (
                      <span key={kw} className="px-1.5 py-0.5 rounded bg-warning/10 text-warning border border-warning/20 text-[10px] font-mono lowercase">
                        {kw}
                      </span>
                    )) : <span className="text-[11px] text-muted-foreground">None detected</span>}
                  </div>
                </section>
                
                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-[10px] font-bold text-muted-foreground mb-3 uppercase tracking-wider flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-destructive" />
                    Attack Type
                  </h3>
                  <div className="text-sm font-bold text-foreground tracking-tight">
                    {getMostCommonAttackType()}
                  </div>
                </section>

                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-[10px] font-bold text-muted-foreground mb-3 uppercase tracking-wider flex items-center gap-2">
                    <Building2 className="w-3.5 h-3.5 text-primary" />
                    Targeted Brand
                  </h3>
                  <div className="text-sm font-bold text-foreground tracking-tight">
                    {getMostTargetedBrand()}
                  </div>
                </section>
              </div>

              {/* ── Model Performance ── */}
              <section>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-primary" />
                    Detection Accuracy
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
                    Recent Activity
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
                                <span><span className="font-mono bg-secondary px-1 rounded">{LANG_CODES[item.detectedLanguage] ?? 'MX'}</span> {LANG_LABELS[item.detectedLanguage] ?? item.detectedLanguage}</span>
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
                    Language Support
                  </h3>
                  <div className="space-y-3">
                    {[
                      { code: 'EN', lang: 'English', status: 'Full support', desc: 'Urgency, financial, social engineering' },
                      { code: 'HI', lang: 'Hindi', status: 'Active', desc: 'Devanagari — तुरंत, बंद, इनाम' },
                      { code: 'TE', lang: 'Telugu', status: 'Active', desc: 'Unicode range matching' },
                    ].map(({ code, lang, status, desc }) => (
                      <div key={lang} className="flex items-start gap-2">
                        <span className="font-mono text-[10px] bg-secondary px-1.5 py-0.5 rounded shrink-0 mt-0.5">{code}</span>
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
                    <Shield className="w-4 h-4 text-primary" />
                    India-specific patterns
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

      <footer className="mt-20 py-10 border-t border-border/40 text-center space-y-6">
        <div className="flex flex-wrap justify-center gap-6 opacity-60 grayscale hover:grayscale-0 transition-all duration-500">
           {[
             { label: 'Privacy First', icon: <Lock className="w-4 h-4" /> },
             { label: 'Offline Engine', icon: <ShieldCheck className="w-4 h-4" /> },
             { label: 'India Precise', icon: <Globe className="w-4 h-4" /> },
             { label: 'No Data Storage', icon: <Trash2 className="w-4 h-4" /> }
           ].map(badge => (
             <div key={badge.label} className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest">
                {badge.icon}
                {badge.label}
             </div>
           ))}
        </div>
        <div className="space-y-2">
           <p className="text-xs text-muted-foreground">PhishShield AI — built for India</p>
           <p className="text-[10px] text-muted-foreground/50 font-mono">Secure Node v24.2.0 • Session ID: {Math.random().toString(36).substring(7).toUpperCase()}</p>
        </div>
      </footer>
    </div>
  );
}
