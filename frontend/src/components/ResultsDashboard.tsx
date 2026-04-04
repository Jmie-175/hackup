import { motion } from "framer-motion"
import { AlertTriangle, ShieldCheck, Zap, ChevronRight, Info } from "lucide-react"
import type { ScanResult } from "../lib/api"

export function ResultsDashboard({ result }: { result: ScanResult }) {
  const isThreat = result.score >= 70
  const isSuspicious = result.score >= 40 && result.score < 70
  const isSafe = result.score < 40

  const color = isThreat ? "text-destructive border-destructive" : isSuspicious ? "text-amber-500 border-amber-500" : "text-emerald-500 border-emerald-500"
  const bgColor = isThreat ? "bg-destructive/10" : isSuspicious ? "bg-amber-500/10" : "bg-emerald-500/10"
  
  const Icon = isSafe ? ShieldCheck : isSuspicious ? Zap : AlertTriangle

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="mt-8 space-y-6 max-w-4xl max-w-full"
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Main Verdict Card */}
        <div className="col-span-1 md:col-span-2 bg-card/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-center">
          <div className="absolute top-0 right-0 p-8 opacity-5 overflow-hidden">
            <Icon size={200} className={color.split(" ")[0]} />
          </div>
          
          <div className="flex items-center gap-6 relative z-10">
            <div className={`relative flex items-center justify-center w-28 h-28 rounded-full border-[6px] ${color}`}>
              <span className="text-4xl font-bold font-mono tracking-tighter">{result.score}</span>
            </div>
            
            <div>
              <div className={`inline-flex flex-row items-center gap-2 px-3 py-1 rounded-full text-xs font-bold tracking-widest mb-3 border ${color} ${bgColor}`}>
                <Icon size={14} />
                {result.verdict.toUpperCase()}
              </div>
              
              <h3 className="text-xl font-medium leading-tight mb-2">
                {result.reasons?.[0] || "No primary reason provided."}
              </h3>
              
              {result.ai_generated_score >= 65 && (
                <div className="inline-flex items-center gap-1.5 text-xs text-indigo-400 bg-indigo-500/10 px-2 py-1 rounded border border-indigo-500/20">
                  <span>🤖</span> AI-generated context detected ({result.ai_generated_score}% confidence)
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Explainability Box */}
        <div className="col-span-1 bg-card/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6 shadow-xl flex flex-col">
          <div className="flex items-center gap-2 mb-4 text-primary">
            <Info size={18} />
            <span className="font-semibold text-sm uppercase tracking-wider">AI Reasoning</span>
          </div>
          <div className="flex-1 overflow-y-auto pr-2 text-sm text-muted-foreground/90 font-medium leading-relaxed custom-scrollbar">
            {result.explanation || "No advanced AI reasoning available."}
          </div>
        </div>
      </div>

      {/* Signals Grid */}
      <div>
        <h4 className="text-sm uppercase tracking-widest text-muted-foreground mb-4">Detection Signals</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {result.signals?.map((s, i) => (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.05 }}
              key={i} 
              className={`p-4 rounded-xl border bg-black/40 ${
                s.severity === 'danger' ? 'border-destructive/30 border-l-4 border-l-destructive' : 
                s.severity === 'warning' ? 'border-amber-500/30 border-l-4 border-l-amber-500' : 
                'border-white/5 border-l-4 border-l-white/20'
              }`}
            >
              <div className="flex justify-between items-start mb-2">
                <span className="font-semibold text-sm">{s.name}</span>
                <span className="text-xs font-mono font-bold bg-black/50 px-2 py-0.5 rounded">{s.score}/100</span>
              </div>
              <p className="text-xs text-muted-foreground">{s.detail}</p>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Attack Chain */}
      {result.chain && result.chain.length > 0 && (
        <div className="mt-8">
          <h4 className="text-sm uppercase tracking-widest text-muted-foreground mb-4">Attack Chain Analysis</h4>
          <div className="bg-black/30 rounded-2xl border border-white/5 p-8">
            <div className="flex flex-wrap items-center gap-y-6">
              {result.chain.map((c, i) => (
                <div key={i} className="flex items-center">
                  <motion.div 
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.3 + (i * 0.1) }}
                    className={`px-4 py-3 rounded-lg border ${
                      c.verdict === 'threat' ? 'bg-destructive/10 border-destructive outline outline-1 outline-destructive/50' :
                      c.verdict === 'suspicious' ? 'bg-amber-500/10 border-amber-500/50' : 'bg-emerald-500/10 border-emerald-500/30'
                    }`}
                  >
                    <div className="text-[10px] uppercase font-bold tracking-widest opacity-60 mb-1">{c.stage}</div>
                    <div className="text-sm font-mono break-all line-clamp-2 max-w-[200px]">{c.value}</div>
                  </motion.div>
                  
                  {i < result.chain.length - 1 && (
                    <div className="px-4 text-white/20">
                      <ChevronRight size={24} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

    </motion.div>
  )
}
