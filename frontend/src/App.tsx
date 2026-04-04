import { useState, useEffect } from "react"
import { Sidebar } from "./components/Sidebar"
import type { TabType } from "./components/Sidebar"
import { ScanTab } from "./components/ScanTab"
import { ResultsDashboard } from "./components/ResultsDashboard"
import { StatsTab } from "./components/StatsTab"
import { connectLiveFeed, submitScan } from "./lib/api"
import type { ScanResult } from "./lib/api"
import { ShieldAlert, X } from "lucide-react"

export default function App() {
  const [tab, setTab] = useState<TabType>("scan")
  const [wsState, setWsState] = useState<"connected" | "connecting" | "disconnected">("connecting")
  
  const [isScanning, setIsScanning] = useState(false)
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null)
  
  const [liveFeed, setLiveFeed] = useState<ScanResult[]>([])
  const [showLiveFeed, setShowLiveFeed] = useState(true)

  useEffect(() => {
    const cleanup = connectLiveFeed(
      (newResult) => setLiveFeed(prev => [newResult, ...prev].slice(0, 5)),
      (state) => setWsState(state)
    )
    return cleanup
  }, [])

  const handleScan = async (content: string, type: "email" | "url" | "attachment_base64") => {
    setIsScanning(true)
    setCurrentResult(null)
    try {
      const res = await submitScan(content, type)
      setCurrentResult(res)
    } catch (err) {
      console.error(err)
      alert("Analysis failed. Ensure backend is running.")
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground overflow-hidden selection:bg-primary/30">
      
      {/* Background ambient lighting */}
      <div className="fixed top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-primary/5 blur-[120px] pointer-events-none" />
      <div className="fixed bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-500/5 blur-[120px] pointer-events-none" />
      
      <Sidebar currentTab={tab} onTabChange={setTab} wsState={wsState} />
      
      <main className="flex-1 min-w-0 h-screen overflow-y-auto relative z-10 custom-scrollbar">
        <div className="p-6 md:p-12 pb-24">
          
          {tab === "scan" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <ScanTab isScanning={isScanning} onScan={handleScan} />
              
              {currentResult && !isScanning && (
                <ResultsDashboard result={currentResult} />
              )}
            </div>
          )}
          
          {tab === "stats" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <StatsTab />
            </div>
          )}

          {tab === "campaigns" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 max-w-4xl">
              <div className="mb-8">
                <h2 className="text-3xl font-light tracking-tight mb-2">Campaign <span className="font-semibold text-primary">Tracker</span></h2>
                <p className="text-muted-foreground">Clustered phishing campaigns detected across network scans.</p>
              </div>
              <div className="bg-card/40 backdrop-blur-xl border border-white/5 rounded-2xl p-12 text-center text-muted-foreground flex flex-col items-center shadow-xl">
                <ShieldAlert size={48} className="opacity-20 mb-4" />
                <p className="text-lg font-medium">Clustering Engine learning...</p>
                <p className="text-sm mt-2 max-w-md">The AI requires deeper historical data across multiple threat vectors to successfully identify and cluster adversarial campaigns. Keep scanning to provide data to the clustering model.</p>
              </div>
            </div>
          )}
          
        </div>
      </main>

      {/* Floating Live Feed Widget */}
      {showLiveFeed && liveFeed.length > 0 && (
        <div className="fixed bottom-6 right-6 w-80 bg-black/80 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl p-4 flex flex-col gap-3 z-50 animate-in slide-in-from-bottom-5">
          <div className="text-xs uppercase tracking-widest text-muted-foreground font-semibold flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Live Threat Feed</span>
            </div>
            <button 
              onClick={() => setShowLiveFeed(false)}
              className="p-1 hover:bg-white/10 rounded-md transition-colors text-muted-foreground hover:text-white"
            >
              <X size={14} />
            </button>
          </div>
          <div className="space-y-2">
            {liveFeed.map(feed => (
               <div key={feed.id} className="text-xs flex flex-col gap-1 p-2 rounded bg-white/5">
                 <div className="flex justify-between font-mono">
                   <span className="opacity-60">{feed.source || 'paste'}</span>
                   <span className={feed.verdict === 'threat' ? 'text-destructive font-bold' : feed.verdict === 'suspicious' ? 'text-amber-500 font-bold' : 'text-emerald-500 font-bold'}>
                     {feed.score}/100
                   </span>
                 </div>
                 <div className="truncate opacity-80">{feed.reasons?.[0] || 'Processed scan'}</div>
               </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
