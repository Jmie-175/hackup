import { ShieldAlert, Zap, BarChart2, Link as LinkIcon, Activity } from "lucide-react"
import { motion } from "framer-motion"

export type TabType = "scan" | "stats" | "campaigns"

interface SidebarProps {
  currentTab: TabType
  onTabChange: (tab: TabType) => void
  wsState: "connected" | "connecting" | "disconnected"
}

export function Sidebar({ currentTab, onTabChange, wsState }: SidebarProps) {
  return (
    <aside className="w-64 border-r border-white/10 bg-background/50 backdrop-blur-xl flex flex-col justify-between p-4 hidden md:flex shrink-0 h-screen sticky top-0">
      <div>
        <div className="flex items-center gap-3 mb-10 mt-4 px-2">
          <div className="bg-primary/20 p-2 rounded-lg text-primary ring-1 ring-primary/30 shadow-[0_0_15px_rgba(var(--primary),0.3)]">
            <ShieldAlert size={28} />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wider text-foreground">PHISHGUARD</h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-mono">AI Threat Detection</p>
          </div>
        </div>

        <nav className="space-y-2">
          <NavItem 
            icon={<Zap size={18} />} 
            label="Scan Threat" 
            isActive={currentTab === "scan"} 
            onClick={() => onTabChange("scan")} 
          />
          <NavItem 
            icon={<BarChart2 size={18} />} 
            label="Statistics" 
            isActive={currentTab === "stats"} 
            onClick={() => onTabChange("stats")} 
          />
          <NavItem 
            icon={<LinkIcon size={18} />} 
            label="Campaigns" 
            isActive={currentTab === "campaigns"} 
            onClick={() => onTabChange("campaigns")} 
          />
        </nav>
      </div>

      <div className="px-2 py-4 border-t border-white/5 space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="relative flex h-2.5 w-2.5">
            {wsState === "connected" && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            )}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
              wsState === "connected" ? "bg-emerald-500" : 
              wsState === "connecting" ? "bg-amber-500 animate-pulse" : "bg-red-500"
            }`}></span>
          </div>
          <span className="text-muted-foreground">
            {wsState === "connected" ? "LIVE FEED ACTIVE" : 
             wsState === "connecting" ? "CONNECTING..." : "DISCONNECTED"}
          </span>
        </div>
      </div>
    </aside>
  )
}

function NavItem({ icon, label, isActive, onClick }: { icon: React.ReactNode, label: string, isActive: boolean, onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`relative flex items-center gap-3 w-full px-4 py-3 rounded-lg text-sm transition-all duration-200 overflow-hidden group ${
        isActive ? "text-primary font-medium bg-primary/10" : "text-muted-foreground hover:bg-white/5 hover:text-white"
      }`}
    >
      {isActive && (
        <motion.div 
          layoutId="active-tab-indicator"
          className="absolute left-0 top-0 w-1 h-full bg-primary"
          initial={false}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        />
      )}
      <span className={isActive ? "text-primary" : "text-muted-foreground group-hover:text-white transition-colors"}>
        {icon}
      </span>
      {label}
    </button>
  )
}
