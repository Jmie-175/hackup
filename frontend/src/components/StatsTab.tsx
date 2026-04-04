import { useEffect, useState } from "react"
import { motion } from "framer-motion"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from "recharts"
import { fetchStats } from "../lib/api"
import { ShieldCheck, ShieldAlert, AlertCircle, Activity } from "lucide-react"

export function StatsTab() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchStats()
      .then(d => { setStats(d); setLoading(false) })
      .catch(e => { console.error(e); setLoading(false) })
  }, [])

  if (loading) return <div className="p-8 text-muted-foreground animate-pulse">Loading analytics...</div>
  if (!stats) return <div className="p-8 text-destructive">Failed to load analytics engine.</div>

  return (
    <div className="max-w-5xl max-w-full">
      <div className="mb-8">
        <h2 className="text-3xl font-light tracking-tight mb-2">Threat <span className="font-semibold text-primary">Analytics</span></h2>
        <p className="text-muted-foreground">Historical engine performance and threat trends across the network.</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard title="Total Scanned" value={stats.total_scanned} icon={<Activity size={20}/>} />
        <StatCard title="Threats Prevented" value={stats.threats_detected} icon={<ShieldAlert size={20}/>} color="text-destructive" />
        <StatCard title="Suspicious Flags" value={stats.suspicious_detected} icon={<AlertCircle size={20}/>} color="text-amber-500" />
        <StatCard title="Detection Rate" value={`${stats.detection_rate}%`} icon={<ShieldCheck size={20}/>} color="text-emerald-500" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="bg-card/40 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
          <h3 className="text-sm uppercase tracking-widest text-muted-foreground mb-6">Daily Threat Activity</h3>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats.daily_trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                <XAxis dataKey="date" stroke="#666" fontSize={10} tickFormatter={(t) => t.slice(5)} />
                <YAxis stroke="#666" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
                  itemStyle={{ fontSize: '12px' }}
                />
                <Line type="monotone" dataKey="total" stroke="#4a5568" strokeWidth={2} dot={false} name="Total Scans" />
                <Line type="monotone" dataKey="threats" stroke="#e24b4a" strokeWidth={2} dot={{ r: 4, fill: '#e24b4a' }} activeDot={{ r: 6 }} name="Threats" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-card/40 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
          <h3 className="text-sm uppercase tracking-widest text-muted-foreground mb-6">Top Attack Vectors</h3>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.top_threat_types} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#222" horizontal={false} />
                <XAxis type="number" stroke="#666" fontSize={10} hide />
                <YAxis dataKey="type" type="category" stroke="#999" fontSize={11} axisLine={false} tickLine={false} width={100} />
                <Tooltip 
                  cursor={{fill: 'transparent'}}
                  contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {stats.top_threat_types?.map((_entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={index === 0 ? '#e24b4a' : '#f5a623'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="bg-card/40 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
        <h3 className="text-sm uppercase tracking-widest text-muted-foreground mb-6">Recent Live Scans</h3>
        <div className="space-y-1">
          {stats.recent_scans?.length > 0 ? stats.recent_scans.map((s: any, i: number) => (
             <div key={i} className="flex items-center gap-4 py-3 px-4 rounded-lg hover:bg-white/5 transition-colors border border-transparent hover:border-white/5">
               <div className={`w-2 h-2 rounded-full ${s.verdict === 'threat' ? 'bg-destructive shadow-[0_0_8px_rgba(226,75,74,0.8)]' : s.verdict === 'suspicious' ? 'bg-amber-500' : 'bg-emerald-500'}`} />
               <span className="text-xs text-muted-foreground font-mono w-16">{new Date(s.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span>
               <span className="flex-1 text-sm font-medium truncate opacity-90">{s.verdict.toUpperCase()} DETECTED</span>
               <span className="text-xs font-mono px-2 py-1 bg-black/40 rounded border border-white/5">{s.source}</span>
               <span className="text-sm font-bold font-mono pl-4">{s.score}/100</span>
             </div>
          )) : <div className="text-center py-6 text-muted-foreground text-sm">No recent scans on record.</div>}
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon, color = "text-foreground" }: any) {
  return (
    <motion.div 
       initial={{ opacity: 0, y: 10 }}
       animate={{ opacity: 1, y: 0 }}
       className="bg-card/40 border border-white/5 rounded-2xl p-4 md:p-6 flex flex-col justify-between relative overflow-hidden group"
    >
      <div className="flex justify-between items-start mb-4">
        <span className="text-xs text-muted-foreground font-medium tracking-wide uppercase">{title}</span>
        <div className={`opacity-50 group-hover:opacity-100 transition-opacity ${color}`}>{icon}</div>
      </div>
      <div className={`text-3xl md:text-4xl font-light font-mono ${color}`}>{value}</div>
    </motion.div>
  )
}
