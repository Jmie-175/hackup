import { useState, useRef } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Mail, Link2, FileWarning, Search, UploadCloud } from "lucide-react"

interface ScanTabProps {
  isScanning: boolean
  onScan: (content: string, type: "email" | "url" | "attachment_base64") => void
}

export function ScanTab({ isScanning, onScan }: ScanTabProps) {
  const [mode, setMode] = useState<"email" | "url" | "attachment">("email")
  const [content, setContent] = useState("")
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleAnalyze = async () => {
    if (mode === "email" || mode === "url") {
      if (!content.trim()) return
      onScan(content, mode)
    } else {
      if (!selectedFile) return
      const reader = new FileReader()
      reader.onload = () => {
        const b64 = (reader.result as string).split(",")[1]
        onScan(b64, "attachment_base64")
      }
      reader.readAsDataURL(selectedFile)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0])
    }
  }

  return (
    <div className="max-w-4xl max-w-full relative">
      <div className="mb-8">
        <h2 className="text-3xl font-light tracking-tight mb-2">Analyze <span className="font-semibold text-primary">Threat</span></h2>
        <p className="text-muted-foreground">Paste email content, a URL, or upload an attachment to begin AI analysis.</p>
      </div>

      <div className="bg-card/50 backdrop-blur-md rounded-2xl border border-white/5 shadow-2xl relative overflow-hidden">
        
        {/* Animated scanning overlay */}
        <AnimatePresence>
          {isScanning && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 z-50 bg-background/80 backdrop-blur-sm flex flex-col items-center justify-center pointer-events-none"
            >
              <div className="relative w-32 h-32 flex items-center justify-center">
                <motion.div 
                  animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }}
                  transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                  className="absolute w-full h-full rounded-full bg-primary/20 blur-xl"
                />
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                  className="absolute w-24 h-24 rounded-full border-t-2 border-r-2 border-primary"
                />
                <ShieldIcon className="text-primary z-10 w-8 h-8" />
              </div>
              <motion.p 
                animate={{ opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 1.5, repeat: Infinity }}
                className="mt-6 text-primary font-mono text-sm tracking-widest"
              >
                AI ENGINE PROCESSING
              </motion.p>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="p-6 border-b border-white/5">
          <div className="flex gap-2 p-1 bg-black/40 rounded-xl inline-flex mb-6 border border-white/5">
            <ModeTab icon={<Mail size={16} />} label="Email" active={mode === "email"} onClick={() => setMode("email")} />
            <ModeTab icon={<Link2 size={16} />} label="URL" active={mode === "url"} onClick={() => setMode("url")} />
            <ModeTab icon={<FileWarning size={16} />} label="Attachment" active={mode === "attachment"} onClick={() => setMode("attachment")} />
          </div>

          <div className="min-h-[250px]">
            <AnimatePresence mode="wait">
              <motion.div
                key={mode}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
              >
                {mode === "email" && (
                  <textarea 
                    autoFocus
                    placeholder="Subject: Urgent action required...&#10;From: security@paypal-alerts.net&#10;&#10;Paste the raw email header and body here..."
                    className="w-full h-[250px] bg-black/20 border border-white/10 rounded-xl p-4 text-sm font-mono placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none"
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                  />
                )}
                {mode === "url" && (
                  <div className="flex flex-col gap-4">
                    <input 
                      autoFocus
                      type="text" 
                      placeholder="https://suspicious-site.com/login"
                      className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-4 text-sm font-mono placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
                      value={content}
                      onChange={(e) => setContent(e.target.value)}
                    />
                    <div className="text-xs text-muted-foreground p-4 bg-primary/5 rounded-lg border border-primary/10">
                      Our engines will analyze domain age, lookalike characters (homoglyphs), TLD reputation, and path heuristics.
                    </div>
                  </div>
                )}
                {mode === "attachment" && (
                  <div 
                    onClick={() => fileInputRef.current?.click()}
                    className="w-full h-[250px] bg-black/20 border-2 border-dashed border-white/20 rounded-xl flex flex-col items-center justify-center cursor-pointer hover:bg-black/40 hover:border-primary/50 transition-all group"
                  >
                    <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileChange} accept=".pdf,.doc,.docx,.exe,.zip" />
                    
                    {selectedFile ? (
                      <div className="text-center">
                        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-primary/20 text-primary mb-4">
                          <FileWarning size={32} />
                        </div>
                        <p className="font-semibold">{selectedFile.name}</p>
                        <p className="text-xs text-muted-foreground mt-1">{(selectedFile.size / 1024).toFixed(1)} KB</p>
                        <p className="text-xs text-primary mt-4 group-hover:underline">Click to change file</p>
                      </div>
                    ) : (
                      <div className="text-center">
                        <UploadCloud size={48} className="mx-auto text-muted-foreground group-hover:text-primary transition-colors mb-4" />
                        <p className="font-medium">Draw or click to upload file</p>
                        <p className="text-xs text-muted-foreground mt-2">Supports PDF, DOCX, EXE, ZIP</p>
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>

        <div className="p-6 bg-black/20 flex justify-between items-center">
          <div className="flex gap-2">
            {/* Quick inject buttons for testing */}
            <span className="text-xs text-muted-foreground py-2 px-1">Try:</span>
            <button className="px-3 py-1.5 rounded-md text-xs bg-white/5 hover:bg-white/10 text-white/70 transition-colors"
                onClick={() => {setMode("email"); setContent("Subject: Urgent\nFrom: sys@app1e.com\n\nReset your password here http://app1e-id.com/login")}}>
              ⚠ Bank Scam
            </button>
            <button className="px-3 py-1.5 rounded-md text-xs bg-white/5 hover:bg-white/10 text-white/70 transition-colors"
                onClick={() => {setMode("url"); setContent("http://paypa1-secure.net/login")}}>
              ⚠ Fake URL
            </button>
          </div>

          <button 
            disabled={isScanning || (mode !== "attachment" && !content) || (mode === "attachment" && !selectedFile)}
            onClick={handleAnalyze}
            className="px-8 py-3 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold rounded-xl flex items-center gap-2 transition-all shadow-[0_0_20px_rgba(var(--primary),0.3)] hover:shadow-[0_0_30px_rgba(var(--primary),0.5)] disabled:opacity-50 disabled:shadow-none disabled:cursor-not-allowed"
          >
            <Search size={18} />
            {isScanning ? "ANALYZING..." : "ANALYZE THREAT"}
          </button>
        </div>
      </div>
    </div>
  )
}

function ModeTab({ icon, label, active, onClick }: any) {
  return (
    <button 
      onClick={onClick}
      className={`relative px-4 py-2 text-sm font-medium transition-colors flex items-center gap-2 rounded-lg ${
        active ? "text-white" : "text-muted-foreground hover:text-white"
      }`}
    >
      {active && (
        <motion.div layoutId="mode-tab-bg" className="absolute inset-0 bg-white/10 rounded-lg shadow-sm" />
      )}
      <span className="relative z-10">{icon}</span>
      <span className="relative z-10">{label}</span>
    </button>
  )
}

function ShieldIcon(props: any) {
  return (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z" />
    </svg>
  )
}
