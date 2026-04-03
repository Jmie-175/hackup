const API_URL = "http://localhost:8000"
const WS_URL = "ws://localhost:8000/stream"

export type ThreatVerdict = "safe" | "suspicious" | "threat"

export interface Signal {
  name: string
  score: number
  severity: "info" | "warning" | "danger"
  detail: string
}

export interface AttackNode {
  stage: string
  value: string
  verdict: ThreatVerdict
}

export interface ScanResult {
  id: string
  score: number
  verdict: ThreatVerdict
  ai_generated_score: number
  reasons: string[]
  explanation: string
  signals: Signal[]
  chain: AttackNode[]
  timestamp?: string
  source?: string
}

export async function submitScan(content: string, inputType: "email" | "url" | "attachment_base64") {
  const res = await fetch(`${API_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, input_type: inputType, source: "paste" })
  })
  
  if (!res.ok) {
    throw new Error(`API Error: ${res.statusText}`)
  }
  
  return res.json() as Promise<ScanResult>
}

export async function fetchStats() {
  const res = await fetch(`${API_URL}/stats`)
  if (!res.ok) throw new Error("Failed to fetch stats")
  return res.json()
}

export async function submitFeedback(scanId: string, correction: "false_positive" | "false_negative") {
  const res = await fetch(`${API_URL}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_id: scanId, correction })
  })
  if (!res.ok) throw new Error("Failed to submit feedback")
  return res.json()
}

// Global WebSocket singleton pattern
let wsInstance: WebSocket | null = null

export function connectLiveFeed(onMessage: (data: ScanResult) => void, onStateChange: (state: "connected" | "connecting" | "disconnected") => void) {
  if (wsInstance) {
    wsInstance.close()
  }
  
  onStateChange("connecting")
  wsInstance = new WebSocket(WS_URL)
  
  wsInstance.onopen = () => onStateChange("connected")
  wsInstance.onclose = () => {
    onStateChange("disconnected")
    // Reconnect logic
    setTimeout(() => connectLiveFeed(onMessage, onStateChange), 3000)
  }
  wsInstance.onerror = () => onStateChange("disconnected")
  
  wsInstance.onmessage = (e) => {
    try {
      const result = JSON.parse(e.data) as ScanResult
      onMessage(result)
    } catch (err) {
      console.error("Invalid WS message", err)
    }
  }
  
  return () => {
    wsInstance?.close()
    wsInstance = null
  }
}
