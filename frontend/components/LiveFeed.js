// LiveFeed.js — receives real-time scan results via WebSocket
const LiveFeed = (() => {
  const MAX = 50;
  let items = [];

  function push(result) {
    items.unshift({
      id: result.id,
      verdict: result.verdict,
      score: result.score,
      timestamp: result.timestamp || new Date().toISOString(),
      reason: result.reasons?.[0] || result.verdict,
    });
    if (items.length > MAX) items.pop();
  }

  function getAll() { return items; }

  return { push, getAll };
})();
