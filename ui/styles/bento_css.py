"""
Bento Grid UI Design System
Modern, minimalist SOC dashboard styling inspired by Apple Vision Pro / Linear / Notion
"""


def get_bento_css() -> str:
    """
    Returns the complete Bento UI CSS with design tokens,
    grid system, card styles, and animations.
    """
    return """
/* ============================================
   BENTO UI DESIGN SYSTEM
   SOC Orchestrator - Futuristic Dashboard
   ============================================ */

/* ---------- DESIGN TOKENS ---------- */
:root {
  /* Background Colors */
  --bg-primary: #000000;
  --bg-surface: #0a0a0a;
  --bg-elevated: #111111;
  --bg-hover: #151515;

  /* Border Colors */
  --border-subtle: #1a1a1a;
  --border-hover: #2a2a2a;
  --border-active: #3a3a3a;

  /* Text Colors */
  --text-primary: #ffffff;
  --text-secondary: #71717a;
  --text-tertiary: #52525b;
  --text-muted: #3f3f46;

  /* Accent - Neon Green */
  --accent: #00ff88;
  --accent-dim: rgba(0, 255, 136, 0.2);
  --accent-subtle: rgba(0, 255, 136, 0.1);
  --accent-glow: rgba(0, 255, 136, 0.4);

  /* Semantic Colors */
  --success: #10b981;
  --success-dim: rgba(16, 185, 129, 0.2);
  --warning: #f59e0b;
  --warning-dim: rgba(245, 158, 11, 0.2);
  --danger: #ef4444;
  --danger-dim: rgba(239, 68, 68, 0.2);
  --info: #3b82f6;
  --info-dim: rgba(59, 130, 246, 0.2);

  /* Agent Colors */
  --agent-supervisor: #3b82f6;
  --agent-enrichment: #10b981;
  --agent-analysis: #f59e0b;
  --agent-investigation: #8b5cf6;
  --agent-response: #ef4444;
  --agent-communication: #06b6d4;
  --agent-memory: #ec4899;

  /* Typography */
  --font-display: 'SF Pro Display', 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --font-mono: 'SF Mono', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;

  /* Font Sizes */
  --text-xs: 0.75rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-lg: 1.125rem;
  --text-xl: 1.25rem;
  --text-2xl: 1.5rem;
  --text-3xl: 2rem;
  --text-4xl: 2.5rem;
  --text-hero: 4rem;

  /* Font Weights */
  --font-normal: 400;
  --font-medium: 500;
  --font-semibold: 600;
  --font-bold: 700;

  /* Letter Spacing */
  --tracking-tight: -0.02em;
  --tracking-normal: 0;
  --tracking-wide: 0.05em;
  --tracking-wider: 0.1em;

  /* Spacing Scale */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;
  --space-10: 40px;
  --space-12: 48px;

  /* Border Radius (Bento = extra rounded) */
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 24px;
  --radius-2xl: 32px;
  --radius-full: 9999px;

  /* Card Sizing */
  --card-padding: 20px;
  --card-gap: 16px;
  --grid-gap: 16px;
}


/* ---------- GLOBAL RESET FOR GRADIO ---------- */
.gradio-container {
  background: var(--bg-primary) !important;
  max-width: 100% !important;
  padding: 0 !important;
}

.dark {
  --background-fill-primary: var(--bg-primary) !important;
  --background-fill-secondary: var(--bg-surface) !important;
  --border-color-primary: var(--border-subtle) !important;
}

gradio-app {
  background: var(--bg-primary) !important;
}

/* ---------- LAYOUT FIX ---------- */
#main_container {
  display: flex !important;
  flex-direction: row !important;
  gap: var(--grid-gap) !important;
  padding: var(--space-4) !important;
}

#sidebar {
  position: relative !important;
  z-index: 10 !important;
  display: flex !important;
  flex-direction: column !important;
  gap: var(--grid-gap) !important;
  flex-shrink: 0 !important;
}

#sidebar_card {
  position: relative !important;
  z-index: 10 !important;
}

#mcp_status_panel {
  position: relative !important;
  z-index: 10 !important;
}

#mcp_status_panel .bento-card {
  margin-top: 0 !important;
}

#content_area {
  position: relative !important;
  z-index: 1 !important;
  flex: 1 !important;
  min-width: 0 !important;
  overflow: hidden !important;
}


/* ---------- BENTO GRID SYSTEM ---------- */
.bento-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  grid-auto-rows: minmax(60px, auto);
  gap: var(--grid-gap);
  padding: var(--space-4);
  width: 100%;
}

/* Grid Size Classes */
.bento-2x1 { grid-column: span 3; grid-row: span 1; }
.bento-2x2 { grid-column: span 3; grid-row: span 2; }
.bento-2x3 { grid-column: span 3; grid-row: span 3; }
.bento-3x1 { grid-column: span 4; grid-row: span 1; }
.bento-3x2 { grid-column: span 4; grid-row: span 2; }
.bento-4x1 { grid-column: span 5; grid-row: span 1; }
.bento-4x2 { grid-column: span 6; grid-row: span 2; }
.bento-4x3 { grid-column: span 6; grid-row: span 3; }
.bento-6x1 { grid-column: span 8; grid-row: span 1; }
.bento-6x2 { grid-column: span 8; grid-row: span 2; }
.bento-8x2 { grid-column: span 9; grid-row: span 2; }
.bento-full { grid-column: span 12; grid-row: span 1; }
.bento-full-2 { grid-column: span 12; grid-row: span 2; }


/* ---------- BENTO CARD BASE ---------- */
.bento-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-xl);
  padding: var(--card-padding);
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.bento-card:hover {
  border-color: var(--border-hover);
  box-shadow:
    0 0 0 1px var(--accent-subtle),
    0 20px 40px -20px rgba(0, 255, 136, 0.08);
  transform: translateY(-2px);
}

/* Card top glow line on hover */
.bento-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(
    90deg,
    transparent,
    var(--accent-dim),
    transparent
  );
  opacity: 0;
  transition: opacity 0.3s ease;
}

.bento-card:hover::before {
  opacity: 1;
}

/* Card Header */
.bento-card-header {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-bottom: var(--space-4);
}

.bento-card-icon {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--accent-dim);
  border-radius: var(--radius-md);
  font-size: var(--text-lg);
}

.bento-card-title {
  font-family: var(--font-display);
  font-size: var(--text-sm);
  font-weight: var(--font-semibold);
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: var(--tracking-wider);
}


/* ---------- TAB STYLING ---------- */
.bento-tabs {
  display: flex;
  gap: var(--space-2);
  padding: var(--space-2);
  background: var(--bg-surface);
  border-radius: var(--radius-xl);
  border: 1px solid var(--border-subtle);
  margin-bottom: var(--space-4);
}

/* Override Gradio tabs */
.tabs {
  background: transparent !important;
  border: none !important;
}

.tab-nav {
  background: var(--bg-surface) !important;
  border: 1px solid var(--border-subtle) !important;
  border-radius: var(--radius-xl) !important;
  padding: var(--space-2) !important;
  gap: var(--space-2) !important;
}

.tab-nav button {
  padding: var(--space-3) var(--space-5) !important;
  border-radius: var(--radius-lg) !important;
  font-family: var(--font-display) !important;
  font-size: var(--text-sm) !important;
  font-weight: var(--font-medium) !important;
  color: var(--text-secondary) !important;
  background: transparent !important;
  border: none !important;
  transition: all 0.2s ease !important;
}

.tab-nav button:hover {
  color: var(--text-primary) !important;
  background: var(--bg-elevated) !important;
}

.tab-nav button.selected {
  color: var(--accent) !important;
  background: var(--accent-dim) !important;
}

.tabitem {
  background: transparent !important;
  border: none !important;
  padding: 0 !important;
}


/* ---------- HEADER BAR ---------- */
.bento-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-4) var(--space-6);
  border-bottom: 1px solid var(--border-subtle);
  background: var(--bg-surface);
}

.bento-logo {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.bento-logo-text {
  font-family: var(--font-display);
  font-size: var(--text-xl);
  font-weight: var(--font-bold);
  color: var(--text-primary);
  letter-spacing: var(--tracking-tight);
}

.bento-version {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--accent);
  background: var(--accent-dim);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
}


/* ---------- AGENT ORCHESTRATION ---------- */
.agent-pipeline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  padding: var(--space-4) 0;
  position: relative;
}

.agent-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-2);
  position: relative;
  z-index: 1;
}

.node-ring {
  width: 56px;
  height: 56px;
  border-radius: 50%;
  border: 2px solid var(--border-subtle);
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-surface);
  transition: all 0.3s ease;
  position: relative;
}

.node-icon {
  font-size: var(--text-xl);
}

.node-label {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-secondary);
  letter-spacing: var(--tracking-wide);
}

/* Agent States */
.agent-node.active .node-ring {
  border-color: var(--accent);
  box-shadow: 0 0 20px var(--accent-dim);
  animation: breathe 2s infinite;
}

.agent-node.completed .node-ring {
  border-color: var(--success);
  background: var(--success-dim);
}

.agent-node.completed .node-ring::after {
  content: '\\2713';
  position: absolute;
  top: -4px;
  right: -4px;
  width: 18px;
  height: 18px;
  background: var(--success);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  color: #000;
  font-weight: bold;
}

.agent-node.pending .node-ring {
  border-color: var(--border-subtle);
  opacity: 0.5;
}

/* Flow line between nodes */
.flow-connector {
  flex: 1;
  height: 2px;
  background: var(--border-subtle);
  position: relative;
}

.flow-connector.active {
  background: linear-gradient(90deg, var(--accent), var(--accent-dim));
  animation: flowPulse 1.5s ease infinite;
}


/* ---------- REASONING STREAM ---------- */
.stream-container {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  max-height: 350px;
  overflow-y: auto;
  padding-right: var(--space-2);
}

.stream-container::-webkit-scrollbar {
  width: 6px;
}

.stream-container::-webkit-scrollbar-track {
  background: var(--bg-elevated);
  border-radius: var(--radius-full);
}

.stream-container::-webkit-scrollbar-thumb {
  background: var(--border-hover);
  border-radius: var(--radius-full);
}

.stream-message {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3);
  background: var(--bg-elevated);
  border-radius: var(--radius-md);
  animation: fadeInUp 0.3s ease;
}

.agent-badge {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: var(--font-semibold);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  letter-spacing: var(--tracking-wide);
}

.agent-badge.supervisor { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
.agent-badge.enrichment { background: rgba(16, 185, 129, 0.2); color: #10b981; }
.agent-badge.analysis { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
.agent-badge.investigation { background: rgba(139, 92, 246, 0.2); color: #8b5cf6; }
.agent-badge.response { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
.agent-badge.communication { background: rgba(6, 182, 212, 0.2); color: #06b6d4; }
.agent-badge.memory { background: rgba(236, 72, 153, 0.2); color: #ec4899; }

.tool-chip {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-2);
  background: var(--border-subtle);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-secondary);
}

.message-text {
  color: var(--text-primary);
  font-size: var(--text-sm);
  line-height: 1.5;
}

.typing-cursor {
  color: var(--accent);
  animation: blink 1s step-end infinite;
}

.live-indicator {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  margin-left: auto;
  font-size: var(--text-xs);
  font-family: var(--font-mono);
  color: var(--accent);
  letter-spacing: var(--tracking-wide);
}

.live-dot {
  width: 6px;
  height: 6px;
  background: var(--accent);
  border-radius: 50%;
  animation: pulse 1.5s infinite;
}


/* ---------- THREAT SCORE GAUGE ---------- */
.threat-score-display {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--space-4);
}

.score-ring {
  position: relative;
  width: 140px;
  height: 140px;
}

.score-ring svg {
  transform: rotate(-90deg);
  width: 100%;
  height: 100%;
}

.ring-bg {
  fill: none;
  stroke: var(--border-subtle);
  stroke-width: 8;
}

.ring-progress {
  fill: none;
  stroke-width: 8;
  stroke-linecap: round;
  stroke-dasharray: 283;
  transition: stroke-dashoffset 1s ease, stroke 0.3s ease;
  filter: drop-shadow(0 0 10px currentColor);
}

.ring-progress.critical { stroke: var(--danger); }
.ring-progress.high { stroke: #f97316; }
.ring-progress.medium { stroke: var(--warning); }
.ring-progress.low { stroke: var(--success); }

.score-value {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  font-family: var(--font-display);
  font-size: var(--text-4xl);
  font-weight: var(--font-bold);
  color: var(--text-primary);
}

.score-percent {
  font-size: var(--text-lg);
  color: var(--text-secondary);
}

.severity-badge {
  padding: var(--space-2) var(--space-4);
  border-radius: var(--radius-full);
  font-size: var(--text-xs);
  font-weight: var(--font-semibold);
  letter-spacing: var(--tracking-wide);
  text-transform: uppercase;
}

.severity-badge.critical { background: var(--danger-dim); color: var(--danger); }
.severity-badge.high { background: rgba(249, 115, 22, 0.2); color: #f97316; }
.severity-badge.medium { background: var(--warning-dim); color: var(--warning); }
.severity-badge.low { background: var(--success-dim); color: var(--success); }


/* ---------- MCP SERVERS STATUS ---------- */
.mcp-servers-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.server-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3);
  background: var(--bg-elevated);
  border-radius: var(--radius-md);
  transition: all 0.2s ease;
}

.server-item:hover {
  background: var(--bg-hover);
}

.server-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-tertiary);
  flex-shrink: 0;
}

.server-item.connected .server-dot {
  background: var(--accent);
  box-shadow: 0 0 10px var(--accent);
  animation: pulse 2s infinite;
}

.server-item.disconnected .server-dot {
  background: var(--danger);
}

.server-item.connecting .server-dot {
  background: var(--warning);
  animation: blink 1s infinite;
}

.server-name {
  font-family: var(--font-display);
  font-size: var(--text-sm);
  font-weight: var(--font-medium);
  color: var(--text-primary);
  flex: 1;
}

.server-port {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-tertiary);
}


/* ---------- STAT CARDS ---------- */
.stat-grid {
  display: flex;
  gap: var(--space-4);
  flex-wrap: wrap;
}

.stat-item {
  flex: 1;
  min-width: 100px;
  padding: var(--space-3);
  background: var(--bg-elevated);
  border-radius: var(--radius-md);
  text-align: center;
}

.stat-label {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-tertiary);
  letter-spacing: var(--tracking-wider);
  text-transform: uppercase;
  display: block;
  margin-bottom: var(--space-2);
}

.stat-value {
  font-family: var(--font-display);
  font-size: var(--text-lg);
  font-weight: var(--font-semibold);
  color: var(--text-primary);
}

.stat-item.danger .stat-value {
  color: var(--danger);
}

.stat-item.success .stat-value {
  color: var(--success);
}

.stat-item.accent .stat-value {
  color: var(--accent);
}


/* ---------- ACTIONS LIST ---------- */
.action-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.action-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3);
  background: var(--bg-elevated);
  border-radius: var(--radius-md);
  transition: all 0.2s ease;
}

.action-item:hover {
  background: var(--bg-hover);
}

.action-number {
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--border-subtle);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: var(--font-semibold);
  color: var(--text-secondary);
}

.action-item.urgent .action-number {
  background: var(--danger-dim);
  color: var(--danger);
}

.action-text {
  flex: 1;
  font-size: var(--text-sm);
  color: var(--text-primary);
}


/* ---------- TECHNIQUE BARS (MITRE) ---------- */
.technique-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.technique-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.technique-id {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  font-weight: var(--font-semibold);
  color: var(--accent);
  min-width: 85px;
  text-decoration: none;
}

.technique-id:hover {
  text-decoration: underline;
}

.technique-bar {
  flex: 1;
  height: 6px;
  background: var(--border-subtle);
  border-radius: var(--radius-full);
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  background: var(--accent);
  border-radius: var(--radius-full);
  width: var(--confidence, 0%);
  transition: width 0.6s ease;
}

.technique-confidence {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-secondary);
  min-width: 35px;
  text-align: right;
}


/* ---------- SIMILAR INCIDENTS ---------- */
.incident-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-4);
}

.incident-card {
  padding: var(--space-4);
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  transition: all 0.2s ease;
}

.incident-card:hover {
  border-color: var(--accent-dim);
  transform: translateY(-2px);
}

.incident-id {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  font-weight: var(--font-semibold);
  color: var(--text-primary);
  margin-bottom: var(--space-2);
}

.similarity-bar {
  height: 4px;
  background: var(--border-subtle);
  border-radius: var(--radius-full);
  margin-bottom: var(--space-3);
  overflow: hidden;
}

.similarity-bar .bar-fill {
  background: linear-gradient(90deg, var(--accent), var(--success));
}

.incident-meta {
  font-size: var(--text-xs);
  color: var(--text-secondary);
}


/* ---------- CHAT INTERFACE ---------- */
.chat-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 400px;
}

.chat-messages {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.chat-message {
  padding: var(--space-4);
  border-radius: var(--radius-lg);
  max-width: 85%;
}

.chat-message.user {
  background: var(--accent-dim);
  border: 1px solid var(--accent);
  margin-left: auto;
}

.chat-message.assistant {
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  margin-right: auto;
}

.chat-input-container {
  display: flex;
  gap: var(--space-3);
  padding: var(--space-4);
  background: var(--bg-surface);
  border-radius: var(--radius-xl);
  border: 1px solid var(--border-subtle);
}

.chat-input {
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text-primary);
  font-family: var(--font-display);
  font-size: var(--text-base);
  outline: none;
}

.chat-send-btn {
  padding: var(--space-3) var(--space-5);
  background: var(--accent);
  color: #000;
  border: none;
  border-radius: var(--radius-lg);
  font-weight: var(--font-semibold);
  cursor: pointer;
  transition: all 0.2s ease;
}

.chat-send-btn:hover {
  background: #00ff99;
  box-shadow: 0 0 20px var(--accent-dim);
}


/* ---------- BUTTONS ---------- */
.bento-button {
  padding: var(--space-3) var(--space-5);
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  font-family: var(--font-display);
  font-size: var(--text-sm);
  font-weight: var(--font-medium);
  color: var(--text-primary);
  cursor: pointer;
  transition: all 0.2s ease;
}

.bento-button:hover {
  background: var(--bg-hover);
  border-color: var(--border-hover);
}

.bento-button.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #000;
}

.bento-button.primary:hover {
  background: #00ff99;
  box-shadow: 0 0 30px var(--accent-dim);
}


/* ---------- ANALYZE BUTTON (HERO) ---------- */
.analyze-button {
  width: 100%;
  padding: var(--space-4) var(--space-6);
  background: var(--accent);
  color: #000;
  border: none;
  border-radius: var(--radius-lg);
  font-family: var(--font-display);
  font-weight: var(--font-semibold);
  font-size: var(--text-sm);
  letter-spacing: var(--tracking-wide);
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
}

.analyze-button:hover {
  background: #00ff99;
  box-shadow: 0 0 30px var(--accent-dim);
  transform: translateY(-1px);
}

.analyze-button:active {
  transform: translateY(0);
}


/* ---------- INPUT OVERRIDES ---------- */
.bento-input textarea,
.bento-input input {
  background: var(--bg-elevated) !important;
  border: 1px solid var(--border-subtle) !important;
  border-radius: var(--radius-md) !important;
  color: var(--text-primary) !important;
  font-family: var(--font-mono) !important;
  padding: var(--space-3) !important;
}

.bento-input textarea:focus,
.bento-input input:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 2px var(--accent-dim) !important;
  outline: none !important;
}


/* ---------- ANIMATIONS ---------- */
@keyframes breathe {
  0%, 100% {
    transform: scale(1);
    opacity: 0.9;
  }
  50% {
    transform: scale(1.02);
    opacity: 1;
  }
}

@keyframes pulse {
  0%, 100% {
    box-shadow: 0 0 0 0 currentColor;
  }
  50% {
    box-shadow: 0 0 0 8px transparent;
  }
}

@keyframes blink {
  0%, 50% { opacity: 1; }
  51%, 100% { opacity: 0; }
}

@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes cardEntrance {
  from {
    opacity: 0;
    transform: translateY(20px) scale(0.95);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@keyframes flowPulse {
  0%, 100% { opacity: 0.5; }
  50% { opacity: 1; }
}

@keyframes countUp {
  from {
    opacity: 0;
    transform: scale(0.5);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}

@keyframes accentGlow {
  0%, 100% {
    filter: drop-shadow(0 0 5px var(--accent));
  }
  50% {
    filter: drop-shadow(0 0 20px var(--accent));
  }
}

/* Staggered card entrance */
.bento-card { animation: cardEntrance 0.5s ease forwards; }
.bento-card:nth-child(1) { animation-delay: 0.0s; }
.bento-card:nth-child(2) { animation-delay: 0.05s; }
.bento-card:nth-child(3) { animation-delay: 0.1s; }
.bento-card:nth-child(4) { animation-delay: 0.15s; }
.bento-card:nth-child(5) { animation-delay: 0.2s; }
.bento-card:nth-child(6) { animation-delay: 0.25s; }


/* ---------- REDUCED MOTION ---------- */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}


/* ---------- RESPONSIVE ---------- */
@media (max-width: 1200px) {
  .bento-grid {
    grid-template-columns: repeat(8, 1fr);
  }
  .bento-4x2, .bento-4x3, .bento-6x2 { grid-column: span 8; }
  .bento-2x2, .bento-2x3, .bento-3x2 { grid-column: span 4; }
}

@media (max-width: 768px) {
  .bento-grid {
    grid-template-columns: repeat(4, 1fr);
  }
  .bento-2x2, .bento-3x2, .bento-4x2, .bento-full { grid-column: span 4; }

  .agent-pipeline {
    flex-wrap: wrap;
    justify-content: center;
  }

  .flow-connector {
    display: none;
  }
}
"""
