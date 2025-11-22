"""
Global CSS Styles
Extracted from gradio_ui.py for modularity
"""

GLOBAL_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap');

/* === BASE STYLES === */
.gradio-container {
    max-width: 1920px !important;
    background: #000000 !important;
    font-family: 'Inter', 'ui-sans-serif', 'system-ui', sans-serif !important;
}

body {
    background: #000000 !important;
    /* Subtle noise texture for depth */
    background-image:
        radial-gradient(circle at 20% 50%, rgba(255, 255, 255, 0.01) 0%, transparent 50%),
        radial-gradient(circle at 80% 80%, rgba(255, 255, 255, 0.01) 0%, transparent 50%);
}

/* === TYPOGRAPHY === */
h1, h2, h3, h4, h5, h6 {
    font-family: 'Inter', sans-serif !important;
    color: #e8e8e8 !important;
    font-weight: 600 !important;
    letter-spacing: -0.02em;
}

.prose p {
    color: #999999 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.875rem;
    line-height: 1.6;
}

label {
    color: #999999 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.01em;
}

/* === BUTTONS - Ultra Minimal === */
.gr-button {
    border-radius: 8px !important;
    border: 1px solid #1a1a1a !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    letter-spacing: 0;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    background: #000000 !important;
    color: #e8e8e8 !important;
    box-shadow: 0 1px 3px rgba(255, 255, 255, 0.03) !important;
}

.gr-button:hover {
    background: #111111 !important;
    border-color: #333333 !important;
    box-shadow: 0 0 12px rgba(255, 255, 255, 0.06) !important;
    transform: translateY(-1px);
}

.gr-button-primary {
    border-color: #e8e8e8 !important;
}

.gr-button-primary:hover {
    box-shadow: 0 0 16px rgba(232, 232, 232, 0.1) !important;
}

/* === INPUTS === */
.gr-box {
    border-radius: 8px !important;
    border: 1px solid #1a1a1a !important;
    background: #000000 !important;
}

.gr-input, .gr-textarea, select {
    border-radius: 8px !important;
    border: 1px solid #1a1a1a !important;
    background: #000000 !important;
    color: #e8e8e8 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.875rem !important;
    transition: all 0.2s ease !important;
}

.gr-input:focus, .gr-textarea:focus, select:focus {
    border-color: #e8e8e8 !important;
    box-shadow: 0 0 8px rgba(255, 255, 255, 0.08) !important;
    outline: none !important;
}

/* === SCROLLBAR - Minimal === */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: #000000;
}

::-webkit-scrollbar-thumb {
    background: #1a1a1a;
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: #333333;
}

/* === CARD CONTAINERS - Ultra Minimal === */
#reasoning_card, #results_card {
    background: #000000 !important;
    border: 1px solid #1a1a1a !important;
    border-radius: 12px !important;
    padding: 28px !important;
    box-shadow:
        0 1px 3px rgba(255, 255, 255, 0.03),
        inset 0 0 0 1px rgba(255, 255, 255, 0.02) !important;
    transition: all 0.3s ease !important;
}

#reasoning_card:hover, #results_card:hover {
    border-color: #333333 !important;
    box-shadow:
        0 2px 6px rgba(255, 255, 255, 0.05),
        inset 0 0 0 1px rgba(255, 255, 255, 0.03),
        0 0 20px rgba(255, 255, 255, 0.04) !important;
}

#sidebar_card:hover {
    border-color: #333333 !important;
    box-shadow:
        0 2px 6px rgba(255, 255, 255, 0.05),
        inset 0 0 0 1px rgba(255, 255, 255, 0.03),
        0 0 20px rgba(255, 255, 255, 0.04) !important;
}

/* === SIDEBAR LAYOUT === */
#main_container {
    gap: 24px !important;
    align-items: stretch !important;
}

#sidebar {
    min-width: 420px !important;
    max-width: 500px !important;
    flex-shrink: 0 !important;
}

#sidebar_card {
    height: 100% !important;
}

#content_area {
    display: flex !important;
    flex-direction: column !important;
    gap: 20px !important;
    flex: 1 !important;
    min-width: 900px !important;
}

.gradio-row {
    gap: 24px !important;
}

/* === SIDEBAR STYLING === */
#sidebar_card {
    background: #000000 !important;
    border: 1px solid #1a1a1a !important;
    border-radius: 12px !important;
    padding: 28px !important;
    box-shadow:
        0 1px 3px rgba(255, 255, 255, 0.03),
        inset 0 0 0 1px rgba(255, 255, 255, 0.02) !important;
}

#alert_input {
    border: 1px solid #1a1a1a !important;
    border-radius: 8px !important;
    margin-top: 10px !important;
    margin-bottom: 14px !important;
    background: #000000 !important;
    font-size: 0.85rem !important;
}

#alert_dropdown {
    margin-bottom: 12px !important;
}

#investigate_btn {
    margin-top: 16px !important;
    width: 100% !important;
    font-size: 1rem !important;
    padding: 14px 20px !important;
}

/* === STATUS IN SIDEBAR === */
#status_compact {
    margin-top: 0 !important;
}

.status-compact {
    font-family: 'JetBrains Mono', monospace !important;
    color: #999999 !important;
    font-size: 0.8rem !important;
}

.status-compact .metric-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid #1a1a1a;
}

.status-compact .metric-row:last-child {
    border-bottom: none;
}

.status-compact .metric-label {
    color: #999999;
    font-size: 0.75rem;
    font-weight: 500;
    letter-spacing: 0.01em;
}

.status-compact .metric-value {
    color: #e8e8e8;
    font-weight: 600;
    font-size: 0.8rem;
}

/* === PROGRESS BAR - Minimal === */
.progress-bar-container {
    background: #0a0a0a !important;
    border: 1px solid #1a1a1a !important;
    border-radius: 4px !important;
    height: 6px !important;
    overflow: hidden !important;
    margin: 10px 0 !important;
}

.progress-bar {
    background: linear-gradient(90deg, #e8e8e8 0%, #999999 100%) !important;
    height: 100% !important;
    transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    box-shadow: 0 0 10px rgba(232, 232, 232, 0.2) !important;
}

/* === CARD HEADERS - Minimal Style === */
.card-header {
    font-family: 'Inter', sans-serif !important;
    color: #e8e8e8 !important;
    font-size: 1.1rem !important;
    font-weight: 600 !important;
    margin-bottom: 8px !important;
    letter-spacing: -0.01em;
}

.card-description {
    font-family: 'Inter', sans-serif !important;
    color: #999999 !important;
    font-size: 0.85rem !important;
    margin-bottom: 20px !important;
    line-height: 1.5;
    font-weight: 400;
}

/* === REASONING PANEL - Clean Display (HERO SIZE) === */
#reasoning_panel {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.875rem !important;
    line-height: 1.8 !important;
    background: transparent !important;
    border: none !important;
    padding: 0 !important;
    color: #e8e8e8 !important;
    min-height: 400px !important;
    max-height: 500px !important;
    overflow-y: auto !important;
}

/* Reasoning card - primary focus */
#reasoning_card {
    flex: 1 !important;
    margin-bottom: 0 !important;
}

/* Results card */
#results_card {
    flex: 0.6 !important;
}

#reasoning_panel * {
    background: transparent !important;
}

/* Reasoning Panel Markdown Elements */
#reasoning_panel p {
    color: #e8e8e8 !important;
    margin-bottom: 12px !important;
    font-family: 'JetBrains Mono', monospace !important;
}

#reasoning_panel strong {
    color: #e8e8e8 !important;
    font-weight: 600 !important;
}

#reasoning_panel em {
    color: #999999 !important;
    font-style: italic !important;
}

#reasoning_panel ul, #reasoning_panel ol {
    color: #e8e8e8 !important;
    margin-left: 20px !important;
    margin-bottom: 12px !important;
}

#reasoning_panel li {
    margin-bottom: 6px !important;
    color: #999999 !important;
}

#reasoning_panel h1, #reasoning_panel h2, #reasoning_panel h3, #reasoning_panel h4 {
    color: #e8e8e8 !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    margin-top: 16px !important;
    margin-bottom: 12px !important;
    letter-spacing: -0.01em;
}

#reasoning_panel code {
    background: rgba(255, 255, 255, 0.04) !important;
    color: #e8e8e8 !important;
    padding: 3px 6px !important;
    border-radius: 4px !important;
    font-family: 'JetBrains Mono', monospace !important;
    border: 1px solid #1a1a1a !important;
}

#reasoning_panel pre {
    background: rgba(255, 255, 255, 0.02) !important;
    border: 1px solid #1a1a1a !important;
    padding: 16px !important;
    border-radius: 8px !important;
    overflow-x: auto !important;
}

#reasoning_panel blockquote {
    border-left: 2px solid #333333 !important;
    padding-left: 16px !important;
    margin: 12px 0 !important;
    color: #999999 !important;
}

/* === RESULTS HTML === */
#result_html {
    min-height: 300px !important;
}

/* === REMOVE DEFAULT GRADIO STYLES === */
.gr-box {
    border: none !important;
    background: transparent !important;
}

/* === PAGE PADDING === */
.gradio-container {
    padding: 40px !important;
}

/* === TABS === */
.gradio-tabs {
    border: none !important;
    background: transparent !important;
}

.gradio-tabs .tab-nav {
    border-bottom: 1px solid #1a1a1a !important;
    margin-bottom: 24px !important;
    gap: 0 !important;
}

.gradio-tabs button {
    border: none !important;
    border-bottom: 2px solid transparent !important;
    background: transparent !important;
    color: #999999 !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.95rem !important;
    padding: 12px 24px !important;
    transition: all 0.2s ease !important;
    border-radius: 0 !important;
}

.gradio-tabs button.selected {
    color: #e8e8e8 !important;
    border-bottom-color: #e8e8e8 !important;
}

.gradio-tabs button:hover {
    color: #e8e8e8 !important;
    background: rgba(255, 255, 255, 0.02) !important;
}

/* Memory Context Cards */
#memory_reasoning_card, #similar_incidents_card {
    background: #000000 !important;
    border: 1px solid #1a1a1a !important;
    border-radius: 12px !important;
    padding: 28px !important;
    margin-bottom: 20px !important;
    box-shadow:
        0 1px 3px rgba(255, 255, 255, 0.03),
        inset 0 0 0 1px rgba(255, 255, 255, 0.02) !important;
    transition: all 0.3s ease !important;
}

#memory_reasoning_card:hover, #similar_incidents_card:hover {
    border-color: #333333 !important;
    box-shadow:
        0 2px 6px rgba(255, 255, 255, 0.05),
        inset 0 0 0 1px rgba(255, 255, 255, 0.03),
        0 0 20px rgba(255, 255, 255, 0.04) !important;
}

/* Chat Card */
#chat_card {
    background: #000000 !important;
    border: 1px solid #1a1a1a !important;
    border-radius: 12px !important;
    padding: 28px !important;
}

/* === MICRO ANIMATIONS === */
* {
    transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease !important;
}
"""

# Auto-scroll JavaScript for reasoning panel
AUTO_SCROLL_JS = """
function setupAutoScroll() {
    // Auto-scroll reasoning panel when content updates
    const setupObserver = () => {
        // Try multiple selectors to find the scrollable container
        const reasoningPanel = document.querySelector('#reasoning_panel');

        if (reasoningPanel) {
            // Find the actual scrollable element (might be nested)
            const findScrollable = (el) => {
                if (!el) return null;
                const style = window.getComputedStyle(el);
                if (style.overflowY === 'auto' || style.overflowY === 'scroll') {
                    return el;
                }
                // Check children
                for (let child of el.children) {
                    const found = findScrollable(child);
                    if (found) return found;
                }
                return el; // Default to the panel itself
            };

            const scrollContainer = findScrollable(reasoningPanel) || reasoningPanel;

            // Create a MutationObserver to watch for content changes
            const observer = new MutationObserver((mutations) => {
                // Use requestAnimationFrame for smooth scrolling
                requestAnimationFrame(() => {
                    scrollContainer.scrollTop = scrollContainer.scrollHeight;
                });
            });

            // Start observing
            observer.observe(reasoningPanel, {
                childList: true,
                subtree: true,
                characterData: true
            });

            // Initial scroll
            scrollContainer.scrollTop = scrollContainer.scrollHeight;

            console.log('[SOC] Auto-scroll enabled for reasoning panel');
        } else {
            // Retry after a short delay if element not found
            setTimeout(setupObserver, 500);
        }
    };

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupObserver);
    } else {
        setupObserver();
    }

    return [];
}
"""
