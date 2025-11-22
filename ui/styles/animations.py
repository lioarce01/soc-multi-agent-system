"""
CSS Animation Keyframes
Dedicated animation definitions for UI enhancements
"""

# Agent-specific colors for animations
AGENT_COLORS = {
    "supervisor": "#3b82f6",    # Blue
    "enrichment": "#10b981",    # Green
    "analysis": "#f59e0b",      # Amber
    "investigation": "#8b5cf6", # Purple
    "response": "#ef4444",      # Red
    "communication": "#06b6d4", # Cyan
    "memory": "#ec4899",        # Pink
}

# Severity colors
SEVERITY_COLORS = {
    "low": "#10b981",       # Green
    "medium": "#f59e0b",    # Amber
    "high": "#f97316",      # Orange
    "critical": "#ef4444",  # Red
}


ANIMATION_KEYFRAMES = """
/* ========================================
   SOC ORCHESTRATOR - ANIMATION KEYFRAMES
   ======================================== */

/* === PULSE EFFECTS === */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

@keyframes pulse-ring {
    0% { transform: scale(0.95); opacity: 0.7; }
    50% { transform: scale(1); opacity: 1; }
    100% { transform: scale(0.95); opacity: 0.7; }
}

@keyframes pulse-glow {
    0%, 100% { box-shadow: 0 0 5px currentColor, 0 0 10px currentColor; }
    50% { box-shadow: 0 0 15px currentColor, 0 0 25px currentColor; }
}

/* === GLOW EFFECTS === */
@keyframes glow {
    0%, 100% { box-shadow: 0 0 5px currentColor; }
    50% { box-shadow: 0 0 20px currentColor; }
}

@keyframes glow-intense {
    0%, 100% {
        box-shadow: 0 0 5px currentColor, 0 0 10px currentColor;
        filter: brightness(1);
    }
    50% {
        box-shadow: 0 0 20px currentColor, 0 0 40px currentColor;
        filter: brightness(1.2);
    }
}

/* === SLIDE ANIMATIONS === */
@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes slideInLeft {
    from { transform: translateX(-100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes slideInUp {
    from { transform: translateY(20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}

/* === FADE ANIMATIONS === */
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

@keyframes fadeInUp {
    from { transform: translateY(10px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}

@keyframes fadeInScale {
    from { transform: scale(0.95); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
}

/* === COUNT UP / NUMBER ANIMATIONS === */
@keyframes countUp {
    from { opacity: 0; transform: scale(0.5); }
    to { opacity: 1; transform: scale(1); }
}

@keyframes numberPop {
    0% { transform: scale(1); }
    50% { transform: scale(1.1); }
    100% { transform: scale(1); }
}

/* === CHECKMARK ANIMATION === */
@keyframes drawCheck {
    0% { stroke-dashoffset: 100; }
    100% { stroke-dashoffset: 0; }
}

@keyframes checkPop {
    0% { transform: scale(0); opacity: 0; }
    50% { transform: scale(1.2); }
    100% { transform: scale(1); opacity: 1; }
}

/* === SHAKE ANIMATION (for critical alerts) === */
@keyframes shake {
    0%, 100% { transform: translateX(0); }
    10%, 30%, 50%, 70%, 90% { transform: translateX(-2px); }
    20%, 40%, 60%, 80% { transform: translateX(2px); }
}

@keyframes shakeIntense {
    0%, 100% { transform: translateX(0) rotate(0deg); }
    25% { transform: translateX(-4px) rotate(-1deg); }
    75% { transform: translateX(4px) rotate(1deg); }
}

/* === TYPING / CURSOR ANIMATIONS === */
@keyframes blink {
    0%, 50% { opacity: 1; }
    51%, 100% { opacity: 0; }
}

@keyframes typing-dots {
    0%, 20% { content: '.'; }
    40% { content: '..'; }
    60%, 100% { content: '...'; }
}

/* === SPINNER / LOADING ANIMATIONS === */
@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

@keyframes spinPulse {
    0% { transform: rotate(0deg) scale(1); }
    50% { transform: rotate(180deg) scale(1.1); }
    100% { transform: rotate(360deg) scale(1); }
}

/* === PROGRESS BAR ANIMATIONS === */
@keyframes progressShine {
    0% { background-position: -200% 0; }
    100% { background-position: 200% 0; }
}

@keyframes progressPulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.8; }
}

/* === RIPPLE EFFECT === */
@keyframes ripple {
    0% { transform: scale(0); opacity: 0.5; }
    100% { transform: scale(4); opacity: 0; }
}

/* === CELEBRATION / SUCCESS === */
@keyframes celebratePop {
    0% { transform: scale(1); }
    25% { transform: scale(1.05); }
    50% { transform: scale(0.95); }
    100% { transform: scale(1); }
}

@keyframes successGlow {
    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
    70% { box-shadow: 0 0 0 15px rgba(16, 185, 129, 0); }
    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* === AGENT-SPECIFIC PULSE COLORS === */
@keyframes pulse-supervisor {
    0%, 100% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(59, 130, 246, 0); }
}

@keyframes pulse-enrichment {
    0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
}

@keyframes pulse-analysis {
    0%, 100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(245, 158, 11, 0); }
}

@keyframes pulse-investigation {
    0%, 100% { box-shadow: 0 0 0 0 rgba(139, 92, 246, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(139, 92, 246, 0); }
}

@keyframes pulse-response {
    0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
}

@keyframes pulse-communication {
    0%, 100% { box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(6, 182, 212, 0); }
}

@keyframes pulse-memory {
    0%, 100% { box-shadow: 0 0 0 0 rgba(236, 72, 153, 0.4); }
    50% { box-shadow: 0 0 0 8px rgba(236, 72, 153, 0); }
}

/* === THREAT LEVEL ANIMATIONS === */
@keyframes threat-low {
    0%, 100% { box-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }
    50% { box-shadow: 0 0 20px rgba(16, 185, 129, 0.5); }
}

@keyframes threat-medium {
    0%, 100% { box-shadow: 0 0 10px rgba(245, 158, 11, 0.3); }
    50% { box-shadow: 0 0 25px rgba(245, 158, 11, 0.6); }
}

@keyframes threat-high {
    0%, 100% { box-shadow: 0 0 15px rgba(249, 115, 22, 0.4); }
    50% { box-shadow: 0 0 30px rgba(249, 115, 22, 0.7); }
}

@keyframes threat-critical {
    0%, 100% {
        box-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
        transform: scale(1);
    }
    50% {
        box-shadow: 0 0 40px rgba(239, 68, 68, 0.8);
        transform: scale(1.02);
    }
}

/* === REDUCED MOTION SUPPORT === */
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}
"""

# Animation utility classes
ANIMATION_CLASSES = """
/* ========================================
   ANIMATION UTILITY CLASSES
   ======================================== */

/* Pulse classes */
.animate-pulse { animation: pulse 2s ease-in-out infinite; }
.animate-pulse-ring { animation: pulse-ring 1.5s ease-in-out infinite; }
.animate-pulse-glow { animation: pulse-glow 2s ease-in-out infinite; }

/* Glow classes */
.animate-glow { animation: glow 2s ease-in-out infinite; }
.animate-glow-intense { animation: glow-intense 1.5s ease-in-out infinite; }

/* Slide classes */
.animate-slide-in-right { animation: slideInRight 0.3s ease-out forwards; }
.animate-slide-in-left { animation: slideInLeft 0.3s ease-out forwards; }
.animate-slide-in-up { animation: slideInUp 0.3s ease-out forwards; }

/* Fade classes */
.animate-fade-in { animation: fadeIn 0.3s ease-out forwards; }
.animate-fade-in-up { animation: fadeInUp 0.3s ease-out forwards; }
.animate-fade-in-scale { animation: fadeInScale 0.3s ease-out forwards; }

/* Special effects */
.animate-shake { animation: shake 0.5s ease-in-out; }
.animate-shake-intense { animation: shakeIntense 0.3s ease-in-out infinite; }
.animate-spin { animation: spin 1s linear infinite; }
.animate-check-pop { animation: checkPop 0.4s ease-out forwards; }
.animate-success-glow { animation: successGlow 1s ease-out; }

/* Agent-specific pulse */
.animate-pulse-supervisor { animation: pulse-supervisor 1.5s ease-in-out infinite; }
.animate-pulse-enrichment { animation: pulse-enrichment 1.5s ease-in-out infinite; }
.animate-pulse-analysis { animation: pulse-analysis 1.5s ease-in-out infinite; }
.animate-pulse-investigation { animation: pulse-investigation 1.5s ease-in-out infinite; }
.animate-pulse-response { animation: pulse-response 1.5s ease-in-out infinite; }
.animate-pulse-communication { animation: pulse-communication 1.5s ease-in-out infinite; }
.animate-pulse-memory { animation: pulse-memory 1.5s ease-in-out infinite; }

/* Threat level animations */
.animate-threat-low { animation: threat-low 3s ease-in-out infinite; }
.animate-threat-medium { animation: threat-medium 2.5s ease-in-out infinite; }
.animate-threat-high { animation: threat-high 2s ease-in-out infinite; }
.animate-threat-critical { animation: threat-critical 1s ease-in-out infinite; }

/* Typing cursor */
.typing-cursor::after {
    content: '█';
    animation: blink 0.7s infinite;
}

/* Progress bar shine effect */
.progress-shine {
    background: linear-gradient(
        90deg,
        transparent 0%,
        rgba(255, 255, 255, 0.2) 50%,
        transparent 100%
    );
    background-size: 200% 100%;
    animation: progressShine 2s linear infinite;
}
"""

# JavaScript for dynamic animations (threat score counter, etc.)
ANIMATION_JS = """
// Threat Score Counter Animation
function animateThreatScore(elementId, targetScore, duration = 1500) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const startTime = performance.now();
    const startValue = 0;

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function (ease-out-cubic)
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const currentValue = Math.round(startValue + (targetScore - startValue) * easeOut);

        element.textContent = currentValue + '%';

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            // Add pop effect on completion
            element.style.transform = 'scale(1.1)';
            setTimeout(() => {
                element.style.transform = 'scale(1)';
            }, 150);
        }
    }

    requestAnimationFrame(update);
}

// Step completion animation
function animateStepComplete(stepElement) {
    if (!stepElement) return;

    // Add completion animation
    stepElement.classList.add('animate-check-pop');
    stepElement.classList.add('animate-success-glow');

    // Remove animation classes after completion
    setTimeout(() => {
        stepElement.classList.remove('animate-check-pop');
        stepElement.classList.remove('animate-success-glow');
    }, 1000);
}

// Agent thinking indicator
function showAgentThinking(agentName) {
    const agentElements = document.querySelectorAll(`[data-agent="${agentName}"]`);
    agentElements.forEach(el => {
        el.classList.add(`animate-pulse-${agentName}`);
    });
}

function hideAgentThinking(agentName) {
    const agentElements = document.querySelectorAll(`[data-agent="${agentName}"]`);
    agentElements.forEach(el => {
        el.classList.remove(`animate-pulse-${agentName}`);
    });
}

// Initialize animations on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('[SOC] Animation system initialized');
});
"""


def get_full_animation_css() -> str:
    """Get complete animation CSS (keyframes + utility classes)"""
    return ANIMATION_KEYFRAMES + "\n" + ANIMATION_CLASSES


def get_animation_js() -> str:
    """Get animation JavaScript"""
    return ANIMATION_JS
