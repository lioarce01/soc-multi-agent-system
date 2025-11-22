"""UI Styles - CSS and styling constants"""

from ui.styles.css import GLOBAL_CSS, AUTO_SCROLL_JS
from ui.styles.animations import (
    ANIMATION_KEYFRAMES,
    ANIMATION_CLASSES,
    ANIMATION_JS,
    get_full_animation_css,
    get_animation_js,
    AGENT_COLORS,
    SEVERITY_COLORS,
)
from ui.styles.bento_css import get_bento_css

__all__ = [
    "GLOBAL_CSS",
    "AUTO_SCROLL_JS",
    "ANIMATION_KEYFRAMES",
    "ANIMATION_CLASSES",
    "ANIMATION_JS",
    "get_full_animation_css",
    "get_animation_js",
    "AGENT_COLORS",
    "SEVERITY_COLORS",
    "get_bento_css",
]
