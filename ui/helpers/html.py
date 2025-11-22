"""
HTML Helper Functions
Sanitization and markdown conversion utilities
"""

import html
import re
from typing import Any


def sanitize_html(text: Any) -> str:
    """
    Escape HTML to prevent XSS attacks

    Args:
        text: Any input that will be rendered in HTML

    Returns:
        HTML-escaped string
    """
    return html.escape(str(text))


def markdown_to_html(text: str) -> str:
    """
    Convert basic markdown to HTML for agent reasoning display
    Handles: **bold**, *italic*, `code`, lists, headers

    Args:
        text: Markdown text to convert

    Returns:
        HTML formatted string
    """
    # Escape HTML first but preserve our markdown
    text = html.escape(text)

    # Convert markdown to HTML
    # Headers (## Header)
    text = re.sub(r'^### (.+)$', r'<strong style="color: #f59e0b;">\1</strong>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.+)$', r'<strong style="color: #f59e0b;">\1</strong>', text, flags=re.MULTILINE)
    text = re.sub(r'^\*\*(\d+)\. (.+?)\*\*$', r'<strong>\1. \2</strong>', text, flags=re.MULTILINE)

    # Bold (**text**)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)

    # Italic (*text*) - but not bullet points
    text = re.sub(r'(?<!\*)\*([^*\n]+?)\*(?!\*)', r'<em>\1</em>', text)

    # Inline code (`code`)
    text = re.sub(
        r'`([^`]+)`',
        r'<code style="background: #1a1a2e; padding: 2px 6px; border-radius: 4px; font-family: monospace;">\1</code>',
        text
    )

    # Bullet points (* item or - item)
    text = re.sub(r'^[\*\-] (.+)$', r'<span style="color: #888;">•</span> \1', text, flags=re.MULTILINE)

    # Numbered lists (1. item)
    text = re.sub(r'^(\d+)\. (.+)$', r'<span style="color: #3b82f6;">\1.</span> \2', text, flags=re.MULTILINE)

    # Convert newlines to <br>
    text = text.replace('\n', '<br>')

    return text
