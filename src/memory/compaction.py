"""
Auto-Compaction for Context Engineering
Prevents token limit errors by intelligently compacting message history
"""

from typing import List, Optional
from langchain_core.messages import BaseMessage, SystemMessage, AIMessage, HumanMessage


def count_tokens(messages: List[BaseMessage]) -> int:
    """
    Approximate token count from messages
    
    Uses rule of thumb: ~4 characters = 1 token
    This is a conservative estimate (actual ratio varies by model)
    
    Args:
        messages: List of message objects
    
    Returns:
        Approximate token count
    """
    total_chars = sum(len(str(msg.content)) for msg in messages if hasattr(msg, 'content') and msg.content)
    return total_chars // 4


def should_compact(messages: List[BaseMessage], max_tokens: int = 100000) -> bool:
    """
    Check if message compaction is needed
    
    Compaction is triggered when token usage exceeds 80% of max_tokens
    This provides a safety margin before hitting token limits
    
    Args:
        messages: List of message objects
        max_tokens: Maximum token limit (default: 100k, typical for GPT-4)
    
    Returns:
        True if compaction needed, False otherwise
    """
    if not messages:
        return False
    
    current_tokens = count_tokens(messages)
    threshold = int(max_tokens * 0.8)  # 80% threshold
    
    return current_tokens > threshold


async def auto_compact_messages(
    messages: List[BaseMessage],
    keep_recent: int = 5,
    llm = None
) -> List[BaseMessage]:
    """
    Auto-compact message history to reduce token usage
    
    Strategy:
    1. Keep all system messages (important context)
    2. Keep recent N messages (maintain conversation flow)
    3. Summarize older messages into a single summary message
    
    Args:
        messages: List of message objects to compact
        keep_recent: Number of recent messages to keep (default: 5)
        llm: LLM instance for summarization (optional, falls back to simple truncation)
    
    Returns:
        Compacted list of messages
    """
    if not messages:
        return messages
    
    # Separate messages by type
    system_messages = []
    recent_messages = []
    older_messages = []
    
    # Keep all system messages
    for msg in messages:
        if isinstance(msg, SystemMessage):
            system_messages.append(msg)
        else:
            older_messages.append(msg)
    
    # Keep recent N non-system messages
    if len(older_messages) > keep_recent:
        recent_messages = older_messages[-keep_recent:]
        older_messages = older_messages[:-keep_recent]
    else:
        recent_messages = older_messages
        older_messages = []
    
    # If no older messages to compact, return as-is
    if not older_messages:
        return system_messages + recent_messages
    
    # Summarize older messages
    summary_message = await _summarize_messages(older_messages, llm)
    
    # Reconstruct compacted message list
    compacted = system_messages + [summary_message] + recent_messages
    
    print(f"[COMPACTION] ✅ Compacted {len(messages)} messages → {len(compacted)} messages")
    print(f"  - System messages kept: {len(system_messages)}")
    print(f"  - Older messages summarized: {len(older_messages)}")
    print(f"  - Recent messages kept: {len(recent_messages)}")
    
    return compacted


async def _summarize_messages(
    messages: List[BaseMessage],
    llm = None
) -> BaseMessage:
    """
    Summarize a list of messages into a single summary message
    
    Args:
        messages: List of messages to summarize
        llm: LLM instance for summarization (optional)
    
    Returns:
        Summary message (AIMessage)
    """
    if not messages:
        return AIMessage(content="[No messages to summarize]")
    
    # If LLM available, use it for intelligent summarization
    if llm is not None:
        try:
            from langchain_core.messages import SystemMessage, HumanMessage
            
            # Build summary prompt
            message_texts = []
            for msg in messages:
                msg_type = type(msg).__name__
                content = str(msg.content) if hasattr(msg, 'content') and msg.content else ""
                if content:
                    message_texts.append(f"[{msg_type}]: {content[:200]}...")  # Truncate long messages
            
            messages_text = "\n".join(message_texts)
            
            summary_prompt = f"""Summarize the following conversation history in 2-3 concise sentences.
Focus on key decisions, findings, and important context.

Conversation History:
{messages_text}

Provide a concise summary:"""
            
            summary_messages = [
                SystemMessage(content="You are a helpful assistant that summarizes conversation history concisely."),
                HumanMessage(content=summary_prompt)
            ]
            
            response = await llm.ainvoke(summary_messages)
            summary_text = f"[COMPACTED HISTORY] {response.content}"
            
            return AIMessage(content=summary_text)
            
        except Exception as e:
            print(f"[COMPACTION] ⚠️  LLM summarization failed: {e}, using simple truncation")
            # Fall through to simple truncation
    
    # Fallback: Simple truncation-based summary
    total_messages = len(messages)
    message_preview = []
    
    for i, msg in enumerate(messages[:3]):  # Show first 3 messages
        msg_type = type(msg).__name__
        content = str(msg.content) if hasattr(msg, 'content') and msg.content else ""
        if content:
            preview = content[:100] + "..." if len(content) > 100 else content
            message_preview.append(f"{msg_type}: {preview}")
    
    summary_text = (
        f"[COMPACTED HISTORY] {total_messages} previous messages summarized. "
        f"Key points: {'; '.join(message_preview)}"
    )
    
    if total_messages > 3:
        summary_text += f" ... and {total_messages - 3} more messages."
    
    return AIMessage(content=summary_text)

