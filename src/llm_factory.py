"""
LLM Factory - Abstraction layer for different LLM providers
Supports OpenAI, Google Gemini, and other providers
"""

import os
from typing import Literal, Optional
from langchain_core.language_models.chat_models import BaseChatModel


LLMProvider = Literal["openai", "gemini", "anthropic", "litellm"]


def get_llm(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.0,
    streaming: bool = False,
    **kwargs
) -> BaseChatModel:
    """
    Factory function to get LLM instance based on provider

    Args:
        provider: LLM provider ("openai", "gemini", "anthropic", "litellm")
                 If None, reads from LLM_PROVIDER env var (defaults to "openai")
        model: Model name. If None, uses provider-specific defaults
        temperature: Model temperature (0.0 to 1.0)
        streaming: Enable streaming responses
        **kwargs: Additional provider-specific parameters

    Returns:
        BaseChatModel instance

    Raises:
        ValueError: If provider is not supported
        EnvironmentError: If required API key is missing

    Examples:
        # Use Gemini
        llm = get_llm(provider="gemini", model="gemini-1.5-flash")

        # Use OpenAI (default)
        llm = get_llm(model="gpt-4o-mini")

        # Use LiteLLM gateway (supports all providers)
        llm = get_llm(provider="litellm", model="gemini/gemini-1.5-flash")
    """
    # Get provider from env if not specified
    if provider is None:
        provider = os.getenv("LLM_PROVIDER", "openai").lower()

    provider = provider.lower()

    # ===== OPENAI =====
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key or api_key.startswith("sk-your-"):
            raise EnvironmentError(
                "OPENAI_API_KEY not configured. "
                "Get your API key from https://platform.openai.com/account/api-keys"
            )

        default_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        return ChatOpenAI(
            model=model or default_model,
            temperature=temperature,
            streaming=streaming,
            api_key=api_key,
            **kwargs
        )

    # ===== GOOGLE GEMINI =====
    elif provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GOOGLE_API_KEY not configured. "
                "Get your API key from https://makersuite.google.com/app/apikey"
            )

        default_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

        return ChatGoogleGenerativeAI(
            model=model or default_model,
            temperature=temperature,
            streaming=streaming,
            google_api_key=api_key,
            **kwargs
        )

    # ===== ANTHROPIC CLAUDE =====
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY not configured. "
                "Get your API key from https://console.anthropic.com/"
            )

        default_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

        return ChatAnthropic(
            model=model or default_model,
            temperature=temperature,
            streaming=streaming,
            anthropic_api_key=api_key,
            **kwargs
        )

    # ===== LITELLM (Gateway for all providers) =====
    elif provider == "litellm":
        from langchain_community.chat_models import ChatLiteLLM

        # LiteLLM uses provider-specific env vars (OPENAI_API_KEY, GOOGLE_API_KEY, etc.)
        # Model format: "provider/model" (e.g., "gemini/gemini-1.5-flash", "openai/gpt-4")

        if not model:
            # Default to gemini if no model specified
            model = os.getenv("LITELLM_MODEL", "gemini/gemini-1.5-flash")

        return ChatLiteLLM(
            model=model,
            temperature=temperature,
            streaming=streaming,
            **kwargs
        )

    else:
        raise ValueError(
            f"Unsupported LLM provider: {provider}. "
            f"Supported providers: openai, gemini, anthropic, litellm"
        )


def get_available_providers() -> dict[str, bool]:
    """
    Check which LLM providers are configured (have valid API keys)

    Returns:
        Dict mapping provider name to availability status
    """
    providers = {}

    # OpenAI
    openai_key = os.getenv("OPENAI_API_KEY", "")
    providers["openai"] = bool(openai_key and not openai_key.startswith("sk-your-"))

    # Google Gemini
    providers["gemini"] = bool(os.getenv("GOOGLE_API_KEY"))

    # Anthropic Claude
    providers["anthropic"] = bool(os.getenv("ANTHROPIC_API_KEY"))

    # LiteLLM (available if any provider key exists)
    providers["litellm"] = any([
        providers["openai"],
        providers["gemini"],
        providers["anthropic"]
    ])

    return providers
