"""
Configuration management for SOC Orchestrator
Loads environment variables and provides configuration validation
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration"""

    # Project paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_DIR = PROJECT_ROOT / "data"
    CHROMA_DB_DIR = DATA_DIR / "chroma_db"

    # ===== LLM Provider Configuration =====
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")  # openai, gemini, anthropic, litellm

    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Google Gemini Configuration
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    # Anthropic Claude Configuration
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

    # MCP Server Configuration
    SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
    SIEM_API_KEY = os.getenv("SIEM_API_KEY", "")

    # Security
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-key-change-in-production")

    # LangSmith (Observability)
    LANGCHAIN_TRACING_V2 = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
    LANGCHAIN_API_KEY = os.getenv("LANGCHAIN_API_KEY", "")
    LANGCHAIN_PROJECT = os.getenv("LANGCHAIN_PROJECT", "soc-orchestrator")

    # Environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "true").lower() == "true"

    # Gradio
    GRADIO_SERVER_PORT = int(os.getenv("GRADIO_SERVER_PORT", "7860"))
    GRADIO_SERVER_NAME = os.getenv("GRADIO_SERVER_NAME", "0.0.0.0")

    @classmethod
    def validate(cls) -> None:
        """Validate required configuration based on LLM provider"""
        errors = []

        # Validate LLM provider configuration
        provider = cls.LLM_PROVIDER.lower()

        if provider == "openai":
            if not cls.OPENAI_API_KEY or cls.OPENAI_API_KEY.startswith("sk-your-"):
                errors.append(
                    "OPENAI_API_KEY is required when LLM_PROVIDER=openai\n"
                    "  Get your key from: https://platform.openai.com/account/api-keys"
                )
        elif provider == "gemini":
            if not cls.GOOGLE_API_KEY or cls.GOOGLE_API_KEY == "your-google-api-key-here":
                errors.append(
                    "GOOGLE_API_KEY is required when LLM_PROVIDER=gemini\n"
                    "  Get your FREE key from: https://makersuite.google.com/app/apikey"
                )
        elif provider == "anthropic":
            if not cls.ANTHROPIC_API_KEY:
                errors.append(
                    "ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic\n"
                    "  Get your key from: https://console.anthropic.com/"
                )
        elif provider == "litellm":
            # LiteLLM needs at least one provider configured
            has_any_key = any([
                cls.OPENAI_API_KEY and not cls.OPENAI_API_KEY.startswith("sk-your-"),
                cls.GOOGLE_API_KEY and cls.GOOGLE_API_KEY != "your-google-api-key-here",
                cls.ANTHROPIC_API_KEY
            ])
            if not has_any_key:
                errors.append(
                    "LiteLLM requires at least one LLM provider API key configured\n"
                    "  Set OPENAI_API_KEY, GOOGLE_API_KEY, or ANTHROPIC_API_KEY"
                )
        else:
            errors.append(
                f"Invalid LLM_PROVIDER: {cls.LLM_PROVIDER}\n"
                f"  Supported providers: openai, gemini, anthropic, litellm"
            )

        if errors:
            raise EnvironmentError(
                "\n❌ Configuration validation failed:\n\n" +
                "\n\n".join(f"  • {error}" for error in errors) +
                "\n\nPlease update your .env file with valid configuration."
            )

    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure required directories exist"""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.CHROMA_DB_DIR.mkdir(exist_ok=True)

    @classmethod
    def info(cls) -> dict:
        """Get configuration info (safe for logging)"""
        # Determine active LLM configuration
        provider = cls.LLM_PROVIDER.lower()
        llm_info = {"provider": provider}

        if provider == "openai":
            llm_info.update({
                "model": cls.OPENAI_MODEL,
                "api_key_set": bool(cls.OPENAI_API_KEY and not cls.OPENAI_API_KEY.startswith("sk-your-"))
            })
        elif provider == "gemini":
            llm_info.update({
                "model": cls.GEMINI_MODEL,
                "api_key_set": bool(cls.GOOGLE_API_KEY and cls.GOOGLE_API_KEY != "your-google-api-key-here")
            })
        elif provider == "anthropic":
            llm_info.update({
                "model": cls.ANTHROPIC_MODEL,
                "api_key_set": bool(cls.ANTHROPIC_API_KEY)
            })
        elif provider == "litellm":
            llm_info.update({
                "openai_available": bool(cls.OPENAI_API_KEY and not cls.OPENAI_API_KEY.startswith("sk-your-")),
                "gemini_available": bool(cls.GOOGLE_API_KEY and cls.GOOGLE_API_KEY != "your-google-api-key-here"),
                "anthropic_available": bool(cls.ANTHROPIC_API_KEY)
            })

        return {
            "environment": cls.ENVIRONMENT,
            "debug": cls.DEBUG,
            "llm": llm_info,
            "langsmith_enabled": cls.LANGCHAIN_TRACING_V2,
            "data_dir": str(cls.DATA_DIR),
            "chroma_db_dir": str(cls.CHROMA_DB_DIR),
            "gradio_port": cls.GRADIO_SERVER_PORT,
        }


# Initialize configuration
Config.ensure_directories()

# Validate on import (only in production)
if Config.ENVIRONMENT == "production":
    Config.validate()
