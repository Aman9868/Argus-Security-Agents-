"""Application configuration using Pydantic Settings."""

import os
from typing import Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8001
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "b912c75a40b84742a0b1f3c834a78e72619028a1c9ef028a47814bfa4d89e271"

    # Redis Cache & Idempotency Store
    REDIS_URL: str = "redis://127.0.0.1:6379/0"

    # LLM Gateway
    LLM_PROVIDER: str = "groq"
    # Google Gemini
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GEMINI_PROJECT_ID: Optional[str] = None
    GEMINI_PROJECT_NO: Optional[str] = None

    # Groq
    GROQ_API_KEY: str = ""
    GROQ_ROUTING_MODEL: str = "openai/gpt-oss-20b"
    GROQ_REASONING_MODEL: str = "openai/gpt-oss-120b"

    # LangSmith Tracing & Observability
    LANGCHAIN_TRACING_V2: str = "true"
    LANGCHAIN_ENDPOINT: str = "https://api.smith.langchain.com"
    LANGCHAIN_API_KEY: Optional[str] = None
    LANGCHAIN_PROJECT: str = "cyber-agent-prod"

    # External Threat Intelligence APIs
    VIRUSTOTAL_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    NVD_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # Rate Limiting & Safety Thresholds
    RATE_LIMIT_IP_PER_MINUTE: int = 100
    CONTAINMENT_HITL_THRESHOLD: float = 0.75

    @field_validator("API_PORT", mode="before")
    @classmethod
    def parse_api_port(cls, v):
        if v is None or v == "" or (isinstance(v, str) and not v.strip()):
            return 8001
        return int(v)

    @field_validator("RATE_LIMIT_IP_PER_MINUTE", mode="before")
    @classmethod
    def parse_rate_limit(cls, v):
        if v is None or v == "" or (isinstance(v, str) and not v.strip()):
            return 100
        return int(v)

    @field_validator("CONTAINMENT_HITL_THRESHOLD", mode="before")
    @classmethod
    def parse_containment_threshold(cls, v):
        if v is None or v == "" or (isinstance(v, str) and not v.strip()):
            return 0.75
        return float(v)

    @field_validator("SECRET_KEY", mode="before")
    @classmethod
    def parse_secret_key(cls, v):
        if not v or (isinstance(v, str) and not v.strip()):
            return "b912c75a40b84742a0b1f3c834a78e72619028a1c9ef028a47814bfa4d89e271"
        return v

    @field_validator("API_HOST", mode="before")
    @classmethod
    def parse_api_host(cls, v):
        if not v or (isinstance(v, str) and not v.strip()):
            return "127.0.0.1"
        return v

    @field_validator("ENVIRONMENT", mode="before")
    @classmethod
    def parse_environment(cls, v):
        if not v or (isinstance(v, str) and not v.strip()):
            return "development"
        return v

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def parse_log_level(cls, v):
        if not v or (isinstance(v, str) and not v.strip()):
            return "INFO"
        return v

    @field_validator("LLM_PROVIDER", mode="before")
    @classmethod
    def parse_llm_provider(cls, v):
        if not v or (isinstance(v, str) and not v.strip()):
            return "groq"
        return v


settings = Settings()

# Propagate configurations into os.environ
if settings.GEMINI_API_KEY:
    os.environ["GEMINI_API_KEY"] = settings.GEMINI_API_KEY
if settings.GEMINI_MODEL:
    os.environ["GEMINI_MODEL"] = settings.GEMINI_MODEL
if settings.GROQ_API_KEY:
    os.environ["GROQ_API_KEY"] = settings.GROQ_API_KEY
if settings.ABUSEIPDB_API_KEY:
    os.environ["ABUSEIPDB_API_KEY"] = settings.ABUSEIPDB_API_KEY
if settings.LANGCHAIN_API_KEY:
    os.environ["LANGCHAIN_TRACING_V2"] = settings.LANGCHAIN_TRACING_V2
    os.environ["LANGCHAIN_ENDPOINT"] = settings.LANGCHAIN_ENDPOINT
    os.environ["LANGCHAIN_API_KEY"] = settings.LANGCHAIN_API_KEY
    os.environ["LANGCHAIN_PROJECT"] = settings.LANGCHAIN_PROJECT
