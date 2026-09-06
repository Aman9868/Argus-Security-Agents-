"""Structured logging and LangSmith tracing initialization."""

import os
import structlog
from typing import Optional


def configure_tracing(
    enable_langsmith: bool = True,
    project_name: str = "cyber-agent-prod",
    api_key: Optional[str] = None
):
    """Configures structured logging and LangChain/LangSmith tracing."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    if enable_langsmith and api_key:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_PROJECT"] = project_name
        os.environ["LANGCHAIN_API_KEY"] = api_key

