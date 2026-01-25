"""Configuration management for VeriSol."""

from pathlib import Path
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Solidity Compiler
    solc_version: str = Field(default="0.8.24", description="Solidity compiler version")
    
    # Verification Timeouts (seconds)
    slither_timeout: int = Field(default=60, ge=10, le=600)
    smtchecker_timeout: int = Field(default=120, ge=30, le=600)

    # LLM Configuration
    llm_enabled: bool = Field(default=True, description="Enable LLM-based analysis")
    llm_provider: str = Field(default="openai", description="LLM provider: openai or anthropic")
    llm_model: str | None = Field(default=None, description="Model name (defaults to gpt-4o or claude-3-5-sonnet-latest)")
    llm_timeout: int = Field(default=120, ge=30, le=600, description="LLM API timeout in seconds")
    llm_enable_filters: bool = Field(default=True, description="Enable FP filtering for LLM findings")

    # API Configuration
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_cors_origins: str = Field(default="*", description="Comma-separated CORS origins (use specific origins in production)")
    
    # API Keys
    openai_api_key: str | None = Field(default=None)
    anthropic_api_key: str | None = Field(default=None)
    
    # Paths
    contracts_dir: Path = Field(default=Path("./data/contracts"))
    reports_dir: Path = Field(default=Path("./data/reports"))
    
    # Derived paths
    @property
    def project_root(self) -> Path:
        return Path(__file__).parent.parent.parent
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience access
settings = get_settings()
