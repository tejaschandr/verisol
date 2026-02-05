"""Configuration management for VeriSol."""

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

    # Exploit LLM Configuration
    exploit_llm_enabled: bool = Field(default=True, description="Use LLM for exploit generation")
    exploit_llm_provider: str | None = Field(default=None, description="Provider override for exploit gen (defaults to llm_provider)")
    exploit_llm_model: str | None = Field(default=None, description="Model override for exploit gen")
    exploit_max_retries: int = Field(default=3, ge=1, le=10, description="Max LLM retry attempts for exploit gen")

    # API Configuration
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_cors_origins: str = Field(default="*", description="Comma-separated CORS origins (use specific origins in production)")
    
    # API Keys
    openai_api_key: str | None = Field(default=None)
    anthropic_api_key: str | None = Field(default=None)

    # Etherscan
    etherscan_api_key: str | None = Field(default=None)

    # Fork Mode RPC URLs
    ethereum_rpc_url: str | None = Field(default=None)
    polygon_rpc_url: str | None = Field(default=None)
    arbitrum_rpc_url: str | None = Field(default=None)
    optimism_rpc_url: str | None = Field(default=None)
    base_rpc_url: str | None = Field(default=None)

    # Fork timeout
    fork_timeout: int = Field(default=180, ge=30, le=600)

    def get_rpc_url(self, chain: str) -> str | None:
        """Map chain name to configured RPC URL."""
        mapping = {
            "ethereum": self.ethereum_rpc_url,
            "polygon": self.polygon_rpc_url,
            "arbitrum": self.arbitrum_rpc_url,
            "optimism": self.optimism_rpc_url,
            "base": self.base_rpc_url,
        }
        return mapping.get(chain.lower())
    
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
