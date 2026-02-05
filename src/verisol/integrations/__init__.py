"""Integrations with external services."""

from verisol.integrations.etherscan import (
    EtherscanResult,
    fetch_contract_source,
    get_chain_id,
    get_explorer_url,
    CHAIN_EXPLORER_URLS,
    CHAIN_IDS,
)

__all__ = [
    "EtherscanResult",
    "fetch_contract_source",
    "get_chain_id",
    "get_explorer_url",
    "CHAIN_EXPLORER_URLS",
    "CHAIN_IDS",
]
