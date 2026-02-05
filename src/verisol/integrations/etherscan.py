"""Etherscan client for fetching verified contract source code."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Etherscan V2 unified endpoint
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

# Chain name -> chain ID (used by Etherscan V2 API)
CHAIN_IDS: dict[str, int] = {
    "ethereum": 1,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
}

# Kept for backwards compat with existing imports
CHAIN_EXPLORER_URLS: dict[str, str] = {
    chain: f"{ETHERSCAN_V2_URL}?chainid={chain_id}"
    for chain, chain_id in CHAIN_IDS.items()
}

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass
class EtherscanResult:
    """Parsed result from an Etherscan getsourcecode response."""

    source_code: str
    contract_name: str
    compiler_version: str
    abi: str
    is_proxy: bool = False
    implementation_address: str | None = None
    source_files: dict[str, str] = field(default_factory=dict)


def get_chain_id(chain: str) -> int:
    """Return the chain ID for the given chain name.

    Raises:
        ValueError: If chain is not supported.
    """
    chain_id = CHAIN_IDS.get(chain.lower())
    if chain_id is None:
        supported = ", ".join(sorted(CHAIN_IDS))
        raise ValueError(f"Unsupported chain '{chain}'. Supported: {supported}")
    return chain_id


def get_explorer_url(chain: str) -> str:
    """Return the V2 API URL for the given chain.

    Raises:
        ValueError: If chain is not supported.
    """
    chain_id = get_chain_id(chain)
    return f"{ETHERSCAN_V2_URL}?chainid={chain_id}"


async def fetch_contract_source(
    address: str,
    chain: str = "ethereum",
    api_key: str | None = None,
) -> EtherscanResult:
    """Fetch verified source code from Etherscan (or compatible explorer).

    Args:
        address: Contract address (0x + 40 hex chars).
        chain: Chain name (ethereum, polygon, arbitrum, optimism, base).
        api_key: Etherscan API key. Rate-limited without one.

    Returns:
        EtherscanResult with parsed source code and metadata.

    Raises:
        ValueError: If address format is invalid or chain unsupported.
        RuntimeError: If contract is not verified or API returns error.
    """
    if not _ADDRESS_RE.match(address):
        raise ValueError(f"Invalid address format: {address}")

    chain_id = get_chain_id(chain)
    params: dict[str, str] = {
        "chainid": str(chain_id),
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
    }
    if api_key:
        params["apikey"] = api_key

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(ETHERSCAN_V2_URL, params=params)
        resp.raise_for_status()

    data = resp.json()

    if data.get("status") != "1" or not data.get("result"):
        raise RuntimeError(
            f"Etherscan API error: {data.get('message', 'unknown error')}"
        )

    item = data["result"][0]

    raw_source = item.get("SourceCode", "")
    if not raw_source:
        raise RuntimeError(
            f"Contract {address} is not verified on {chain}"
        )

    source_code = _parse_source_code(raw_source)
    source_files = _parse_source_files(raw_source)
    contract_name = item.get("ContractName", "")
    compiler_version = item.get("CompilerVersion", "")
    abi = item.get("ABI", "")

    # Proxy detection
    is_proxy = item.get("Proxy", "0") == "1"
    implementation = item.get("Implementation", "") or None

    if is_proxy:
        logger.warning(
            "Contract %s on %s is a proxy (implementation: %s). "
            "Proceeding with proxy source code.",
            address,
            chain,
            implementation or "unknown",
        )

    return EtherscanResult(
        source_code=source_code,
        contract_name=contract_name,
        compiler_version=compiler_version,
        abi=abi,
        is_proxy=is_proxy,
        implementation_address=implementation,
        source_files=source_files,
    )


def _parse_source_code(raw: str) -> str:
    """Parse Etherscan's source code field which has three possible formats.

    1. Plain Solidity string.
    2. Double-brace JSON multi-file: ``{{...}}`` (Etherscan wraps JSON in
       extra braces).
    3. Single-brace JSON: ``{...}`` with ``sources`` mapping.
    """
    stripped = raw.strip()

    # Format 2: double-brace JSON multi-file
    if stripped.startswith("{{"):
        stripped = stripped[1:-1]  # unwrap extra braces
        try:
            parsed = json.loads(stripped)
            if "sources" in parsed:
                return _concat_sources(parsed["sources"])
            return _concat_sources(parsed)
        except json.JSONDecodeError:
            pass

    # Format 3: single-brace JSON
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            if "sources" in parsed:
                return _concat_sources(parsed["sources"])
            return _concat_sources(parsed)
        except json.JSONDecodeError:
            pass

    # Format 1: plain Solidity string
    return stripped


def _parse_source_files(raw: str) -> dict[str, str]:
    """Parse Etherscan's source code field into a file mapping.

    Returns a dict of ``{filepath: content}`` for multi-file sources,
    or an empty dict for single-file (plain Solidity) sources.
    """
    stripped = raw.strip()

    # Format 2: double-brace JSON multi-file
    if stripped.startswith("{{"):
        stripped = stripped[1:-1]
        try:
            parsed = json.loads(stripped)
            if "sources" in parsed:
                return _extract_file_contents(parsed["sources"])
            return _extract_file_contents(parsed)
        except json.JSONDecodeError:
            pass

    # Format 3: single-brace JSON
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            if "sources" in parsed:
                return _extract_file_contents(parsed["sources"])
            return _extract_file_contents(parsed)
        except json.JSONDecodeError:
            pass

    # Format 1: plain Solidity string (single file)
    return {}


def _extract_file_contents(sources: dict) -> dict[str, str]:
    """Extract ``{filename: content}`` from Etherscan's sources dict."""
    result: dict[str, str] = {}
    for filename, entry in sources.items():
        content = entry.get("content", "") if isinstance(entry, dict) else str(entry)
        result[filename] = content
    return result


def _concat_sources(sources: dict) -> str:
    """Concatenate multi-file sources into a single Solidity string."""
    parts: list[str] = []
    for filename, entry in sources.items():
        content = entry.get("content", "") if isinstance(entry, dict) else str(entry)
        parts.append(f"// File: {filename}\n{content}")
    return "\n\n".join(parts)
