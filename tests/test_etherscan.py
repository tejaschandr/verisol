"""Tests for Etherscan integration and Contract.from_address()."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from verisol.integrations.etherscan import (
    CHAIN_EXPLORER_URLS,
    EtherscanResult,
    fetch_contract_source,
    get_explorer_url,
    _parse_source_code,
    _parse_source_files,
)
from verisol.core.contract import Contract


# ---------------------------------------------------------------------------
# get_explorer_url
# ---------------------------------------------------------------------------

class TestGetExplorerUrl:
    def test_all_supported_chains(self):
        for chain in ("ethereum", "polygon", "arbitrum", "optimism", "base"):
            url = get_explorer_url(chain)
            assert url.startswith("https://")

    def test_case_insensitive(self):
        assert get_explorer_url("Ethereum") == get_explorer_url("ethereum")

    def test_unsupported_chain_raises(self):
        with pytest.raises(ValueError, match="Unsupported chain"):
            get_explorer_url("solana")


# ---------------------------------------------------------------------------
# _parse_source_code
# ---------------------------------------------------------------------------

class TestParseSourceCode:
    def test_plain_solidity(self):
        code = "pragma solidity ^0.8.0;\ncontract Foo {}"
        assert _parse_source_code(code) == code

    def test_double_brace_json(self):
        inner = {
            "contracts/Foo.sol": {"content": "contract Foo {}"},
            "contracts/Bar.sol": {"content": "contract Bar {}"},
        }
        # Etherscan wraps one extra brace on each side of the JSON
        raw = "{" + json.dumps(inner) + "}"
        result = _parse_source_code(raw)
        assert "contract Foo {}" in result
        assert "contract Bar {}" in result
        assert "// File: contracts/Foo.sol" in result

    def test_double_brace_json_with_sources_key(self):
        """Etherscan sometimes returns {{\"language\":...,\"sources\":{...}}}."""
        inner = {
            "language": "Solidity",
            "sources": {
                "contracts/Token.sol": {"content": "contract Token {}"},
                "contracts/Utils.sol": {"content": "library Utils {}"},
            },
            "settings": {"optimizer": {"enabled": True}},
        }
        raw = "{" + json.dumps(inner) + "}"
        result = _parse_source_code(raw)
        assert "contract Token {}" in result
        assert "library Utils {}" in result
        assert "// File: contracts/Token.sol" in result

    def test_single_brace_json_with_sources(self):
        inner = {
            "sources": {
                "Token.sol": {"content": "contract Token {}"},
            }
        }
        raw = json.dumps(inner)
        result = _parse_source_code(raw)
        assert "contract Token {}" in result

    def test_single_brace_json_without_sources(self):
        inner = {
            "Main.sol": {"content": "contract Main {}"},
        }
        raw = json.dumps(inner)
        result = _parse_source_code(raw)
        assert "contract Main {}" in result


# ---------------------------------------------------------------------------
# fetch_contract_source
# ---------------------------------------------------------------------------

def _etherscan_response(
    source_code: str = "contract Foo {}",
    contract_name: str = "Foo",
    compiler_version: str = "v0.8.24",
    abi: str = "[]",
    proxy: str = "0",
    implementation: str = "",
) -> dict:
    return {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "SourceCode": source_code,
                "ContractName": contract_name,
                "CompilerVersion": compiler_version,
                "ABI": abi,
                "Proxy": proxy,
                "Implementation": implementation,
            }
        ],
    }


class TestFetchContractSource:
    @pytest.mark.asyncio
    async def test_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _etherscan_response()
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verisol.integrations.etherscan.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_contract_source(
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                chain="ethereum",
                api_key="test-key",
            )

        assert isinstance(result, EtherscanResult)
        assert result.contract_name == "Foo"
        assert "contract Foo {}" in result.source_code
        assert not result.is_proxy

    @pytest.mark.asyncio
    async def test_not_verified(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _etherscan_response(source_code="")
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verisol.integrations.etherscan.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(RuntimeError, match="not verified"):
                await fetch_contract_source(
                    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                    chain="ethereum",
                )

    @pytest.mark.asyncio
    async def test_invalid_address(self):
        with pytest.raises(ValueError, match="Invalid address"):
            await fetch_contract_source("not-an-address")

    @pytest.mark.asyncio
    async def test_short_address(self):
        with pytest.raises(ValueError, match="Invalid address"):
            await fetch_contract_source("0x1234")

    @pytest.mark.asyncio
    async def test_api_error(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "0", "message": "NOTOK", "result": []}
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verisol.integrations.etherscan.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(RuntimeError, match="Etherscan API error"):
                await fetch_contract_source(
                    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                )

    @pytest.mark.asyncio
    async def test_proxy_detection(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _etherscan_response(
            proxy="1",
            implementation="0x1111111111111111111111111111111111111111",
        )
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verisol.integrations.etherscan.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_contract_source(
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                chain="ethereum",
            )

        assert result.is_proxy
        assert result.implementation_address == "0x1111111111111111111111111111111111111111"


# ---------------------------------------------------------------------------
# Contract.from_address (end-to-end with mocked Etherscan)
# ---------------------------------------------------------------------------

class TestContractFromAddress:
    @pytest.mark.asyncio
    async def test_creates_contract_from_address(self):
        etherscan_result = EtherscanResult(
            source_code="pragma solidity ^0.8.0;\ncontract USDT {}",
            contract_name="USDT",
            compiler_version="v0.8.24",
            abi="[]",
        )

        with patch(
            "verisol.integrations.etherscan.fetch_contract_source",
            new_callable=AsyncMock,
            return_value=etherscan_result,
        ):
            contract = await Contract.from_address(
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                chain="ethereum",
                api_key="test-key",
            )

        assert contract.name == "USDT"
        assert contract.source.origin == "etherscan"
        assert contract.source.address == "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        assert contract.source.chain == "ethereum"
        assert "contract USDT" in contract.code

    @pytest.mark.asyncio
    async def test_falls_back_to_extracted_name(self):
        etherscan_result = EtherscanResult(
            source_code="pragma solidity ^0.8.0;\ncontract MyToken {}",
            contract_name="",
            compiler_version="v0.8.24",
            abi="[]",
        )

        with patch(
            "verisol.integrations.etherscan.fetch_contract_source",
            new_callable=AsyncMock,
            return_value=etherscan_result,
        ):
            contract = await Contract.from_address(
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            )

        assert contract.name == "MyToken"


# ---------------------------------------------------------------------------
# _parse_source_files
# ---------------------------------------------------------------------------

class TestParseSourceFiles:
    def test_plain_solidity_returns_empty_dict(self):
        code = "pragma solidity ^0.8.0;\ncontract Foo {}"
        assert _parse_source_files(code) == {}

    def test_double_brace_json_returns_files(self):
        inner = {
            "contracts/Foo.sol": {"content": "contract Foo {}"},
            "contracts/Bar.sol": {"content": "contract Bar {}"},
        }
        raw = "{" + json.dumps(inner) + "}"
        result = _parse_source_files(raw)
        assert len(result) == 2
        assert result["contracts/Foo.sol"] == "contract Foo {}"
        assert result["contracts/Bar.sol"] == "contract Bar {}"

    def test_double_brace_json_with_sources_key(self):
        inner = {
            "language": "Solidity",
            "sources": {
                "contracts/Token.sol": {"content": "contract Token {}"},
            },
            "settings": {"optimizer": {"enabled": True}},
        }
        raw = "{" + json.dumps(inner) + "}"
        result = _parse_source_files(raw)
        assert len(result) == 1
        assert result["contracts/Token.sol"] == "contract Token {}"

    def test_single_brace_json_with_sources(self):
        inner = {
            "sources": {
                "Token.sol": {"content": "contract Token {}"},
                "Utils.sol": {"content": "library Utils {}"},
            }
        }
        raw = json.dumps(inner)
        result = _parse_source_files(raw)
        assert len(result) == 2
        assert result["Token.sol"] == "contract Token {}"

    def test_preserves_openzeppelin_paths(self):
        inner = {
            "contracts/Token.sol": {"content": "import '@openzeppelin/contracts/token/ERC20/ERC20.sol';"},
            "@openzeppelin/contracts/token/ERC20/ERC20.sol": {"content": "contract ERC20 {}"},
        }
        raw = "{" + json.dumps(inner) + "}"
        result = _parse_source_files(raw)
        assert "@openzeppelin/contracts/token/ERC20/ERC20.sol" in result


# ---------------------------------------------------------------------------
# Multi-file Contract.from_address
# ---------------------------------------------------------------------------

class TestContractFromAddressMultiFile:
    @pytest.mark.asyncio
    async def test_populates_source_files(self):
        source_files = {
            "contracts/Token.sol": "contract Token {}",
            "contracts/Utils.sol": "library Utils {}",
        }
        etherscan_result = EtherscanResult(
            source_code="// File: contracts/Token.sol\ncontract Token {}\n\n// File: contracts/Utils.sol\nlibrary Utils {}",
            contract_name="Token",
            compiler_version="v0.8.24",
            abi="[]",
            source_files=source_files,
        )

        with patch(
            "verisol.integrations.etherscan.fetch_contract_source",
            new_callable=AsyncMock,
            return_value=etherscan_result,
        ):
            contract = await Contract.from_address(
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                chain="ethereum",
            )

        assert contract.source_files is not None
        assert len(contract.source_files) == 2
        assert "contracts/Token.sol" in contract.source_files

    @pytest.mark.asyncio
    async def test_single_file_has_no_source_files(self):
        etherscan_result = EtherscanResult(
            source_code="pragma solidity ^0.8.0;\ncontract Simple {}",
            contract_name="Simple",
            compiler_version="v0.8.24",
            abi="[]",
            source_files={},
        )

        with patch(
            "verisol.integrations.etherscan.fetch_contract_source",
            new_callable=AsyncMock,
            return_value=etherscan_result,
        ):
            contract = await Contract.from_address(
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            )

        assert contract.source_files is None
