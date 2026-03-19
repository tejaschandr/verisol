"""Tests for fork mode and multi-file sources in the exploit runner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from verisol.exploits.runner import (
    run_exploit,
    _write_multi_file_sources,
    _find_main_contract_file,
)


SAMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EtherStore {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
}
"""

SAMPLE_EXPLOIT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
contract Exploit is Test {
    function testReentrancyExploit() public { assertTrue(true); }
}
"""


class TestForkUrlInCommand:
    """Verify --fork-url and --fork-block-number appear in the forge command."""

    @patch("verisol.exploits.runner.check_foundry_available", return_value=True)
    @patch("verisol.exploits.runner._setup_hot_start_project")
    @patch("verisol.exploits.runner.subprocess.run")
    @patch("verisol.exploits.runner.shutil.rmtree")
    def test_fork_url_added_to_command(self, _rmtree, mock_run, _create, _check, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PASS testReentrancyExploit\nProfit: 1000",
            stderr="",
        )

        with patch("verisol.exploits.runner.tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("verisol.exploits.runner.Path.exists", return_value=True), \
             patch("verisol.exploits.runner.Path.write_text"):
            run_exploit(
                SAMPLE_EXPLOIT,
                SAMPLE_CONTRACT,
                "EtherStore",
                fork_url="https://eth-mainnet.example.com",
            )

        cmd = mock_run.call_args[0][0]
        assert "--fork-url" in cmd
        assert "https://eth-mainnet.example.com" in cmd
        assert "--fork-block-number" not in cmd

    @patch("verisol.exploits.runner.check_foundry_available", return_value=True)
    @patch("verisol.exploits.runner._setup_hot_start_project")
    @patch("verisol.exploits.runner.subprocess.run")
    @patch("verisol.exploits.runner.shutil.rmtree")
    def test_fork_block_added_to_command(self, _rmtree, mock_run, _create, _check, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PASS testReentrancyExploit",
            stderr="",
        )

        with patch("verisol.exploits.runner.tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("verisol.exploits.runner.Path.exists", return_value=True), \
             patch("verisol.exploits.runner.Path.write_text"):
            run_exploit(
                SAMPLE_EXPLOIT,
                SAMPLE_CONTRACT,
                "EtherStore",
                fork_url="https://eth-mainnet.example.com",
                fork_block=18000000,
            )

        cmd = mock_run.call_args[0][0]
        assert "--fork-url" in cmd
        assert "--fork-block-number" in cmd
        assert "18000000" in cmd

    @patch("verisol.exploits.runner.check_foundry_available", return_value=True)
    @patch("verisol.exploits.runner._setup_hot_start_project")
    @patch("verisol.exploits.runner.subprocess.run")
    @patch("verisol.exploits.runner.shutil.rmtree")
    def test_no_fork_params_without_url(self, _rmtree, mock_run, _create, _check, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PASS testReentrancyExploit",
            stderr="",
        )

        with patch("verisol.exploits.runner.tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("verisol.exploits.runner.Path.exists", return_value=True), \
             patch("verisol.exploits.runner.Path.write_text"):
            run_exploit(
                SAMPLE_EXPLOIT,
                SAMPLE_CONTRACT,
                "EtherStore",
            )

        cmd = mock_run.call_args[0][0]
        assert "--fork-url" not in cmd
        assert "--fork-block-number" not in cmd


class TestForkTimeout:
    """Verify fork mode uses the longer timeout."""

    @patch("verisol.exploits.runner.check_foundry_available", return_value=True)
    @patch("verisol.exploits.runner._setup_hot_start_project")
    @patch("verisol.exploits.runner.subprocess.run")
    @patch("verisol.exploits.runner.shutil.rmtree")
    def test_fork_mode_uses_settings_timeout(self, _rmtree, mock_run, _create, _check, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PASS testReentrancyExploit",
            stderr="",
        )

        with patch("verisol.exploits.runner.tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("verisol.exploits.runner.Path.exists", return_value=True), \
             patch("verisol.exploits.runner.Path.write_text"), \
             patch("verisol.config.get_settings") as mock_settings:
            mock_settings.return_value.fork_timeout = 300
            run_exploit(
                SAMPLE_EXPLOIT,
                SAMPLE_CONTRACT,
                "EtherStore",
                fork_url="https://eth-mainnet.example.com",
            )

        # Verify timeout kwarg passed to subprocess.run
        assert mock_run.call_args[1]["timeout"] == 300

    @patch("verisol.exploits.runner.check_foundry_available", return_value=True)
    @patch("verisol.exploits.runner._setup_hot_start_project")
    @patch("verisol.exploits.runner.subprocess.run")
    @patch("verisol.exploits.runner.shutil.rmtree")
    def test_non_fork_uses_default_timeout(self, _rmtree, mock_run, _create, _check, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="PASS testReentrancyExploit",
            stderr="",
        )

        with patch("verisol.exploits.runner.tempfile.mkdtemp", return_value=str(tmp_path)), \
             patch("verisol.exploits.runner.Path.exists", return_value=True), \
             patch("verisol.exploits.runner.Path.write_text"):
            run_exploit(
                SAMPLE_EXPLOIT,
                SAMPLE_CONTRACT,
                "EtherStore",
            )

        assert mock_run.call_args[1]["timeout"] == 30


# ---------------------------------------------------------------------------
# Multi-file source helpers
# ---------------------------------------------------------------------------

class TestWriteMultiFileSources:
    def test_writes_files_to_correct_paths(self, tmp_path):
        source_files = {
            "contracts/Token.sol": "pragma solidity ^0.8.0;\ncontract Token {}",
            "contracts/Utils.sol": "library Utils {}",
        }
        _write_multi_file_sources(tmp_path, source_files)

        assert (tmp_path / "contracts" / "Token.sol").exists()
        assert (tmp_path / "contracts" / "Utils.sol").exists()
        assert "contract Token" in (tmp_path / "contracts" / "Token.sol").read_text()

    def test_creates_nested_directories(self, tmp_path):
        source_files = {
            "@openzeppelin/contracts/token/ERC20/ERC20.sol": "contract ERC20 {}",
        }
        _write_multi_file_sources(tmp_path, source_files)

        dest = tmp_path / "@openzeppelin" / "contracts" / "token" / "ERC20" / "ERC20.sol"
        assert dest.exists()
        assert "contract ERC20" in dest.read_text()


class TestFindMainContractFile:
    def test_finds_contract_by_name(self):
        source_files = {
            "contracts/Token.sol": "contract Token is ERC20 {}",
            "contracts/Utils.sol": "library Utils {}",
        }
        result = _find_main_contract_file(source_files, "Token")
        assert result == "contracts/Token.sol"

    def test_returns_none_when_not_found(self):
        source_files = {
            "contracts/Token.sol": "contract Token {}",
        }
        result = _find_main_contract_file(source_files, "NonExistent")
        assert result is None

    def test_does_not_match_substring(self):
        source_files = {
            "contracts/Token.sol": "contract TokenV2 {}",
        }
        # Should not match "Token" when the actual name is "TokenV2"
        result = _find_main_contract_file(source_files, "Token")
        assert result is None
