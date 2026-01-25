"""Contract data models."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, computed_field


class ContractSource(BaseModel):
    """Source information for a contract."""
    
    origin: Literal["file", "upload", "text", "etherscan"] = "text"
    path: Path | None = None
    address: str | None = None  # For etherscan-sourced contracts
    chain: str | None = None


class Contract(BaseModel):
    """Represents a Solidity smart contract for verification."""
    
    code: str = Field(..., min_length=1, description="Solidity source code")
    name: str | None = Field(default=None, description="Contract name (extracted or provided)")
    source: ContractSource = Field(default_factory=ContractSource)
    
    @computed_field
    @property
    def hash(self) -> str:
        """SHA256 hash of contract code for deduplication."""
        return hashlib.sha256(self.code.encode()).hexdigest()[:16]
    
    @computed_field
    @property
    def solidity_version(self) -> str | None:
        """Extract pragma solidity version from code."""
        match = re.search(r"pragma\s+solidity\s+([^;]+);", self.code)
        if match:
            return match.group(1).strip()
        return None
    
    @computed_field
    @property
    def lines_of_code(self) -> int:
        """Count non-empty, non-comment lines."""
        lines = self.code.split("\n")
        count = 0
        in_block_comment = False

        for line in lines:
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                continue

            # Process line character by character to handle comments properly
            has_code = False
            i = 0
            in_string = False
            string_char = None

            while i < len(stripped):
                char = stripped[i]

                # Handle string literals (skip comment detection inside strings)
                if not in_block_comment and char in ('"', "'") and (i == 0 or stripped[i-1] != '\\'):
                    if not in_string:
                        in_string = True
                        string_char = char
                        has_code = True
                    elif char == string_char:
                        in_string = False
                    i += 1
                    continue

                if in_string:
                    has_code = True
                    i += 1
                    continue

                # Check for block comment start
                if not in_block_comment and i + 1 < len(stripped) and stripped[i:i+2] == "/*":
                    in_block_comment = True
                    i += 2
                    continue

                # Check for block comment end
                if in_block_comment and i + 1 < len(stripped) and stripped[i:i+2] == "*/":
                    in_block_comment = False
                    i += 2
                    continue

                # Check for line comment
                if not in_block_comment and i + 1 < len(stripped) and stripped[i:i+2] == "//":
                    break  # Rest of line is comment

                # If not in comment, this is code
                if not in_block_comment and not char.isspace():
                    has_code = True

                i += 1

            if has_code:
                count += 1

        return count
    
    @classmethod
    def from_file(cls, path: Path | str) -> Contract:
        """Load contract from file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Contract file not found: {path}")
        
        code = path.read_text()
        name = cls._extract_contract_name(code) or path.stem
        
        return cls(
            code=code,
            name=name,
            source=ContractSource(origin="file", path=path),
        )
    
    @classmethod
    def from_text(cls, code: str, name: str | None = None) -> Contract:
        """Create contract from source code text."""
        extracted_name = cls._extract_contract_name(code)
        return cls(
            code=code,
            name=name or extracted_name,
            source=ContractSource(origin="text"),
        )
    
    @staticmethod
    def _extract_contract_name(code: str) -> str | None:
        """Extract main contract name from source code."""
        # Look for contract declarations
        matches = re.findall(r"contract\s+(\w+)", code)
        if matches:
            # Return last contract (usually the main one)
            return matches[-1]
        return None
    
    def to_temp_file(self, dir: Path | None = None) -> Path:
        """Write contract to a temporary file for verification tools."""
        import tempfile
        
        if dir:
            dir.mkdir(parents=True, exist_ok=True)
        
        suffix = ".sol"
        prefix = f"{self.name}_" if self.name else "contract_"
        
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            prefix=prefix,
            dir=dir,
            delete=False,
        ) as f:
            f.write(self.code)
            return Path(f.name)
