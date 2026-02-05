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
    source_files: dict[str, str] | None = Field(
        default=None,
        description="Individual source files for multi-file contracts (filepath -> content)",
    )
    
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
    async def from_address(
        cls,
        address: str,
        chain: str = "ethereum",
        api_key: str | None = None,
    ) -> Contract:
        """Load contract source from Etherscan (or compatible explorer).

        Args:
            address: Contract address (0x + 40 hex chars).
            chain: Chain name (ethereum, polygon, etc.).
            api_key: Etherscan API key.

        Returns:
            Contract with source from block explorer.
        """
        from verisol.integrations.etherscan import fetch_contract_source

        result = await fetch_contract_source(address, chain=chain, api_key=api_key)
        name = result.contract_name or cls._extract_contract_name(result.source_code)

        return cls(
            code=result.source_code,
            name=name,
            source=ContractSource(
                origin="etherscan",
                address=address,
                chain=chain,
            ),
            source_files=result.source_files or None,
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
    
    def write_source_project(self, base_dir: Path) -> tuple[Path, list[str]]:
        """Write source files to a project directory.

        For single-file contracts, writes a single ``.sol`` file.
        For multi-file contracts (from Etherscan), writes each file to its
        original path and creates ``remappings.txt`` for ``@``-prefixed
        imports.

        Args:
            base_dir: Directory to write files into.

        Returns:
            Tuple of (main_file_path, remapping_entries).
        """
        base_dir.mkdir(parents=True, exist_ok=True)

        if not self.source_files or len(self.source_files) <= 1:
            path = self.to_temp_file(base_dir)
            return path, []

        # Write each source file preserving directory structure
        for filepath, content in self.source_files.items():
            dest = base_dir / filepath
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)

        # Detect remappings by scanning import statements against file paths
        remap_set: set[str] = set()

        import_pattern = re.compile(r'import\s+(?:.*\s+from\s+)?["\']([^"\']+)["\']')
        import_paths: set[str] = set()
        for content in self.source_files.values():
            for m in import_pattern.finditer(content):
                import_paths.add(m.group(1))

        file_path_set = set(self.source_files.keys())

        for imp in import_paths:
            if imp.startswith(".") or imp in file_path_set:
                continue
            # Find a file that shares the longest common suffix with the import
            imp_parts = imp.split("/")
            for fpath in file_path_set:
                fpath_parts = fpath.split("/")
                # Count common trailing path segments
                common = 0
                for i in range(1, min(len(imp_parts), len(fpath_parts)) + 1):
                    if imp_parts[-i] == fpath_parts[-i]:
                        common = i
                    else:
                        break
                if common > 0 and common < len(imp_parts):
                    imp_prefix = "/".join(imp_parts[:-common]) + "/"
                    fpath_prefix = "/".join(fpath_parts[:-common]) + "/"
                    remap_set.add(f"{imp_prefix}={fpath_prefix}")
                    break

        # Also handle @-prefixed dirs at root level
        for filepath in self.source_files:
            parts = filepath.split("/")
            if parts[0].startswith("@"):
                remap_set.add(f"{parts[0]}/={parts[0]}/")

        remappings = sorted(remap_set)

        if remappings:
            (base_dir / "remappings.txt").write_text("\n".join(remappings) + "\n")

        # Find the file that defines the main contract
        main_file: Path | None = None
        if self.name:
            pattern = re.compile(rf"\bcontract\s+{re.escape(self.name)}\b")
            for filepath, content in self.source_files.items():
                if pattern.search(content):
                    main_file = base_dir / filepath
                    break

        if main_file is None:
            main_file = base_dir / list(self.source_files.keys())[0]

        return main_file, remappings

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
