"""VeriSol FastAPI server for web demo."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, UTC
from typing import Any

try:
    from fastapi import FastAPI, File, Form, HTTPException, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:
    raise ImportError(
        "FastAPI is required for the API server. "
        "Install with: pip install verisol[api]"
    )

from pydantic import BaseModel, Field

from verisol import __version__
from verisol.config import settings
from verisol.core.contract import Contract
from verisol.pipeline import VerificationPipeline

# Security limits
MAX_CONTRACT_SIZE = 1_000_000  # 1MB max file upload
MAX_CODE_LENGTH = 500_000  # 500KB max for inline code


# Request/Response models
class AuditRequest(BaseModel):
    """Request body for audit endpoint."""
    code: str = Field(..., min_length=1, max_length=500_000, description="Solidity source code (max 500KB)")
    name: str | None = Field(default=None, description="Contract name")
    quick: bool = Field(default=False, description="Quick mode: Slither only (fastest)")
    offline: bool = Field(default=False, description="Offline mode: Slither + SMTChecker (no API)")
    full: bool = Field(default=False, description="Full mode: Slither + LLM + SMTChecker")


class AuditResponse(BaseModel):
    """Response from audit endpoint."""
    success: bool
    contract_name: str | None
    contract_hash: str
    overall_score: float
    passed: bool
    confidence: str
    finding_summary: dict[str, int]
    total_duration_ms: int
    report_markdown: str
    report_json: dict[str, Any]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    tools: dict[str, bool]
    timestamp: str


# App setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown events."""
    # Startup: check tools
    pipeline = VerificationPipeline()
    tools = pipeline.check_tools()
    missing = [name for name, available in tools.items() if not available]
    if missing:
        print(f"Warning: Missing tools: {', '.join(missing)}")
    yield
    # Shutdown: cleanup if needed


app = FastAPI(
    title="VeriSol API",
    description="Smart contract security verification API",
    version=__version__,
    lifespan=lifespan,
)

# CORS configuration (set API_CORS_ORIGINS env var for production)
cors_origins = [origin.strip() for origin in settings.api_cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    pipeline = VerificationPipeline()
    return HealthResponse(
        status="healthy",
        version=__version__,
        tools=pipeline.check_tools(),
        timestamp=datetime.now(UTC).isoformat(),
    )


@app.post("/audit", response_model=AuditResponse)
async def audit_contract(request: AuditRequest) -> AuditResponse:
    """
    Audit a smart contract.
    
    Accepts Solidity source code and returns verification results.
    """
    try:
        contract = Contract.from_text(request.code, request.name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid contract: {e}")
    
    pipeline = VerificationPipeline()
    
    try:
        if request.quick:
            report = await pipeline.run_quick(contract)
        else:
            report = await pipeline.run(
                contract,
                include_smt=(request.full or request.offline),
                skip_llm=request.offline,
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")

    return AuditResponse(
        success=True,
        contract_name=report.contract_name,
        contract_hash=report.contract_hash,
        overall_score=report.overall_score,
        passed=report.passed,
        confidence=report.confidence,
        finding_summary=report.finding_summary,
        total_duration_ms=report.total_duration_ms,
        report_markdown=report.to_markdown(),
        report_json=report.to_json(),
    )


@app.post("/audit/file")
async def audit_file(
    file: UploadFile = File(..., description="Solidity file to audit"),
    quick: bool = Form(default=False),
    offline: bool = Form(default=False),
    full: bool = Form(default=False),
) -> AuditResponse:
    """
    Audit an uploaded Solidity file.
    """
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(status_code=415, detail="File must be a .sol Solidity file")

    # Check file size before reading
    if file.size and file.size > MAX_CONTRACT_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_CONTRACT_SIZE // 1_000_000}MB)")

    content = await file.read()

    # Double-check size after reading (file.size may be None for some uploads)
    if len(content) > MAX_CONTRACT_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_CONTRACT_SIZE // 1_000_000}MB)")
    
    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    
    try:
        contract = Contract.from_text(code, file.filename.replace(".sol", ""))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid contract: {e}")
    
    pipeline = VerificationPipeline()
    
    try:
        if quick:
            report = await pipeline.run_quick(contract)
        else:
            report = await pipeline.run(
                contract,
                include_smt=(full or offline),
                skip_llm=offline,
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")

    return AuditResponse(
        success=True,
        contract_name=report.contract_name,
        contract_hash=report.contract_hash,
        overall_score=report.overall_score,
        passed=report.passed,
        confidence=report.confidence,
        finding_summary=report.finding_summary,
        total_duration_ms=report.total_duration_ms,
        report_markdown=report.to_markdown(),
        report_json=report.to_json(),
    )


@app.get("/tools")
async def list_tools() -> dict[str, Any]:
    """List available verification tools and their status."""
    pipeline = VerificationPipeline()
    tools = pipeline.check_tools()
    
    tool_info = {
        "solc": {
            "available": tools["solc"],
            "description": "Solidity compiler",
            "install": "pip install solc-select && solc-select install 0.8.24",
        },
        "slither": {
            "available": tools["slither"],
            "description": "Static analysis framework with 90+ vulnerability detectors",
            "install": "pip install slither-analyzer",
        },
        "smtchecker": {
            "available": tools["smtchecker"],
            "description": "Formal verification using SMT solvers (built into solc)",
            "install": "Included with solc",
        },
    }
    
    return {
        "tools": tool_info,
        "all_available": all(tools.values()),
    }


def start_server(
    host: str | None = None,
    port: int | None = None,
    reload: bool = False,
) -> None:
    """Start the API server."""
    import uvicorn
    
    uvicorn.run(
        "verisol.api:app",
        host=host or settings.api_host,
        port=port or settings.api_port,
        reload=reload,
    )


if __name__ == "__main__":
    start_server(reload=True)
