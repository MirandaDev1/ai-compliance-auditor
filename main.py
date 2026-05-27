
from **future** import annotations
import asyncio
import logging
import os
import pathlib
import random
import re
import sys
import time
import traceback
from enum import Enum
from typing import Any, ClassVar, Dict, Final, List
import aiofiles
from openai import AsyncOpenAI
from prometheus_client import Counter, Gauge, start_http_server
from pydantic import BaseModel, Field
class AppConfig:
DIRECTORY_TO_SCAN: Final[str] = os.getenv("DLP_SCAN_DIR", "./target_audit_directory")
OPENAI_API_KEY: Final[str] = os.getenv("OPENAI_API_KEY", "your-production-api-key-here")
LOG_FILE_PATH: Final[str] = os.getenv("DLP_LOG_PATH", "audit.log")
PROMETHEUS_PORT: Final[int] = int(os.getenv("DLP_METRICS_PORT", "8000"))
MAX_CONCURRENT_TASKS: Final[int] = int(os.getenv("DLP_MAX_CONCURRENCY", "10"))
AI_MODEL_ENGINE: Final[str] = os.getenv("DLP_AI_MODEL", "gpt-4o")
class RiskCategory(str, Enum):
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"
class ComplianceViolation(BaseModel):
violation_detected: bool = Field(..., description="Boolean flag indicating if the document contains sensitive data leaks, corporate espionage, or compliance breaches.")
vulnerability_type: str = Field(..., description="Standardized short string classification of the vulnerability.")
risk_score: int = Field(..., ge=0, le=100, description="Numerical risk telemetry metrics from 0 to 100.")
risk_classification: RiskCategory = Field(..., description="Strict Enum metric mapping the severity level.")
technical_justification: str = Field(..., description="Concise technical analysis detailing the violated segment and legal implications.")
def initialize_enterprise_logger() -> logging.Logger:
logger = logging.getLogger("EnterpriseDLPAuditor")
logger.setLevel(logging.INFO)
if logger.hasHandlers():
return logger
log_format = logging.Formatter(fmt="%(asctime)s | %(levelname)-8s | [PID:%(process)d] | %(filename)s:%(lineno)d | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_format)
logger.addHandler(console_handler)
file_handler = logging.FileHandler(AppConfig.LOG_FILE_PATH, encoding="utf-8")
file_handler.setFormatter(log_format)
logger.addHandler(file_handler)
return logger
class SystemTelemetry:
FILES_SCANNED: ClassVar[Counter] = Counter("dlp_files_scanned_total", "Total counter tracking all processed files.")
LEAKS_DETECTED: ClassVar[Counter] = Counter("dlp_leaks_detected_total", "Total counter isolating compliance violations.")
CRITICAL_RISK_COUNT: ClassVar[Counter] = Counter("dlp_critical_risk_total", "Counter isolating extreme risk level events.")
FILE_READ_FAILURES: ClassVar[Counter] = Counter("dlp_file_read_failures_total", "Counter tracking asynchronous file read failures.")
PROCESSING_VELOCITY: ClassVar[Gauge] = Gauge("dlp_processing_duration_seconds", "Gauge metric measuring execution time metrics.")
async def start_telemetry_server() -> None:
logger = logging.getLogger("EnterpriseDLPAuditor")
try:
start_http_server(AppConfig.PROMETHEUS_PORT)
logger.info(f"Prometheus infrastructure telemetric engine initiated on port :{AppConfig.PROMETHEUS_PORT}/metrics")
except Exception as exc:
logger.error(f"Failed to bind Prometheus metrics runtime pipeline: {str(exc)}")
async def read_file_content_async(file_path: str, semaphore: asyncio.Semaphore) -> str:
logger = logging.getLogger("EnterpriseDLPAuditor")
async with semaphore:
try:
async with aiofiles.open(file_path, mode="r", encoding="utf-8", errors="ignore") as file_handle:
return await file_handle.read()
except (OSError, PermissionError, FileNotFoundError) as exc:
SystemTelemetry.FILE_READ_FAILURES.inc()
logger.error(f"Failed to read file asynchronously: {file_path} | Exception: {str(exc)} | Traceback: {traceback.format_exc()}")
return ""
class AuditEngine:
REGEX_PATTERNS: ClassVar[Dict[str, re.Pattern[str]]] = {
"OPENAI_KEY": re.compile(r"sk-[a-zA-Z0-9]{48}"),
"PRIVATE_KEY": re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
"CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
"CPF": re.compile(r"\b\d{3}.\d{3}.\d{3}-\d{2}\b"),
"CNPJ": re.compile(r"\b\d{2}.\d{3}.\d{3}/\d{4}-\d{2}\b")
}
@classmethod
def execute_tier1_local_regex(cls, text: str) -> Dict[str, Any]:
for name, pattern in cls.REGEX_PATTERNS.items():
if pattern.search(text):
return {
"violation_detected": True,
"vulnerability_type": f"REGEX_{name}_MATCH",
"risk_score": 100,
"risk_classification": "CRITICAL",
"technical_justification": f"Deterministic regex string matched signatures for {name} within raw source file."
}
return {"violation_detected": False}
@classmethod
async def execute_tier2_cognitive_llm(cls, text: str, client: AsyncOpenAI) -> ComplianceViolation:
system_prompt = "You are a Senior Enterprise GRC and Data Leakage Prevention auditor. Analyze the following document snippet for intellectual property leaks, compliance violations, credentials, or corporate secrets. Return a strict validated JSON structure matching the required parameters."
completion = await client.beta.chat.completions.parse(
model=AppConfig.AI_MODEL_ENGINE,
messages=[
{"role": "system", "content": system_prompt},
{"role": "user", "content": text[:12000]}
],
response_format=ComplianceViolation
)
return completion.choices[0].message.parsed
async def execute_cognitive_analysis_with_retry(text: str, client: AsyncOpenAI) -> ComplianceViolation:
logger = logging.getLogger("EnterpriseDLPAuditor")
max_retries = 5
base_delay = 2.0
for attempt in range(max_retries):
try:
return await AuditEngine.execute_tier2_cognitive_llm(text, client)
except Exception as exc:
if attempt == max_retries - 1:
logger.critical(f"Aborting analysis pipeline. Maximum retries exceeded for file chunk. Exception: {str(exc)}")
raise
jitter = random.uniform(0.5, 1.5)
delay = (base_delay ** attempt) * jitter
logger.warning(f"Transient fault detected during OpenAI completion layer. Retry {attempt + 1}/{max_retries} executing in {delay:.2f}s. Error: {str(exc)}")
await asyncio.sleep(delay)
raise RuntimeError("Retry pipeline exhausted unexpectedly.")
async def process_single_file_pipeline(file_path: str, semaphore: asyncio.Semaphore, client: AsyncOpenAI) -> None:
logger = logging.getLogger("EnterpriseDLPAuditor")
start_time = time.time()
try:
content = await read_file_content_async(file_path, semaphore)
if not content.strip():
return
SystemTelemetry.FILES_SCANNED.inc()
tier1_result = AuditEngine.execute_tier1_local_regex(content)
if tier1_result["violation_detected"]:
SystemTelemetry.LEAKS_DETECTED.inc()
SystemTelemetry.CRITICAL_RISK_COUNT.inc()
logger.error(f"CRITICAL COMPLIANCE VIOLATION FOUND BY TIER 1 [FILE: {file_path}] | Type: {tier1_result['vulnerability_type']} | Risk: {tier1_result['risk_classification']} | Justification: {tier1_result['technical_justification']}")
return
violation = await execute_cognitive_analysis_with_retry(content, client)
if violation.violation_detected:
SystemTelemetry.LEAKS_DETECTED.inc()
if violation.risk_classification == RiskCategory.CRITICAL:
SystemTelemetry.CRITICAL_RISK_COUNT.inc()
log_message = f"COMPLIANCE BREACH ISOLATED BY TIER 2 [FILE: {file_path}] | Type: {violation.vulnerability_type} | Score: {violation.risk_score} | Classification: {violation.risk_classification.value} | Reason: {violation.technical_justification}"
if violation.risk_classification in (RiskCategory.HIGH, RiskCategory.CRITICAL):
logger.error(log_message)
else:
logger.warning(log_message)
else:
logger.info(f"File {file_path} scanned successfully. Status: CLEAN.")
except Exception as exc:
logger.error(f"Analysis engine completely bypassed for file {file_path} due to critical pipeline failures. Exception: {str(exc)}")
finally:
SystemTelemetry.PROCESSING_VELOCITY.set(time.time() - start_time)
async def main_orchestrator() -> None:
logger = initialize_enterprise_logger()
logger.info("Initializing Enterprise AI-Driven Compliance DLP Engine runtime lifecycle...")
await start_telemetry_server()
client = AsyncOpenAI(api_key=AppConfig.OPENAI_API_KEY)
semaphore = asyncio.Semaphore(AppConfig.MAX_CONCURRENT_TASKS)
target_dir = pathlib.Path(AppConfig.DIRECTORY_TO_SCAN)
if not target_dir.exists():
logger.warning(f"Target directory {AppConfig.DIRECTORY_TO_SCAN} not found. Creating placeholder staging directory.")
target_dir.mkdir(parents=True, exist_ok=True)
allowed_extensions = {".txt", ".log", ".json", ".yaml", ".yml", ".csv", ".md"}
tasks: List[asyncio.Task[None]] = []
for file_item in target_dir.rglob("*"):
if file_item.is_file() and file_item.suffix.lower() in allowed_extensions:
tasks.append(asyncio.create_task(process_single_file_pipeline(str(file_item), semaphore, client)))
if tasks:
logger.info(f"Asynchronous task queue populated with {len(tasks)} target entities. Dispatching worker pool...")
await asyncio.gather(*tasks, return_exceptions=True)
logger.info("Batch compliance audit lifecycle execution complete. Standing by for infrastructure maintenance.")
else:
logger.info("No text-based configuration or log files identified within staging pathways.")
while True:
await asyncio.sleep(3600)
if **name** == "**main**":
try:
asyncio.run(main_orchestrator())
except KeyboardInterrupt:
runtime_logger = logging.getLogger("EnterpriseDLPAuditor")
runtime_logger.info("System gracefully terminated via DevOps interaction layer.")
