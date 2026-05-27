 # 🛡️ AI-Driven Corporate Compliance Auditor & DLP Guardian
An enterprise-grade, high-throughput, non-blocking asynchronous **Data Leakage Prevention (DLP)** and **Governance, Risk, and Compliance (GRC)** microservice designed to execute deterministic and cognitive scanning against unstructured data landscapes.
## ⚡ Core Architectural Pillars
 * 🤖 **Asynchronous Concurrent Pipeline:** Engine structured completely on top of Python's native asyncio loop and parallel non-blocking disk access handlers (aiofiles).
 * 🎯 **Two-Tier Strategic Classification:** Runs a local deterministic compiled regex matrix to intercept plain text signatures, defaulting clean text to Tier 2 cognitive evaluation models via OpenAI AsyncClient.
 * 🔒 **Deterministic JSON Enforcement:** Guarantees structural input parsing alignment using strict Pydantic V2 schemas mapped directly to OpenAI's native Structured Outputs model backend engine (response_format).
 * 📊 **Distributed Production Observability:** Exposes live application health and traffic telemetry data directly into container monitoring graphs using an embedded native Prometheus instrument server.
 * 🔄 **Production-Grade Resiliency:** Intercepts cloud network dropouts utilizing multi-tier exponential backoff and randomized jitter execution layers.
## ⚙️ Infrastructure Initialization
System configuration variables are resolved dynamically using host environment parameters:
 * 📂 DLP_SCAN_DIR: Specifies target directories for recursive data validation scanning. *Defaults to ./target_audit_directory*.
 * 🔑 OPENAI_API_KEY: Authentication vector processing cognitive parsing logic execution.
 * 🔌 DLP_METRICS_PORT: Local endpoint binding for real-time Prometheus monitoring tracking data metrics. *Defaults to 8000*.
 * 🚀 DLP_MAX_CONCURRENCY: Numeric semaphore floor scaling file system process pipelines concurrently. *Defaults to 10*.
## 💻 Execution & Deployment Lifecycle
### 🛠️ Local Development Execution
```bash
# Install high-performance enterprise dependencies
pip install -r requirements.txt

# Inject your cognitive analytical master authentication vector
export OPENAI_API_KEY="your-production-api-key"

# Dispatch the core asynchronous orchestration lifecycle
python main.py

```
### 🐳 Containerized Orchestration Deployment
```bash
# Build the secure multi-stage runner infrastructure image
docker build -t enterprise-dlp-guardian:latest .

# Run the isolated, non-root microservice container
docker run -d \
  --name dlp_compliance_service \
  -e OPENAI_API_KEY="your-production-api-key" \
  -v /var/log/corporate_vault:/app/compliance_vault \
  -p 8000:8000 \
  enterprise-dlp-guardian:latest

