# Google Cloud Agent Gateway: Cross-Project Governance & Interactive Visualizer

This repository contains a comprehensive architecture specification, a step-by-step hands-on codelab, and an interactive web visualizer for implementing **Centralized Cross-Project Governance in Google Cloud Agent Gateway**.

---

## 📁 Repository Contents

- **`agent_gateway_explorer/`**: Interactive web application featuring:
  - **Topology Map**: Visualizing 3-project topology (Governance Hub, Concierge Consumer, Sellers Domain) and mTLS/SPIFFE flow.
  - **Observability & SIEM Hub**: Centralized BigQuery audit logging, multi-tenant sliced sinks, and distributed tracing.
  - **Multi-Agent Playground**: Live prompt simulation and dynamic IAP policy toggling (`ALLOW` vs `DENY`).
  - **Step-by-Step Walkthrough**: Guided implementation steps with copyable CLI commands.
- **`agent_gateway_cross_project_design.md`**: Complete 7-pillar enterprise architecture blueprint covering Shared VPC, Zero Trust mTLS/SPIFFE identities, full-duplex traffic inspection, and CI/CD lifecycle.
- **`codelab.md`**: Detailed step-by-step guide for manual multi-project deployment with Google Cloud CLI.

---

## 🚀 Quickstart: Running the Web Visualizer Locally

The web visualizer requires only Python (no Node.js or external dependencies needed):

```bash
# Navigate to the web app directory
cd agent_gateway_explorer

# Start the local server
python3 server.py 8080
```

Open **`http://localhost:8080`** in your browser to interact with the architecture diagram and test live multi-agent scenarios!

---

## 🏛 Architecture Overview

```
 ┌────────────────────────┐         ┌──────────────────────────────┐         ┌────────────────────────┐
 │   PROJECT_CONCIERGE    │         │      PROJECT_GOVERNANCE      │         │    PROJECT_SELLERS     │
 │                        │         │        (Shared VPC Hub)      │         │                        │
 │  ┌──────────────────┐  │  mTLS   │  ┌────────────────────────┐  │  mTLS   │  ┌──────────────────┐  │
 │  │Purchasing Concier│──┼─────────┼─▶│ Central Agent Gateway  │──┼─────────┼─▶│   Burger Seller  │  │
 │  │   Reasoning Eng  │  │ (SPIFFE)│  │   (AGENT_TO_ANYWHERE)  │  │ (SPIFFE)│  │   (200 OK ALLOW) │  │
 │  └──────────────────┘  │         │  └───────────┬────────────┘  │         │  └──────────────────┘  │
 │                        │         │              │               │         │                        │
 │                        │         │              ▼               │         │  ┌──────────────────┐  │
 │                        │         │  ┌────────────────────────┐  │         │  │   Pizza Seller   │  │
 │                        │         │  │    IAP Authz Policy    │──┼─ 403 ───┼─▶│   (Default Deny) │  │
 │                        │         │  │   (roles/iap.egressor) │  │ Forbidden│ └──────────────────┘  │
 │                        │         │  └────────────────────────┘  │         │                        │
 └────────────────────────┘         └──────────────────────────────┘         └────────────────────────┘
```

---

## 📜 License
Apache 2.0
