# Agent Gateway Explorer: Architecture Visualizer & Interactive Simulator

An interactive web application designed to explore, test, and explain the **Cross-Project Centralized Governance** architecture in Google Cloud's **Gemini Enterprise Agent Platform**.

---

## 🌟 Key Application Features

1. **Interactive Three-Tier Topology Map:**
   - Visualizes the 3 projects (`PROJECT_GOVERNANCE`, `PROJECT_CONCIERGE`, `PROJECT_SELLERS`).
   - Interactive SVG packet animation tracing the full request lifecycle from client to orchestrator, across the central gateway, through IAP policy checks, and into domain seller agents.
   - Component Inspector drawer with spec YAMLs for Gateways, Registries, Authz Extensions, and Reasoning Engines.

2. **Live Agent-to-Agent (A2A) Playground & Cloud Logging Stream:**
   - Interactive chat simulator executing real-world purchasing workflows.
   - Real-time IAP Policy Toggle (`roles/iap.egressor`): switch between **Default Deny (403 Forbidden)** and **Granted (200 OK)** to demonstrate zero-downtime policy enforcement.
   - Synchronized Cloud Logging terminal emulating `networkservices.googleapis.com/gateway_requests` audit events.

3. **Complete Codelab Guided Walkthrough:**
   - 8-step interactive guide covering API enablement, `core-gapi-services` registration, Central Gateway deployment, IAP Authz Extension binding, cross-project IAM delegation (`ar_agw_cross_project_sa`), Reasoning Engine deployment, and autodiscovery.
   - One-click copy buttons for terminal commands and YAML manifests.

4. **Dynamic Configuration & Script Generator:**
   - Input custom Project IDs and Region to automatically generate tailored `setup_env.sh` scripts and manifests.

---

## 🚀 How to Run Locally

Run the built-in lightweight Python server from your terminal:

```bash
python3 /usr/local/google/home/piyushshah/.gemini/jetski/brain/eda14a76-b3f0-466b-bc3a-ff9d3f129fef/agent_gateway_explorer/server.py 8080
```

Then open your browser to **`http://localhost:8080`**.
