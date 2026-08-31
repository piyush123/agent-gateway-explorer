/* Agent Gateway Explorer & Architecture Visualizer - Application Logic */

// State Management
const state = {
  activeTab: 'topology',
  activeStep: 1,
  pizzaPolicyAllowed: false,
  inspectedResource: 'agw',
  activeTenant: 'central',
  govProject: 'ps-agw-gov-0901',
  conProject: 'ps-agw-con-0901',
  selProject: 'ps-agw-sel-0901',
  region: 'us-central1',
  agwName: 'centralized-agw'
};

// Resource Inspector Data Dictionary
const resourceSpecs = {
  agw: {
    title: "Central Agent Gateway (AGENT_TO_ANYWHERE)",
    desc: "A managed Google Cloud regional network proxy running in PROJECT_GOVERNANCE. Intercepts all outbound traffic initiated by Reasoning Engines and delegates authorization evaluations to IAP Service Extensions.",
    yaml: `name: centralized-agw
protocols:
  - MCP
googleManaged:
  governedAccessPath: AGENT_TO_ANYWHERE
registries:
  - "//agentregistry.googleapis.com/projects/PROJECT_GOVERNANCE/locations/us-central1"`
  },
  registry: {
    title: "Central Agent Registry Service Catalog",
    desc: "The single enterprise service directory in PROJECT_GOVERNANCE. Hosts vetted service definitions for peer agents (A2A), MCP tool servers, and foundational Core Google APIs.",
    yaml: `gcloud agent-registry services create core-gapi-services \\
  --project=PROJECT_GOVERNANCE \\
  --location=us-central1 \\
  --display-name="gapi.core.services" \\
  --endpoint-spec-type=no-spec \\
  --interfaces=protocolBinding=JSONRPC,url=https://us-central1-aiplatform.mtls.googleapis.com`
  },
  iap: {
    title: "IAP Authorization Service Extension & Policy",
    desc: "Identity-Aware Proxy (IAP) extension evaluating caller SPIFFE identities against roles/iap.egressor IAM policies on target Agent Registry resources.",
    yaml: `name: centralized-agw-authz-policy-profile-iap
target:
  resources:
    - "projects/PROJECT_GOVERNANCE/locations/us-central1/agentGateways/centralized-agw"
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/PROJECT_GOVERNANCE/locations/us-central1/authzExtensions/centralized-agw-svc-ext-authz-iap-dryrun"`
  },
  obs: {
    title: "Central SIEM & Log Bucket Sink",
    desc: "Centralized BigQuery / Chronicle export capturing full audit logs (caller SPIFFE, target tool, IAP verdict, latency, DLP findings) with multi-tenant log routing sinks.",
    yaml: `gcloud logging sinks create central-siem-sink \\
  bigquery.googleapis.com/projects/PROJECT_GOVERNANCE/datasets/agent_gateway_siem \\
  --log-filter='logName="projects/PROJECT_GOVERNANCE/logs/networkservices.googleapis.com%2Fgateway_requests"'`
  },
  concierge: {
    title: "Purchasing Concierge Agent (Reasoning Engine)",
    desc: "Deployed in PROJECT_CONCIERGE with AGENT_IDENTITY (SPIFFE). Performs dynamic REST autodiscovery on session startup to locate seller agents without hardcoding.",
    yaml: `concierge_config = {
    "identity_type": "AGENT_IDENTITY",
    "agent_gateway_config": {
        "agent_to_anywhere_config": {
            "agent_gateway": "projects/PROJECT_GOVERNANCE/locations/us-central1/agentGateways/centralized-agw"
        }
    }
}`
  },
  "concierge-sa": {
    title: "Vertex AI Service Agent Identity",
    desc: "The control plane service account (service-<CONCIERGE_NUM>@gcp-sa-aiplatform.iam.gserviceaccount.com) granted cross-project role ar_agw_cross_project_sa in PROJECT_GOVERNANCE.",
    yaml: `gcloud projects add-iam-policy-binding PROJECT_GOVERNANCE \\
  --member="serviceAccount:service-CONCIERGE_NUM@gcp-sa-aiplatform.iam.gserviceaccount.com" \\
  --role="projects/PROJECT_GOVERNANCE/roles/ar_agw_cross_project_sa"`
  },
  "con-log": {
    title: "Concierge Spoke Log Router Sink",
    desc: "Filters and routes redacted operational logs and OpenTelemetry spans from the Central Gateway to PROJECT_CONCIERGE Cloud Logging.",
    yaml: `gcloud logging sinks create concierge-ops-sink \\
  logging.googleapis.com/projects/PROJECT_CONCIERGE/locations/global/buckets/_Default \\
  --log-filter='jsonPayload.calling_project="PROJECT_NUMBER_CONCIERGE"'`
  },
  burger: {
    title: "Burger Seller Specialist Agent",
    desc: "Deployed in PROJECT_SELLERS. Explicitly authorized in Agent Registry with roles/iap.egressor granted to the Concierge's SPIFFE machine identity.",
    yaml: `gcloud beta iap web add-iam-policy-binding \\
  --resource-type=agent-registry \\
  --agent=BURGER_AGENT_ID \\
  --region=us-central1 \\
  --project=PROJECT_GOVERNANCE \\
  --role="roles/iap.egressor" \\
  --member="principal://agents.global.org-ORG_ID.system.id.goog/resources/aiplatform/projects/PROJECT_NUMBER_CONCIERGE/locations/us-central1/reasoningEngines/CONCIERGE_ENGINE_ID"`
  },
  pizza: {
    title: "Pizza Seller Specialist Agent",
    desc: "Deployed in PROJECT_SELLERS. Initially left unbound under Default Deny (403 Forbidden). Can be granted live via IAP IAM policy update without container redeployment.",
    yaml: `# Deny by default until granted:
gcloud beta iap web add-iam-policy-binding \\
  --resource-type=agent-registry \\
  --agent=PIZZA_AGENT_ID \\
  --region=us-central1 \\
  --project=PROJECT_GOVERNANCE \\
  --role="roles/iap.egressor" \\
  --member="principal://agents.global.org-ORG_ID.system.id.goog/.../reasoningEngines/CONCIERGE_ENGINE_ID"`
  },
  "sel-log": {
    title: "Sellers Spoke Log Router Sink",
    desc: "Filters and routes inbound invocation telemetry and error metrics to PROJECT_SELLERS Cloud Monitoring dashboards.",
    yaml: `gcloud logging sinks create sellers-ops-sink \\
  logging.googleapis.com/projects/PROJECT_SELLERS/locations/global/buckets/_Default \\
  --log-filter='jsonPayload.destination_project="PROJECT_NUMBER_SELLERS"'`
  }
};

// Sample SIEM Audit Log Records
const siemLogRecords = [
  {
    time: "2026-09-01 22:30:12",
    tenant: "concierge",
    caller: "principal://.../reasoningEngines/3569530964470136832",
    dest: "services/burger-seller-agent",
    verdict: "ALLOWED",
    status: 200,
    latency: "148 ms",
    dlp: "Clean"
  },
  {
    time: "2026-09-01 22:29:45",
    tenant: "concierge",
    caller: "principal://.../reasoningEngines/3569530964470136832",
    dest: "services/pizza-seller-agent",
    verdict: "DENIED",
    status: 403,
    latency: "12 ms",
    dlp: "Clean"
  },
  {
    time: "2026-09-01 22:28:01",
    tenant: "concierge",
    caller: "principalSet://.../projects/PROJECT_NUMBER_CONCIERGE",
    dest: "services/core-gapi-services",
    verdict: "ALLOWED",
    status: 200,
    latency: "24 ms",
    dlp: "Clean"
  },
  {
    time: "2026-09-01 22:26:50",
    tenant: "sellers",
    caller: "principalSet://.../projects/PROJECT_NUMBER_SELLERS",
    dest: "services/core-gapi-services",
    verdict: "ALLOWED",
    status: 200,
    latency: "19 ms",
    dlp: "Clean"
  },
  {
    time: "2026-09-01 22:25:10",
    tenant: "concierge",
    caller: "principal://.../reasoningEngines/3569530964470136832",
    dest: "services/burger-seller-agent",
    verdict: "ALLOWED",
    status: 200,
    latency: "162 ms",
    dlp: "Clean"
  }
];

// Codelab Walkthrough Step Data
const walkthroughSteps = [
  {
    step: 1,
    title: "Setup & Three-Project Topology",
    duration: "10 mins",
    desc: "Create and configure three isolated Google Cloud projects: Governance (Central Hub), Concierge (Consumer Orchestrator), and Sellers (Vendor Domain).",
    code: `# Set shell environment variables
export PROJECT_GOVERNANCE="ps-agw-gov-0901"
export PROJECT_CONCIERGE="ps-agw-con-0901"
export PROJECT_SELLERS="ps-agw-sel-0901"
export REGION="us-central1"
export AGW_NAME="centralized-agw"

# Enable required Google Cloud APIs across all 3 projects
for PROJ in \${PROJECT_GOVERNANCE} \${PROJECT_CONCIERGE} \${PROJECT_SELLERS}; do
  gcloud services enable \\
    agentregistry.googleapis.com aiplatform.googleapis.com \\
    iap.googleapis.com networkservices.googleapis.com \\
    networksecurity.googleapis.com storage.googleapis.com \\
    --project=\${PROJ}
done`
  },
  {
    step: 2,
    title: "Register Core Google APIs Endpoint",
    duration: "10 mins",
    desc: "Register foundational Google Cloud APIs in Central Agent Registry so agents can route through the gateway to reach aiplatform, iamcredentials, and telemetry.",
    code: `# 1. Register core Google APIs
gcloud agent-registry services create core-gapi-services \\
  --project=\${PROJECT_GOVERNANCE} \\
  --location=\${REGION} \\
  --display-name="gapi.core.services" \\
  --endpoint-spec-type=no-spec \\
  --interfaces=protocolBinding=JSONRPC,url=https://\${REGION}-aiplatform.mtls.googleapis.com \\
  --interfaces=protocolBinding=JSONRPC,url=https://agentregistry.googleapis.com

# 2. Authorize all 3 project principalSets
for PNUM in \${PROJECT_NUMBER_GOVERNANCE} \${PROJECT_NUMBER_CONCIERGE} \${PROJECT_NUMBER_SELLERS}; do
  gcloud beta iap web add-iam-policy-binding \\
    --resource-type=agent-registry \\
    --endpoint=\${ENDPOINT_ID} \\
    --region=\${REGION} \\
    --project=\${PROJECT_GOVERNANCE} \\
    --role="roles/iap.egressor" \\
    --member="principalSet://agents.global.org-\${ORG_ID}.system.id.goog/attribute.platformContainer/aiplatform/projects/\${PNUM}"
done`
  },
  {
    step: 3,
    title: "Deploy Central Agent Gateway",
    duration: "10 mins",
    desc: "Deploy the regional Agent Gateway in AGENT_TO_ANYWHERE mode pointing to the Central Agent Registry in PROJECT_GOVERNANCE.",
    code: `cat > cfg/\${AGW_NAME}.yaml << EOF
name: \${AGW_NAME}
protocols:
  - MCP
googleManaged:
  governedAccessPath: AGENT_TO_ANYWHERE
registries:
  - "//agentregistry.googleapis.com/projects/\${PROJECT_GOVERNANCE}/locations/\${REGION}"
EOF

gcloud network-services agent-gateways import \${AGW_NAME} \\
  --source="cfg/\${AGW_NAME}.yaml" \\
  --location=\${REGION} \\
  --project=\${PROJECT_GOVERNANCE}`
  },
  {
    step: 4,
    title: "Configure IAP Authz Extension & Policy",
    duration: "10 mins",
    desc: "Attach Identity-Aware Proxy (IAP) authorization extension using REQUEST_AUTHZ policy profile for per-request cryptographic evaluation.",
    code: `# 1. Create Authz Extension
gcloud service-extensions authz-extensions import \${AGW_NAME}-svc-ext-authz-iap-dryrun \\
  --source=cfg/\${AGW_NAME}-svc-ext-authz-iap-dryrun.yaml \\
  --location=\${REGION} \\
  --project=\${PROJECT_GOVERNANCE}

# 2. Create Authz Policy
gcloud beta network-security authz-policies import \${AGW_NAME}-authz-policy-profile-iap \\
  --source=cfg/\${AGW_NAME}-authz-policy-profile-iap.yaml \\
  --location=\${REGION} \\
  --project=\${PROJECT_GOVERNANCE}`
  },
  {
    step: 5,
    title: "Configure Cross-Project IAM Permissions",
    duration: "5 mins",
    desc: "Create custom role ar_agw_cross_project_sa and grant it to spoke Vertex AI Service Agents to allow cross-project gateway resolution and attachment.",
    code: `gcloud iam roles create ar_agw_cross_project_sa \\
  --project=\${PROJECT_GOVERNANCE} \\
  --title="Runtime Agent Gateway Cross-Project SA" \\
  --permissions="networkservices.agentGateways.get,networkservices.agentGateways.use,networkservices.operations.get"

for SA in \${CONCIERGE_AI_SA} \${SELLERS_AI_SA}; do
  gcloud projects add-iam-policy-binding \${PROJECT_GOVERNANCE} \\
    --member="serviceAccount:\${SA}" \\
    --role="projects/\${PROJECT_GOVERNANCE}/roles/ar_agw_cross_project_sa"
done`
  },
  {
    step: 6,
    title: "Deploy Seller & Concierge Reasoning Engines",
    duration: "15 mins",
    desc: "Deploy Burger & Pizza Seller agents in PROJECT_SELLERS and Purchasing Concierge in PROJECT_CONCIERGE bound to the central gateway.",
    code: `# Deploy Burger & Pizza to PROJECT_SELLERS
uv run python deploy_burger.py \\
  --project=\${PROJECT_SELLERS} \\
  --region=\${REGION} \\
  --governance-project=\${PROJECT_GOVERNANCE} \\
  --gateway=projects/\${PROJECT_GOVERNANCE}/locations/\${REGION}/agentGateways/\${AGW_NAME}

# Deploy Purchasing Concierge to PROJECT_CONCIERGE
uv run python deploy_concierge_adk.py \\
  --project=\${PROJECT_CONCIERGE} \\
  --region=\${REGION} \\
  --staging-bucket=gs://\${PROJECT_GOVERNANCE}-shared-staging \\
  --gateway-name=\${AGW_NAME} \\
  --gateway-project=\${PROJECT_GOVERNANCE}`
  },
  {
    step: 7,
    title: "Register Agent Endpoints in Registry",
    duration: "10 mins",
    desc: "Publish regional mTLS endpoints with numeric project numbers into Central Agent Registry for dynamic runtime discovery.",
    code: `gcloud agent-registry services create burger-seller-agent \\
  --project=\${PROJECT_GOVERNANCE} \\
  --location=\${REGION} \\
  --display-name="Burger Seller Agent" \\
  --agent-spec-type=no-spec \\
  --interfaces=protocolBinding=JSONRPC,url=https://\${REGION}-aiplatform.mtls.googleapis.com/v1/projects/\${PROJECT_NUMBER_SELLERS}/locations/\${REGION}/reasoningEngines/\${BURGER_ENGINE_ID}`
  },
  {
    step: 8,
    title: "Live IAP Policy Governance & Verification",
    duration: "10 mins",
    desc: "Enforce Default Deny security posture, verify 403 on Pizza Seller, and dynamically grant roles/iap.egressor with immediate 200 OK success!",
    code: `# Dynamically grant IAP egress to Pizza Seller without redeploying
gcloud beta iap web add-iam-policy-binding \\
  --resource-type=agent-registry \\
  --agent=\${PIZZA_AGENT_ID} \\
  --region=\${REGION} \\
  --project=\${PROJECT_GOVERNANCE} \\
  --role="roles/iap.egressor" \\
  --member="\${CONCIERGE_SPIFFE_PRINCIPAL}"`
  }
];

// Initialize DOM Events
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  renderWalkthroughStep(1);
  renderSiemLogs();
  updatePolicyUI();
});

// Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      
      const target = tab.dataset.tab;
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      document.getElementById(`tab-${target}`).classList.add('active');
      state.activeTab = target;
    });
  });
}

// Resource Inspector
function inspectResource(key) {
  state.inspectedResource = key;
  const spec = resourceSpecs[key] || resourceSpecs.agw;
  
  document.getElementById('inspect-title').textContent = `🔍 Component Inspector: ${spec.title}`;
  document.getElementById('inspect-code').textContent = spec.yaml;
  
  const drawer = document.getElementById('inspector-drawer');
  if (drawer) {
    drawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function copyInspectorYaml() {
  const text = document.getElementById('inspect-code').textContent;
  navigator.clipboard.writeText(text);
  showToast('Copied configuration spec to clipboard!', 'success');
}

// Topology Animation Flow
function animateFlow(type) {
  const packet = document.getElementById('anim-packet');
  if (!packet) return;

  packet.style.opacity = '1';
  
  if (type === 'burger') {
    packet.setAttribute('fill', '#34a853');
    runPacketPath([
      { x: 170, y: 150 },
      { x: 170, y: 240 },
      { x: 375, y: 170 },
      { x: 500, y: 220 },
      { x: 500, y: 260 },
      { x: 625, y: 160 },
      { x: 705, y: 160 }
    ]);
    addLogEntry('GET', 'https://agentregistry.googleapis.com/v1alpha/projects/PROJECT_GOVERNANCE/.../services', 200, 'ALLOWED', 'Autodiscovered burger-seller-agent');
    addLogEntry('POST', 'https://us-central1-aiplatform.mtls.googleapis.com/.../reasoningEngines/BURGER_ENGINE_ID:generateContent', 200, 'ALLOWED', 'Burger order confirmed (IDR 850,000)');
  } else {
    if (state.pizzaPolicyAllowed) {
      packet.setAttribute('fill', '#34a853');
      runPacketPath([
        { x: 170, y: 150 },
        { x: 170, y: 240 },
        { x: 375, y: 170 },
        { x: 500, y: 220 },
        { x: 500, y: 260 },
        { x: 625, y: 280 },
        { x: 705, y: 280 }
      ]);
      addLogEntry('POST', 'https://us-central1-aiplatform.mtls.googleapis.com/.../reasoningEngines/PIZZA_ENGINE_ID:generateContent', 200, 'ALLOWED', 'Pizza order granted & confirmed (IDR 11,000,000)');
    } else {
      packet.setAttribute('fill', '#ea4335');
      runPacketPath([
        { x: 170, y: 150 },
        { x: 170, y: 240 },
        { x: 375, y: 170 },
        { x: 500, y: 220 },
        { x: 500, y: 260 },
        { x: 625, y: 180 }
      ]);
      addLogEntry('POST', 'https://us-central1-aiplatform.mtls.googleapis.com/.../reasoningEngines/PIZZA_ENGINE_ID:generateContent', 403, 'DENIED', 'IAP Policy Check: Permission Denied (Default Deny)');
    }
  }
}

function runPacketPath(points) {
  const packet = document.getElementById('anim-packet');
  let index = 0;
  
  function nextStep() {
    if (index >= points.length) {
      setTimeout(() => { packet.style.opacity = '0'; }, 800);
      return;
    }
    packet.setAttribute('cx', points[index].x);
    packet.setAttribute('cy', points[index].y);
    index++;
    setTimeout(nextStep, 220);
  }
  nextStep();
}

function setScenario(scenario) {
  if (scenario === 'burger') {
    animateFlow('burger');
  } else {
    animateFlow('pizza');
  }
}

// Toggle Pizza IAP Policy
function togglePizzaPolicy() {
  state.pizzaPolicyAllowed = !state.pizzaPolicyAllowed;
  updatePolicyUI();
  
  if (state.pizzaPolicyAllowed) {
    addLogEntry('IAM', 'gcloud beta iap web add-iam-policy-binding --agent=PIZZA_AGENT_ID', 200, 'GRANTED', 'Live policy update: roles/iap.egressor granted');
    showToast('⚡ IAP Policy Granted: roles/iap.egressor active on pizza-seller-agent (200 OK)', 'success');
  } else {
    addLogEntry('IAM', 'gcloud beta iap web remove-iam-policy-binding --agent=PIZZA_AGENT_ID', 200, 'REVOKED', 'Live policy update: Default Deny restored');
    showToast('🔒 IAP Policy Revoked: Pizza Agent restored to Default Deny (HTTP 403)', 'warn');
  }
}

function updatePolicyUI() {
  const pizzaBadge = document.getElementById('badge-pizza-status');
  const svgText = document.getElementById('svg-pizza-policy-text');
  const svgBox = document.getElementById('svg-pizza-box');
  const simToggleText = document.getElementById('sim-btn-toggle-text');
  const policySwitches = document.querySelectorAll('.policy-switch-container');
  
  policySwitches.forEach(sw => {
    sw.classList.toggle('active', state.pizzaPolicyAllowed);
    const label = sw.querySelector('.switch-label');
    if (label) {
      label.textContent = state.pizzaPolicyAllowed ? 'Pizza Policy: ALLOWED (200 OK)' : 'Pizza Policy: DENIED (403 Block)';
    }
  });
  
  if (state.pizzaPolicyAllowed) {
    if (pizzaBadge) {
      pizzaBadge.className = 'status-indicator status-active';
      pizzaBadge.innerHTML = '<span class="status-dot"></span> ALLOW (200 OK)';
    }
    if (svgText) {
      svgText.textContent = 'Policy: ALLOW (200 OK)';
      svgText.setAttribute('fill', '#34a853');
    }
    if (svgBox) {
      svgBox.setAttribute('stroke', '#34a853');
    }
    if (simToggleText) {
      simToggleText.textContent = 'Pizza Access: ALLOWED (200 OK) — Click to Deny';
    }
  } else {
    if (pizzaBadge) {
      pizzaBadge.className = 'status-indicator status-denied';
      pizzaBadge.innerHTML = '<span class="status-dot"></span> DENY (403 Blocked)';
    }
    if (svgText) {
      svgText.textContent = 'Policy: DENIED (403 Block)';
      svgText.setAttribute('fill', '#ea4335');
    }
    if (svgBox) {
      svgBox.setAttribute('stroke', '#ea4335');
    }
    if (simToggleText) {
      simToggleText.textContent = 'Pizza Access: DENIED (403 Block) — Click to Allow';
    }
  }
}

// Toast Notifications
function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Observability & Sliced Spoke Filter
function setTenantView(tenant, btnElement) {
  state.activeTenant = tenant;
  document.querySelectorAll('.tenant-btn').forEach(btn => btn.classList.remove('active'));
  if (btnElement) {
    btnElement.classList.add('active');
  }
  
  const title = document.getElementById('siem-table-title');
  if (title) {
    if (tenant === 'central') {
      title.textContent = "📊 Central SIEM Audit Logs (All Projects & Verdicts)";
    } else if (tenant === 'concierge') {
      title.textContent = "🛒 Concierge Spoke Filtered Logs (Outbound A2A & Discovery)";
    } else {
      title.textContent = "🍔 Sellers Spoke Filtered Logs (Inbound Handler Telemetry)";
    }
  }
  
  renderSiemLogs();
}

function renderSiemLogs() {
  const tbody = document.getElementById('siem-table-body');
  if (!tbody) return;
  
  let records = siemLogRecords;
  if (state.activeTenant !== 'central') {
    records = siemLogRecords.filter(r => r.tenant === state.activeTenant);
  }
  
  tbody.innerHTML = records.map(r => `
    <tr>
      <td style="color: #5f6368;">${r.time}</td>
      <td style="color: var(--primary);">${r.caller}</td>
      <td style="font-weight: 600;">${r.dest}</td>
      <td><span class="log-badge ${r.verdict === 'ALLOWED' ? 'badge-200' : 'badge-403'}">${r.verdict}</span></td>
      <td style="font-weight: 700; color: ${r.status === 200 ? 'var(--success)' : 'var(--danger)'};">${r.status}</td>
      <td>${r.latency}</td>
    </tr>
  `).join('');
}

// Live Simulator Chat Logic
function handleChatKey(e) {
  if (e.key === 'Enter') {
    submitChatInput();
  }
}

function submitChatInput() {
  const input = document.getElementById('chat-user-input');
  const text = input.value.trim();
  if (!text) return;
  
  sendPrompt(text);
  input.value = '';
}

function sendPrompt(promptText) {
  const chatContainer = document.getElementById('chat-history-container');
  
  // Append User Bubble
  const userBubble = document.createElement('div');
  userBubble.className = 'chat-bubble user';
  userBubble.textContent = promptText;
  chatContainer.appendChild(userBubble);
  chatContainer.scrollTop = chatContainer.scrollHeight;
  
  // Simulate Agent Processing
  setTimeout(() => {
    let agentResponse = "";
    const lower = promptText.toLowerCase();
    
    if (lower.includes('burger') || lower.includes('cheeseburger')) {
      animateFlow('burger');
      agentResponse = "You want to order 10 Classic Cheeseburgers. The total price is IDR 850,000 (Order ID: e8f9c732-f347-4cc4-acff-cfe09ccbeddd). Your order has been placed with the Burger Seller in PROJECT_SELLERS!";
    } else if (lower.includes('pizza')) {
      animateFlow('pizza');
      if (state.pizzaPolicyAllowed) {
        agentResponse = "Your order for 50 BBQ Pizzas has been placed with the Pizza Seller in PROJECT_SELLERS! Total price: IDR 5,500,000 (Order ID: piz-88392-aa7c).";
      } else {
        agentResponse = "I am sorry, but I am unable to place the order for 50 BBQ Pizzas. The Central Agent Gateway evaluated IAP security policies and returned HTTP 403 Forbidden (Default Deny).";
      }
    } else if (lower.includes('seller') || lower.includes('list') || lower.includes('catalog')) {
      addLogEntry('GET', 'https://agentregistry.googleapis.com/v1alpha/projects/PROJECT_GOVERNANCE/.../services', 200, 'ALLOWED', 'Autodiscovery catalog list');
      agentResponse = "I have queried the Central Agent Registry in PROJECT_GOVERNANCE and discovered 2 domain sellers: (1) Burger Seller Agent (mTLS JSONRPC) [Policy: ALLOW], (2) Pizza Seller Agent (mTLS JSONRPC) [Policy: " + (state.pizzaPolicyAllowed ? "ALLOW" : "DENIED") + "].";
    } else {
      agentResponse = "I have routed your request through the Central Agent Gateway. Please specify an order for Cheeseburgers or Pizzas to test cross-project governance!";
    }
    
    const agentBubble = document.createElement('div');
    agentBubble.className = 'chat-bubble agent';
    agentBubble.textContent = agentResponse;
    chatContainer.appendChild(agentBubble);
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }, 400);
}

function clearSimChat() {
  const chatContainer = document.getElementById('chat-history-container');
  chatContainer.innerHTML = `
    <div class="chat-bubble system">
      Session Initialized. Dynamic autodiscovery queried Central Agent Registry. Discovered 2 sellers.
    </div>
    <div class="chat-bubble agent">
      Hello! I am your Purchasing Concierge. How can I assist with your food orders today?
    </div>
  `;
}

// Log Stream Emulation
function addLogEntry(method, url, status, result, details) {
  const logTerminal = document.getElementById('logs-terminal-stream');
  if (!logTerminal) return;
  
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const entry = document.createElement('div');
  entry.className = `log-entry ${status === 200 ? 'allowed' : 'denied'}`;
  
  const badgeClass = status === 200 ? 'badge-200' : 'badge-403';
  
  entry.innerHTML = `
    <div class="log-header">
      <span style="color:#9aa0a6;">${now}</span>
      <span class="log-badge ${badgeClass}">${status} ${status === 200 ? 'OK' : 'FORBIDDEN'} • ${result}</span>
    </div>
    <div class="log-url">${method} ${url}</div>
    <div class="log-details">${details}</div>
  `;
  
  logTerminal.insertBefore(entry, logTerminal.firstChild);
}

// Stepper Walkthrough
function goToStep(stepNumber) {
  state.activeStep = stepNumber;
  
  document.querySelectorAll('.step-item').forEach((item, idx) => {
    if (idx + 1 === stepNumber) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });
  
  renderWalkthroughStep(stepNumber);
}

function renderWalkthroughStep(stepNumber) {
  const container = document.getElementById('step-detail-content');
  const data = walkthroughSteps.find(s => s.step === stepNumber) || walkthroughSteps[0];
  
  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h3 style="font-size: 18px; font-weight: 600;">Step ${data.step}: ${data.title}</h3>
      <span class="project-id-tag">Duration: ${data.duration}</span>
    </div>
    <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 16px; line-height: 1.6;">
      ${data.desc}
    </p>
    <div class="code-block-container">
      <div class="code-header">
        <span>Terminal Commands</span>
        <button class="copy-btn" onclick="copyStepCode(${data.step})">Copy Commands</button>
      </div>
      <pre class="code-content"><code id="step-code-${data.step}">${escapeHtml(data.code)}</code></pre>
    </div>
    <div style="margin-top: 20px; display: flex; justify-content: space-between;">
      <button class="btn-pill" ${stepNumber === 1 ? 'disabled style="opacity:0.5;"' : `onclick="goToStep(${stepNumber - 1})"`}>← Previous Step</button>
      <button class="btn-pill btn-primary" ${stepNumber === 8 ? 'disabled style="opacity:0.5;"' : `onclick="goToStep(${stepNumber + 1})"`}>Next Step →</button>
    </div>
  `;
}

function copyStepCode(stepNum) {
  const code = document.getElementById(`step-code-${stepNum}`).textContent;
  navigator.clipboard.writeText(code);
  showToast(`Copied Step ${stepNum} commands to clipboard!`, 'success');
}

function copyCode(elementId) {
  const code = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(code);
  showToast('Copied code to clipboard!', 'success');
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
