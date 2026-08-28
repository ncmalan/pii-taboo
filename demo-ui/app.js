const transcript = document.querySelector("#transcript");
const composer = document.querySelector("#composer");
const messageInput = document.querySelector("#messageInput");
const projectInput = document.querySelector("#projectId");
const toolToggle = document.querySelector("#toolToggle");
const sendButton = document.querySelector("#sendButton");
const resetButton = document.querySelector("#resetButton");
const copyButton = document.querySelector("#copyButton");
const sampleButton = document.querySelector("#sampleButton");
const errorMessage = document.querySelector("#errorMessage");
const filterMetric = document.querySelector("#filterMetric");
const llmMetric = document.querySelector("#llmMetric");
const handleMetric = document.querySelector("#handleMetric");
const privacyStatus = document.querySelector("#privacyStatus");
const qwenStatus = document.querySelector("#qwenStatus");
const modelButton = document.querySelector("#modelButton");
const modelPopover = document.querySelector("#modelPopover");
const modelForm = document.querySelector("#modelForm");
const modelEndpoint = document.querySelector("#modelEndpoint");
const modelApiKey = document.querySelector("#modelApiKey");
const modelName = document.querySelector("#modelName");
const modelDefaults = document.querySelector("#modelDefaults");
const identityContext = document.querySelector("#identityContext");

const HANDLE_PATTERN = /((?:ACCOUNT|ADDRESS|EMAIL|NAME|PERSON|PHONE|URL|DATE|SECRET)-SH-[A-Z2-7]{12}(?:-(?:MONTH-NAME-ENG|MONTH-ISO|DAY-NUM|DAY-ISO|UNRESOLVED|FN|LN|USER|DOMAIN|DAY|MONTH|YEAR))?)/g;
const MODEL_STORAGE_KEY = "pii-taboo-model-config";
let sessionId = crypto.randomUUID();
let turns = [];
let modelContext = null;
let sending = false;
let defaultModelConfig = {
  url: modelEndpoint.value,
  model: modelName.value,
  api_key: "",
};
let storedModelConfig = null;
try {
  storedModelConfig = JSON.parse(sessionStorage.getItem(MODEL_STORAGE_KEY));
} catch (_) {
  sessionStorage.removeItem(MODEL_STORAGE_KEY);
}
if (!storedModelConfig
  || typeof storedModelConfig.url !== "string"
  || typeof storedModelConfig.model !== "string"
  || typeof storedModelConfig.api_key !== "string") {
  storedModelConfig = null;
  sessionStorage.removeItem(MODEL_STORAGE_KEY);
}
let activeModelConfig = storedModelConfig || { ...defaultModelConfig };
let qwenHealth = null;

function populateModelForm() {
  modelEndpoint.value = activeModelConfig.url;
  modelName.value = activeModelConfig.model;
  modelApiKey.value = activeModelConfig.api_key || "";
}

function usesCustomModel() {
  return activeModelConfig.url !== defaultModelConfig.url
    || activeModelConfig.model !== defaultModelConfig.model
    || Boolean(activeModelConfig.api_key);
}

function updateModelStatus() {
  if (usesCustomModel()) {
    qwenStatus.className = "is-custom";
    qwenStatus.querySelector("b").textContent = "custom endpoint";
  } else if (qwenHealth) {
    showServiceStatus(qwenStatus, qwenHealth);
  }
}

function roleName(turn) {
  if (turn.kind === "tool_call") return "Agent → tool";
  if (turn.kind === "tool_result") return "Tool result";
  return turn.role === "user" ? "User" : "Agent";
}

function roleBadge(turn) {
  if (turn.kind === "tool_call") return "TC";
  if (turn.kind === "tool_result") return "TR";
  return turn.role === "user" ? "U" : "A";
}

function appendProtectedText(container, text) {
  text.split(HANDLE_PATTERN).forEach((part) => {
    if (HANDLE_PATTERN.test(part)) {
      HANDLE_PATTERN.lastIndex = 0;
      const mark = document.createElement("mark");
      mark.className = "handle";
      mark.textContent = part;
      container.append(mark);
    } else {
      HANDLE_PATTERN.lastIndex = 0;
      container.append(document.createTextNode(part));
    }
  });
}

function messageNode(turn, protectedView) {
  const article = document.createElement("article");
  const toolClass = turn.kind === "tool_result" ? " tool" : turn.kind === "tool_call" ? " tool-call" : "";
  article.className = `message ${protectedView ? "protected" : "human"}${toolClass}`;
  article.classList.add(
    turn.kind === "message" ? `role-${turn.role}` : "role-tool"
  );
  if (turn.pending === "thinking" || (turn.pending === "protecting" && protectedView)) {
    article.classList.add("loading-row");
  }
  article.setAttribute("aria-label", `${protectedView ? "LLM view" : "User view"} ${roleName(turn)}`);

  const badge = document.createElement("span");
  badge.className = "speaker-badge";
  badge.textContent = roleBadge(turn);

  const body = document.createElement("div");
  body.className = "message-copy";
  const head = document.createElement("div");
  head.className = "message-head";
  const speaker = document.createElement("strong");
  speaker.textContent = roleName(turn);
  head.append(speaker);
  if (turn.kind !== "message") {
    const kind = document.createElement("span");
    kind.className = "kind-label";
    kind.textContent = turn.kind.replace("_", " ");
    head.append(kind);
  }

  const text = document.createElement("p");
  text.className = "message-text";
  if (protectedView) appendProtectedText(text, turn.protected);
  else text.textContent = turn.display;
  body.append(head, text);
  article.append(badge, body);
  return article;
}

function render() {
  identityContext.textContent = modelContext
    ? JSON.stringify(modelContext, null, 2)
    : "No protected person references yet.";
  transcript.replaceChildren();
  if (!turns.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = `<div class="empty-rule"><span></span><i></i><span></span></div><h2>One conversation. Two safe views.</h2><p>Send synthetic PII through the live pipeline. Every turn will align across the User and LLM views.</p>`;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Load the contradiction scenario";
    button.addEventListener("click", loadSample);
    empty.append(button);
    transcript.append(empty);
    copyButton.disabled = true;
    return;
  }

  turns.forEach((turn, index) => {
    const row = document.createElement("section");
    row.className = "turn-row";
    row.append(messageNode(turn, false));
    const rail = document.createElement("div");
    rail.className = "rail";
    const number = document.createElement("span");
    number.textContent = String(index + 1).padStart(2, "0");
    rail.append(number);
    row.append(rail, messageNode(turn, true));
    transcript.append(row);
  });
  copyButton.disabled = turns.some((turn) => turn.pending);
  transcript.scrollTop = transcript.scrollHeight;
}

function setSending(value) {
  sending = value;
  sendButton.disabled = value;
  messageInput.disabled = value;
  projectInput.disabled = value;
  toolToggle.disabled = value;
  modelButton.disabled = value;
  sendButton.querySelector("span").textContent = value ? "Working…" : "Send";
}

async function post(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function showServiceStatus(element, result) {
  element.className = result.ok ? "is-ok" : "is-error";
  element.querySelector("b").textContent = result.detail;
}

async function refreshServiceStatus() {
  try {
    const response = await fetch("/api/status");
    const result = await response.json();
    defaultModelConfig = { ...result.defaults, api_key: "" };
    if (!storedModelConfig) activeModelConfig = { ...defaultModelConfig };
    populateModelForm();
    showServiceStatus(privacyStatus, result.privacy);
    qwenHealth = result.qwen;
    updateModelStatus();
  } catch (_) {
    showServiceStatus(privacyStatus, { ok: false, detail: "unavailable" });
    qwenHealth = { ok: false, detail: "unavailable" };
    updateModelStatus();
  }
}

async function sendMessage(event) {
  event.preventDefault();
  if (sending || !messageInput.value.trim()) return;
  errorMessage.textContent = "";
  setSending(true);
  const message = messageInput.value.trim();
  const projectId = projectInput.value.trim();
  const includeTool = toolToggle.checked;
  const completionModelConfig = { ...activeModelConfig };
  const optimistic = {
    role: "user",
    kind: "message",
    display: message,
    protected: "Protecting PII…",
    pending: "protecting",
  };
  turns.push(optimistic);
  messageInput.value = "";
  toolToggle.checked = false;
  render();
  try {
    const protectedResult = await post("/api/protect", {
      session_id: sessionId,
      project_id: projectId,
      message,
      include_tool: includeTool,
    });
    turns[turns.length - 1] = protectedResult.turn;
    modelContext = protectedResult.model_context;
    filterMetric.textContent = `${protectedResult.metrics.filter_ms} ms`;
    handleMetric.textContent = protectedResult.metrics.handles;
    render();
    turns.push({
      role: "agent",
      kind: "message",
      display: "Model is composing…",
      protected: "Model is composing from protected history…",
      pending: "thinking",
    });
    render();
    const result = await post("/api/complete", {
      session_id: sessionId,
      project_id: projectId,
      model_config: completionModelConfig,
    });
    turns = result.turns;
    modelContext = result.model_context;
    filterMetric.textContent = `${result.metrics.filter_ms} ms`;
    llmMetric.textContent = `${(result.metrics.llm_ms / 1000).toFixed(1)} s`;
    handleMetric.textContent = result.metrics.handles;
    render();
  } catch (error) {
    turns = turns.filter((turn) => turn.pending !== "thinking");
    const unresolved = turns.findLast((turn) => turn.pending === "protecting");
    if (unresolved) {
      unresolved.protected = "Protection failed";
      delete unresolved.pending;
    }
    render();
    errorMessage.textContent = `${error.message}. Check the server terminal and configured services.`;
  } finally {
    setSending(false);
    messageInput.focus();
  }
}

function loadSample() {
  messageInput.value = "On 2026-08-01 John Blake told Alice to approve the migration. On 2026-08-14 John told Bob Jones to stop it. What inconsistency should the team investigate?";
  toolToggle.checked = true;
  messageInput.focus();
}

async function resetConversation() {
  if (sending) return;
  try {
    await post("/api/reset", { session_id: sessionId });
  } catch (_) {
    // A local reset is still useful if the server was restarted.
  }
  sessionId = crypto.randomUUID();
  turns = [];
  modelContext = null;
  filterMetric.textContent = "—";
  llmMetric.textContent = "—";
  handleMetric.textContent = "0";
  errorMessage.textContent = "";
  render();
  messageInput.focus();
}

async function copyProtected() {
  const text = turns.map((turn) => `${roleName(turn)}\n${turn.protected}`).join("\n\n");
  await navigator.clipboard.writeText(text);
  const original = copyButton.textContent;
  copyButton.lastChild.textContent = " Copied";
  setTimeout(() => { copyButton.lastChild.textContent = ` ${original.trim()}`; }, 1200);
}

modelForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!modelForm.reportValidity()) return;
  activeModelConfig = {
    url: modelEndpoint.value.trim(),
    model: modelName.value.trim(),
    api_key: modelApiKey.value,
  };
  storedModelConfig = usesCustomModel() ? { ...activeModelConfig } : null;
  if (storedModelConfig) sessionStorage.setItem(MODEL_STORAGE_KEY, JSON.stringify(storedModelConfig));
  else sessionStorage.removeItem(MODEL_STORAGE_KEY);
  updateModelStatus();
  modelPopover.hidePopover();
});

modelDefaults.addEventListener("click", () => {
  activeModelConfig = { ...defaultModelConfig };
  storedModelConfig = null;
  sessionStorage.removeItem(MODEL_STORAGE_KEY);
  populateModelForm();
  updateModelStatus();
  modelPopover.hidePopover();
});

composer.addEventListener("submit", sendMessage);
resetButton.addEventListener("click", resetConversation);
copyButton.addEventListener("click", copyProtected);
sampleButton?.addEventListener("click", loadSample);
messageInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) composer.requestSubmit();
});

render();
populateModelForm();
refreshServiceStatus();
