// ============================================================
// Bug Extension – Background Script
// Combines: request capture (rep+), endpoint hunting, context menus
// ============================================================

const connectedPanels = new Map(); // Track active devtools tabs: tabId -> port
const requestMap = new Map();
const interceptState = new Map();

function normalizeTabId(tabId) {
  const id = Number(tabId);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function isTargetTab(tabId) {
  const id = normalizeTabId(tabId);
  return id !== null && connectedPanels.has(id);
}

function getPanelPort(tabId) {
  const id = normalizeTabId(tabId);
  return id !== null ? connectedPanels.get(id) : null;
}

// ── Endpoint Hunter state ──
let endpoints = new Map();
let dynamicPatterns = new Map();
let saveTimeout = null;

// ── Config (from endpoint-hunter) ──
const CONFIG = {
  IGNORED_EXTENSIONS: ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.woff', '.woff2', '.ttf', '.m4s', '.ico', '.eot', '.otf'],
  SENSITIVE_PATHS: ['/admin', '/api', '/auth', '/login', '/logout', '/token', '/user', '/users', '/account', '/internal', '/private', '/debug', '/phpmyadmin', '/graphql'],
  SENSITIVE_PARAMS: ['token', 'auth', 'key', 'password', 'pwd', 'session', 'redirect', 'jwt', 'csrf', 'lostpassword', 'secret', 'api_key', 'apikey', 'access_token'],
  SENSITIVE_METHODS: ['PUT', 'DELETE', 'PATCH'],
  TAG_RULES: {
    xss: { params: ['q', 'query', 'search', 'searchTerm', 'term', 'filter', 's', 'msg', 'comment', 'text', 'input', 'body', 'payload', 'combine', 'keys', 'name', 'title', 'content', 'value', 'data', 'html', 'url', 'redirect_uri', 'return_url', 'callback', 'next'], methods: ['GET', 'POST'] },
    sqli: { params: ['id', 'user', 'uid', 'page', 'item', 'order', 'query', 'search', 'q', 'where', 'sql', 'sort', 'column', 'table', 'field', 'category', 'cat', 'type', 'group'], methods: ['GET', 'POST'] },
    lfi: { params: ['file', 'path', 'template', 'include', 'view', 'download', 'render', 'page', 'document', 'folder', 'root', 'dir', 'doc', 'img', 'filename'], paths: ['/view', '/download', '/render', '/read', '/include'], methods: ['GET', 'POST'] },
    idor: { params: ['id', 'user_id', 'account_id', 'order_id', 'uid', 'pid', 'profile_id', 'doc_id', 'invoice_id', 'record_id'], methods: ['GET', 'PUT', 'DELETE'] },
    rce: { params: ['cmd', 'exec', 'command', 'run', 'execute', 'ping', 'func', 'module', 'load', 'process', 'shell', 'code', 'eval', 'ip', 'host', 'daemon'], methods: ['GET', 'POST'] },
    ssrf: { params: ['url', 'uri', 'link', 'src', 'target', 'dest', 'source', 'callback', 'webhook', 'redirect', 'to', 'out', 'view', 'dir', 'path', 'domain', 'host', 'port', 'feed', 'validate', 'val', 'proxy', 'site', 'img_url', 'image_url'], methods: ['GET', 'POST'] },
    auth: { paths: ['/admin', '/auth', '/login', '/account', '/internal', '/dashboard', '/manage', '/settings'], methods: ['PUT', 'DELETE'], params: ['lostpassword', 'recover', 'reset', 'reset_password', 'forgot', 'password_reset'] }
  }
};

// ── Detection functions ──
function isInteresting(details) {
  const urlLower = (details.url || '').toLowerCase();
  const type = details.type || '';
  if (CONFIG.IGNORED_EXTENSIONS.some(ext => urlLower.includes(ext))) return false;
  if (urlLower.includes('.php')) return true;
  if (type === 'xmlhttprequest' || type === 'fetch') return true;
  if (urlLower.includes('.css') && type !== 'xmlhttprequest') return false;
  if (urlLower.includes('.js') && (type === 'xmlhttprequest' || urlLower.includes('config') || urlLower.includes('api') || urlLower.includes('admin'))) return true;
  if (urlLower.includes('/api/') || urlLower.includes('/graphql') || urlLower.includes('/rest/')) return true;
  if (urlLower.includes('?')) return true;

  try {
    const parsed = new URL(details.url);
    if (parsed.pathname.split('/').some(segment => segment.includes('=') && !segment.startsWith('='))) {
      return true;
    }
  } catch (e) {}

  return false;
}

function isSensitiveEndpoint(url, method, params) {
  let urlObj;
  try { urlObj = new URL(url); } catch { return false; }
  const path = urlObj.pathname.toLowerCase();
  if (CONFIG.SENSITIVE_METHODS.includes(method)) return true;
  if (CONFIG.SENSITIVE_PATHS.some(p => path.includes(p))) return true;
  if ((params || []).some(p => CONFIG.SENSITIVE_PARAMS.includes(String(p).toLowerCase()))) return true;
  return false;
}

function detectTags(url, method, params = [], status = 0, responseHeaders = []) {
  let urlObj;
  try { urlObj = new URL(url); } catch { return {}; }
  const path = urlObj.pathname.toLowerCase();
  const lowerParams = (params || []).map(p => String(p || '').toLowerCase());
  const getHeader = (name) => {
    if (!responseHeaders || !Array.isArray(responseHeaders)) return '';
    const h = responseHeaders.find(x => x.name && x.name.toLowerCase() === name.toLowerCase());
    return h ? (h.value || '').toLowerCase() : '';
  };
  const contentType = getHeader('content-type');
  const R = CONFIG.TAG_RULES;

  const xssDetected = R.xss.methods.includes(method) && lowerParams.some(p => R.xss.params.map(x => x.toLowerCase()).includes(p));
  const sqliDetected = R.sqli.methods.includes(method) && lowerParams.some(p => R.sqli.params.map(x => x.toLowerCase()).includes(p));
  const lfiDetected = R.lfi.methods.includes(method) && (lowerParams.some(p => R.lfi.params.map(x => x.toLowerCase()).includes(p)) || R.lfi.paths.some(p => path.includes(p)));
  const idorDetected = R.idor.methods.includes(method) && (lowerParams.some(p => R.idor.params.map(x => x.toLowerCase()).includes(p)) || /\/\d+/.test(path));
  const rceDetected = R.rce.methods.includes(method) && lowerParams.some(p => R.rce.params.map(x => x.toLowerCase()).includes(p));
  const ssrfDetected = R.ssrf.methods.includes(method) && lowerParams.some(p => R.ssrf.params.map(x => x.toLowerCase()).includes(p));
  const authDetected = R.auth.paths.some(p => path.includes(p)) || R.auth.methods.includes(method) || lowerParams.some(p => R.auth.params.map(x => x.toLowerCase()).includes(p)) || status === 403 || status === 401;

  return { xss: !!xssDetected, sqli: !!sqliDetected, lfi: !!lfiDetected, idor: !!idorDetected, rce: !!rceDetected, ssrf: !!ssrfDetected, auth: !!authDetected };
}

// ── Endpoint persistence ──
function saveEndpoints() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    browser.storage.local.set({
      endpoints: Array.from(endpoints.values()),
      dynamicPatterns: Array.from(dynamicPatterns.entries()),
      lastUpdate: Date.now()
    });
  }, 400);
}

// Load persisted endpoints
// Clear endpoints on start/close per user request
function clearEndpointsStorage() {
  endpoints.clear();
  dynamicPatterns.clear();
  try { browser.storage.local.remove(['endpoints', 'dynamicPatterns', 'lastUpdate']); } catch (e) {}
}

// Run immediately on load so previous sessions are not restored
clearEndpointsStorage();

// Also register lifecycle hooks to clear on uninstall/start/shutdown when available
try {
  if (browser.runtime && browser.runtime.onInstalled) browser.runtime.onInstalled.addListener(clearEndpointsStorage);
  if (browser.runtime && browser.runtime.onStartup) browser.runtime.onStartup.addListener(clearEndpointsStorage);
  if (browser.runtime && browser.runtime.onSuspend) browser.runtime.onSuspend.addListener(clearEndpointsStorage);
} catch (e) {}

// Still attempt to load persisted endpoints if anything remains (should be empty)
browser.storage.local.get(['endpoints', 'dynamicPatterns']).then(data => {
  if (data.endpoints) {
    endpoints = new Map(data.endpoints.map(e => [e.method + ' ' + e.url, e]));
  }
  if (data.dynamicPatterns) {
    dynamicPatterns = new Map(data.dynamicPatterns);
  }
});

// ── Request body parser ──
function parseRequestBody(requestBody) {
  if (!requestBody) return null;
  if (requestBody.raw && requestBody.raw.length > 0) {
    try {
      const decoder = new TextDecoder('utf-8');
      return requestBody.raw.map(bytes => bytes.bytes ? decoder.decode(bytes.bytes) : '').join('');
    } catch { return null; }
  }
  if (requestBody.formData) {
    const params = new URLSearchParams();
    for (const [key, values] of Object.entries(requestBody.formData)) {
      values.forEach(value => params.append(key, value));
    }
    return params.toString();
  }
  return null;
}


// ── 1. BEFORE REQUEST LISTENER ──
function handleBeforeRequest(details) {
  if (details.url.startsWith('moz-extension://') || details.url.startsWith('chrome-extension://')) return;

  if (!isTargetTab(details.tabId)) return;

  requestMap.set(details.requestId, {
    requestId: details.requestId,
    url: details.url,
    method: details.method,
    type: details.type,
    timeStamp: Date.now(),
    requestBody: parseRequestBody(details.requestBody),
    tabId: details.tabId,
    initiator: details.initiator
  });
}

// ── 2. HEADERS LISTENER ──
function handleBeforeSendHeaders(details) {
  if (!isTargetTab(details.tabId)) return;

  const tabId = normalizeTabId(details.tabId);
  const intercept = interceptState.get(tabId);
  const req = requestMap.get(details.requestId);

  if (intercept && intercept.enabled) {
    const held = {
      ...(req || {}),
      requestId: details.requestId,
      url: details.url,
      method: details.method,
      type: details.type,
      timeStamp: req?.timeStamp || Date.now(),
      requestBody: req?.requestBody || null,
      tabId,
      requestHeaders: details.requestHeaders || [],
      intercepted: true
    };

    const targetPort = getPanelPort(tabId);
    if (targetPort) {
      try {
        targetPort.postMessage({ type: 'intercepted_request', data: held });
      } catch {
        connectedPanels.delete(tabId);
      }
    }

    requestMap.delete(details.requestId);
    return { cancel: true };
  }

  if (req) {
    req.requestHeaders = details.requestHeaders;
  }
}

function handleCompleted(details) {
  if (details.url.startsWith('moz-extension://') || details.url.startsWith('chrome-extension://')) return;

  if (!isTargetTab(details.tabId)) return;

  const tabId = normalizeTabId(details.tabId);
  const req = requestMap.get(details.requestId);
  if (req) {
    req.statusCode = details.statusCode;
    req.statusLine = details.statusLine;
    req.responseHeaders = details.responseHeaders;

    const message = { type: 'captured_request', data: req };

    const targetPort = getPanelPort(tabId);
    if (targetPort) {
      try {
        targetPort.postMessage(message);
      } catch {
        connectedPanels.delete(tabId);
      }
    }
    requestMap.delete(details.requestId);
  }

  // ── Endpoint Hunter: detect and store ──
  if (!isTargetTab(details.tabId)) return;
  
  // ── Endpoint Hunter: detect and store ──
  if (!isInteresting(details)) return;
  let url;
  try { url = new URL(details.url); } catch { return; }

  const pathname = url.pathname;
  const key = `${details.method} ${url.origin}${pathname}`;
  const allParams = new Set();
  const currentParamValues = {};

  if (endpoints.has(key)) {
    endpoints.get(key).params.forEach(p => allParams.add(p));
  }
  url.searchParams.forEach((v, k) => {
    allParams.add(k);
    currentParamValues[k] = v;
  });

  // Also detect path parameters of the form /key=value when query strings are absent.
  url.pathname.split('/').forEach(segment => {
    if (!segment || !segment.includes('=')) return;
    const [keyPart, ...rest] = segment.split('=');
    const valuePart = rest.join('=');
    if (keyPart && valuePart !== undefined) {
      allParams.add(keyPart);
      if (!currentParamValues[keyPart]) {
        currentParamValues[keyPart] = valuePart;
      }
    }
  });

  if (!endpoints.has(key)) {
    const params = Array.from(allParams);
    const sensitive = isSensitiveEndpoint(url, details.method, params);
    const tags = detectTags(url.href, details.method, params, details.statusCode, details.responseHeaders);

    endpoints.set(key, {
      method: details.method,
      url: `${url.origin}${pathname}`,
      params,
      latestValues: currentParamValues,
      status: details.statusCode,
      count: 1,
      sensitive,
      tags,
      detectedAt: Date.now(),
      lastSeen: Date.now()
    });
  } else {
    const existing = endpoints.get(key);
    existing.count++;
    existing.latestValues = { ...(existing.latestValues || {}), ...currentParamValues };
    existing.lastSeen = Date.now();
    // Merge new params
    Array.from(allParams).forEach(p => {
      if (!existing.params.includes(p)) existing.params.push(p);
    });
  }
  saveEndpoints();
}

function handleErrorOccurred(details) {
  requestMap.delete(details.requestId);
}


// Register listeners
browser.webRequest.onBeforeRequest.addListener(handleBeforeRequest, { urls: ["<all_urls>"] }, ["requestBody", "blocking"]);
browser.webRequest.onBeforeSendHeaders.addListener(handleBeforeSendHeaders, { urls: ["<all_urls>"] }, ["requestHeaders", "blocking"]);
browser.webRequest.onCompleted.addListener(handleCompleted, { urls: ["<all_urls>"] }, ["responseHeaders"]);
browser.webRequest.onErrorOccurred.addListener(handleErrorOccurred, { urls: ["<all_urls>"] });

// ── Port Handshake (Ensures strict mapping) ──
browser.runtime.onConnect.addListener((port) => {
  if (port.name !== "bug-panel") return;

  port.onMessage.addListener((msg) => {
    if (msg.type === "init_panel") {
      const tabId = normalizeTabId(msg.tabId);
      if (!tabId) return;

      for (const [k, v] of connectedPanels.entries()) {
        if (v === port || k === tabId) connectedPanels.delete(k);
      }
      connectedPanels.set(tabId, port);
      try {
        port.postMessage({ type: 'panel_registered', tabId });
      } catch (e) {}
      return;
    }

    if (msg.type === 'set_intercept') {
      let tabId = normalizeTabId(msg.tabId);
      if (!tabId) {
        const matched = Array.from(connectedPanels.entries()).find(([, panelPort]) => panelPort === port);
        tabId = matched ? matched[0] : null;
      }
      if (tabId) {
        interceptState.set(tabId, {
          enabled: Boolean(msg.enabled),
          rule: msg.rule || null
        });
        try {
          port.postMessage({ type: 'intercept_state', tabId, enabled: Boolean(msg.enabled) });
        } catch (e) {}
      }
      return;
    }
  });

  port.onDisconnect.addListener(() => {
    for (const [k, v] of connectedPanels.entries()) {
      if (v === port) connectedPanels.delete(k);
    }
  });
});

// ── Message handling ──
browser.runtime.onMessage.addListener((msg) => {
  if (msg?.action === "clear-endpoints") {
    endpoints.clear();
    dynamicPatterns.clear();
    browser.storage.local.set({ endpoints: [], dynamicPatterns: [], lastUpdate: Date.now() });
  }
});

// ── Context menu for encoding tools ──
const CONTEXT_MENUS = [
  { id: "bug-base64-encode", title: "Base64 Encode" },
  { id: "bug-base64-decode", title: "Base64 Decode" },
  { id: "bug-url-encode", title: "URL Encode" },
  { id: "bug-url-decode", title: "URL Decode" },
  { id: "bug-wayback", title: "Check Wayback Machine" }
];

browser.contextMenus.removeAll().then(() => {
  browser.contextMenus.create({
    id: "bug-extension-parent",
    title: "🐛 Bug Extension",
    contexts: ["selection", "link", "page"]
  });
  CONTEXT_MENUS.forEach(item => {
    browser.contextMenus.create({
      id: item.id,
      parentId: "bug-extension-parent",
      title: item.title,
      contexts: ["selection", "link", "page"]
    });
  });
});

browser.contextMenus.onClicked.addListener((info, tab) => {
  const text = info.selectionText || info.linkUrl || info.pageUrl || '';
  let result = '';
  switch (info.menuItemId) {
    case 'bug-base64-encode':
      try { result = btoa(text); } catch { result = 'Error: invalid input'; }
      break;
    case 'bug-base64-decode':
      try { result = atob(text); } catch { result = 'Error: invalid base64'; }
      break;
    case 'bug-url-encode':
      result = encodeURIComponent(text);
      break;
    case 'bug-url-decode':
      try { result = decodeURIComponent(text); } catch { result = text; }
      break;
    case 'bug-wayback': {
      const targetUrl = info.linkUrl || info.pageUrl || text;
      const waybackUrl = `https://web.archive.org/web/*/${encodeURIComponent(targetUrl)}`;
      browser.tabs.create({ url: waybackUrl });
      return;
    }
  }
  if (result && tab?.id) {
    // Copy to clipboard via content script
    browser.tabs.executeScript(tab.id, {
      code: `
        navigator.clipboard.writeText(${JSON.stringify(result)}).then(() => {
          const toast = document.createElement('div');
          toast.textContent = 'Copied: ' + ${JSON.stringify(result.substring(0, 80))};
          toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#1a1a2e;color:#0f0;padding:12px 20px;border-radius:8px;z-index:999999;font-family:monospace;border:1px solid #0f0;box-shadow:0 4px 20px rgba(0,255,0,0.2);';
          document.body.appendChild(toast);
          setTimeout(() => toast.remove(), 3000);
        });
      `
    });
  }
});

// ── Periodic cleanup ──
setInterval(() => {
  const now = Date.now();
  for (const [id, req] of requestMap.entries()) {
    if (now - req.timeStamp > 60000) requestMap.delete(id);
  }
}, 30000);

console.log("Bug Extension background loaded.");
