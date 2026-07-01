// Shared vulnerability category detection (used by background + panel)
const TAG_DETECTION = {
  SENSITIVE_PATHS: [
    '/admin', '/api', '/auth', '/login', '/logout', '/token', '/user', '/users', '/account', '/internal', '/private', '/debug', '/phpmyadmin', '/graphql',
    '/administrador', '/iniciar-sesion', '/cuenta', '/privado', '/interno',           // ES
    '/administrateur', '/connexion', '/deconnexion', '/compte', '/prive', '/interne', // FR
    '/administrator', '/anmelden', '/abmelden', '/konto', '/privat', '/intern',       // DE
    '/guanli', '/denglu', '/tuichu', '/zhanghu', '/neibu', '/siwang',                 // CN
    '/admin', '/vhod', '/vyhod', '/akkaunt', '/vnutrenniy', '/lichnyy'                // RU
  ],
  SENSITIVE_PARAMS: [
    'token', 'auth', 'key', 'password', 'pwd', 'session', 'redirect', 'jwt', 'csrf', 'lostpassword', 'secret', 'api_key', 'apikey', 'access_token',
    'clave', 'contrasena', 'contrasenia', 'sesion', 'redirigir', 'secreto',     // ES
    'cle', 'motdepasse', 'mdp', 'session', 'redirection', 'secret',             // FR
    'schluessel', 'passwort', 'kennwort', 'sitzung', 'weiterleitung', 'geheim', // DE
    'mi-ma', 'mima', 'yaoshi', 'miyue', 'huihua', 'chongzhi',                   // CN
    'parol', 'klyuch', 'sessiya', 'sekret', 'perevod', 'sbros'                  // RU
  ],
  SENSITIVE_METHODS: ['PUT', 'DELETE', 'PATCH'],
  TAG_RULES: {
    xss: { 
      params: [
        'q', 'query', 'search', 'searchTerm', 'term', 'filter', 's', 'msg', 'comment', 'text', 'input', 'body', 'payload', 'combine', 'keys', 'name', 'title', 'content', 'value', 'data', 'html', 'url', 'redirect_uri', 'return_url', 'callback', 'next',
        // Multilingual additions
        'buscar', 'busqueda', 'texto', 'nombre', 'titulo', 'contenido', 'valor', // ES
        'recherche', 'chercher', 'mot', 'nom', 'titre', 'contenu', 'valeur',     // FR
        'suche', 'suchen', 'text', 'name', 'titel', 'inhalt', 'wert',            // DE
        'sousuo', 'chaxun', 'mingzi', 'biaoti', 'neirong', 'zhi',                // CN
        'poisk', 'zapros', 'tekst', 'imya', 'nazvanie', 'znachenie', 'dannye'    // RU
      ], 
      methods: ['GET', 'POST'] 
    },
    sqli: { 
      params: [
        'id', 'user', 'uid', 'page', 'item', 'order', 'query', 'search', 'q', 'where', 'sql', 'sort', 'column', 'table', 'field', 'category', 'cat', 'type', 'group',
        // Multilingual additions
        'usuario', 'pagina', 'articulo', 'orden', 'ordenar', 'columna', 'tabla', 'categoria',  // ES
        'utilisateur', 'page', 'article', 'ordre', 'trier', 'colonne', 'table', 'categorie',   // FR
        'benutzer', 'seite', 'artikel', 'sortieren', 'spalte', 'tabelle', 'kategorie',         // DE
        'yonghu', 'yemian', 'xiangmu', 'paixu', 'liebiao', 'fenlei',                           // CN
        'polzovatel', 'stranica', 'zapros', 'sortirovka', 'kolonka', 'tablica', 'kategoriya'   // RU
      ], 
      methods: ['GET', 'POST'] 
    },
    lfi: { 
      params: [
        'file', 'path', 'template', 'include', 'view', 'download', 'render', 'page', 'document', 'folder', 'root', 'dir', 'doc', 'img', 'filename',
        // Multilingual additions
        'archivo', 'ruta', 'plantilla', 'vista', 'descargar', 'documento', 'carpeta', 'fichero', // ES
        'fichier', 'chemin', 'modele', 'vue', 'telecharger', 'document', 'dossier',              // FR
        'datei', 'pfad', 'vorlage', 'ansicht', 'herunterladen', 'dokument', 'ordner',            // DE
        'wenjian', 'lujing', 'muban', 'chakan', 'xiazai', 'wendang',                             // CN
        'fayl', 'put', 'shablon', 'prosmotr', 'skachat', 'dokument', 'papka', 'imyafayla'        // RU
      ], 
      paths: [
        '/view', '/download', '/render', '/read', '/include',
        '/vista', '/descargar', '/leer',  // ES
        '/vue', '/telecharger', '/lire',  // FR
        '/ansicht', '/laden', '/lesen',   // DE
        '/chakan', '/xiazai',             // CN
        '/prosmotr', '/skachat', '/chitat'// RU
      ], 
      methods: ['GET', 'POST'] 
    },
    idor: { 
      params: [
        'id', 'user_id', 'account_id', 'order_id', 'uid', 'pid', 'profile_id', 'doc_id', 'invoice_id', 'record_id',
        // Multilingual additions
        'id_usuario', 'id_cuenta', 'id_pedido', 'id_factura',       // ES
        'id_utilisateur', 'id_compte', 'id_commande', 'id_facture', // FR
        'benutzer_id', 'konto_id', 'auftrag_id', 'rechnung_id',     // DE
        'yonghu_id', 'zhanghu_id', 'dingdan_id',                    // CN
        'id_polzovatelya', 'id_akkaunta', 'id_zakaza', 'id_scheta'  // RU
      ], 
      methods: ['GET', 'PUT', 'DELETE'] 
    },
    rce: { 
      params: [
        'cmd', 'exec', 'command', 'run', 'execute', 'ping', 'func', 'module', 'load', 'process', 'shell', 'code', 'eval', 'ip', 'host', 'daemon',
        // Multilingual additions
        'comando', 'ejecutar', 'cargar', 'proceso', 'codigo',    // ES
        'commande', 'executer', 'charger', 'processus', 'code',  // FR
        'befehl', 'ausfuehren', 'laden', 'prozess', 'code',      // DE
        'mingling', 'zhixing', 'jiazai', 'daima',                // CN
        'komanda', 'vypolnit', 'zapusk', 'kod', 'process'        // RU
      ], 
      methods: ['GET', 'POST'] 
    },
    ssrf: { 
      params: [
        'url', 'uri', 'link', 'src', 'target', 'dest', 'source', 'callback', 'webhook', 'redirect', 'to', 'out', 'view', 'dir', 'path', 'domain', 'host', 'port', 'feed', 'validate', 'val', 'proxy', 'site', 'img_url', 'image_url',
        // Multilingual additions
        'enlace', 'destino', 'origen', 'redirigir', 'dominio', 'puerto', 'sitio',   // ES
        'lien', 'destination', 'source', 'redirection', 'domaine', 'port', 'site',  // FR
        'link', 'ziel', 'quelle', 'weiterleitung', 'domaene', 'hafen', 'seite',     // DE
        'lianjie', 'mubiao', 'laiyuan', 'daohang', 'yuming', 'duankou', 'wangzhan', // CN
        'ssylka', 'cel', 'istochnik', 'domen', 'port', 'sayt'                       // RU
      ], 
      methods: ['GET', 'POST'] 
    },
    auth: { 
      paths: [
        '/admin', '/auth', '/login', '/account', '/internal', '/dashboard', '/manage', '/settings',
        // Multilingual additions
        '/configuracion', '/gestion', '/panel',           // ES
        '/configuration', '/gestion', '/tableau-de-bord', // FR
        '/einstellungen', '/verwaltung', '/dashboard',    // DE
        '/shezhi', '/guanli', '/mianban',                 // CN
        '/nastroyki', '/upravlenie', '/panel-upravleniya' // RU
      ], 
      methods: ['PUT', 'DELETE'], 
      params: [
        'lostpassword', 'recover', 'reset', 'reset_password', 'forgot', 'password_reset',
        // Multilingual additions
        'recuperar', 'restablecer', 'olvido', 'cambiar_contrasena', // ES
        'recuperer', 'reinitialiser', 'oublie', 'changement_mdp',   // FR
        'wiederherstellen', 'zuruecksetzen', 'vergessen',           // DE
        'zhaohui', 'chongzhi', 'wangji',                            // CN
        'vosstanovit', 'sbros', 'zabyl', 'sbros_parolya'            // RU
      ] 
    }
  },
  TAG_ICONS: {
    xss: '🎨',
    sqli: '🗄️',
    lfi: '📂',
    idor: '🔑',
    rce: '⚡',
    ssrf: '🌐',
    auth: '🔐',
    sensitive: '⚠️'
  }
};

function extractParamsFromUrl(urlStr) {
  const params = new Set();
  try {
    const url = new URL(urlStr);
    url.searchParams.forEach((_v, k) => params.add(k));
    url.pathname.split('/').forEach(segment => {
      if (!segment || !segment.includes('=')) return;
      const [keyPart] = segment.split('=');
      if (keyPart) params.add(keyPart);
    });
  } catch (e) {}
  return Array.from(params);
}

function extractParamsFromBody(body) {
  const params = new Set();
  if (!body || typeof body !== 'string') return [];
  const trimmed = body.trim();
  if (!trimmed) return [];

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        Object.keys(parsed).forEach(k => params.add(k));
      }
    } catch (e) {}
  }

  if (trimmed.includes('=')) {
    try {
      new URLSearchParams(trimmed).forEach((_v, k) => params.add(k));
    } catch (e) {}
  }

  return Array.from(params);
}

function extractRequestParams(urlStr, body) {
  const all = new Set([
    ...extractParamsFromUrl(urlStr),
    ...extractParamsFromBody(body)
  ]);
  return Array.from(all);
}

function isSensitiveEndpoint(url, method, params) {
  let urlObj;
  try { urlObj = new URL(url); } catch { return false; }
  const path = urlObj.pathname.toLowerCase();
  const upperMethod = (method || 'GET').toUpperCase();
  if (TAG_DETECTION.SENSITIVE_METHODS.includes(upperMethod)) return true;
  if (TAG_DETECTION.SENSITIVE_PATHS.some(p => path.includes(p))) return true;
  if ((params || []).some(p => TAG_DETECTION.SENSITIVE_PARAMS.includes(String(p).toLowerCase()))) return true;
  return false;
}

function detectTags(url, method, params = [], status = 0, responseHeaders = []) {
  let urlObj;
  try { urlObj = new URL(url); } catch { return {}; }
  const path = urlObj.pathname.toLowerCase();
  const upperMethod = (method || 'GET').toUpperCase();
  const lowerParams = (params || []).map(p => String(p || '').toLowerCase());
  const getHeader = (name) => {
    if (!responseHeaders || !Array.isArray(responseHeaders)) return '';
    const h = responseHeaders.find(x => x.name && x.name.toLowerCase() === name.toLowerCase());
    return h ? (h.value || '').toLowerCase() : '';
  };
  const contentType = getHeader('content-type');
  const R = TAG_DETECTION.TAG_RULES;

  const xssDetected = R.xss.methods.includes(upperMethod) && lowerParams.some(p => R.xss.params.map(x => x.toLowerCase()).includes(p));
  const sqliDetected = R.sqli.methods.includes(upperMethod) && lowerParams.some(p => R.sqli.params.map(x => x.toLowerCase()).includes(p));
  const lfiDetected = R.lfi.methods.includes(upperMethod) && (lowerParams.some(p => R.lfi.params.map(x => x.toLowerCase()).includes(p)) || R.lfi.paths.some(p => path.includes(p)));
  const idorDetected = R.idor.methods.includes(upperMethod) && (lowerParams.some(p => R.idor.params.map(x => x.toLowerCase()).includes(p)) || /\/\d+/.test(path));
  const rceDetected = R.rce.methods.includes(upperMethod) && lowerParams.some(p => R.rce.params.map(x => x.toLowerCase()).includes(p));
  const ssrfDetected = R.ssrf.methods.includes(upperMethod) && lowerParams.some(p => R.ssrf.params.map(x => x.toLowerCase()).includes(p));
  const authDetected = R.auth.paths.some(p => path.includes(p)) || R.auth.methods.includes(upperMethod) || lowerParams.some(p => R.auth.params.map(x => x.toLowerCase()).includes(p)) || status === 403 || status === 401;

  return { xss: !!xssDetected, sqli: !!sqliDetected, lfi: !!lfiDetected, idor: !!idorDetected, rce: !!rceDetected, ssrf: !!ssrfDetected, auth: !!authDetected };
}

function getRequestFindingsFromData(url, method, body, statusCode, responseHeaders) {
  const params = extractRequestParams(url, body);
  const tags = detectTags(url, method, params, statusCode || 0, responseHeaders || []);
  const findings = [];
  if (isSensitiveEndpoint(url, method, params)) findings.push('sensitive');
  Object.entries(tags).forEach(([tag, value]) => {
    if (value) findings.push(tag);
  });
  return findings;
}
