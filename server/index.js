import express from "express";
import { Client } from "ldapts";
import crypto from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = Number(process.env.PORT ?? 3000);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
const legacyEncryptionSecret = "nexus-cmdb-local-dev-change-this-64-char-secret-before-prod";
const encryptionSecret = process.env.APP_ENCRYPTION_KEY || legacyEncryptionSecret;
const encryptionKey = deriveEncryptionKey(encryptionSecret);
const previousEncryptionKeys = [process.env.APP_ENCRYPTION_KEY_PREVIOUS, legacyEncryptionSecret]
  .filter((secret) => secret && secret !== encryptionSecret)
  .map(deriveEncryptionKey);
const SYNC_BATCH_SIZE = Number(process.env.SYNC_BATCH_SIZE || 50);
const JIRA_RETRY_ATTEMPTS = Number(process.env.JIRA_RETRY_ATTEMPTS || 3);
const JIRA_REQUEST_TIMEOUT_MS = Number(process.env.JIRA_REQUEST_TIMEOUT_MS || 20000);
const MAPPING_SCHEDULER_INTERVAL_MS = Number(process.env.MAPPING_SCHEDULER_INTERVAL_MS || 60_000);
const syncJobs = new Map();
const scheduledSyncs = new Set();
const syncContextStorage = new AsyncLocalStorage();
const allowedStateKeys = new Set(["config", "mappings", "logs"]);
const defaultBranding = { logoDataUrl: "", faviconDataUrl: "", appTitle: "Nexus CMDB" };
const pngDataUrlPattern = /^data:image\/png;base64,[A-Za-z0-9+/=]+$/;
const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const csrfHeaderName = "x-nexus-cmdb-request";
const sessionCookieName = "nexus_cmdb_session";
const SESSION_DURATION_MS = Number(process.env.SESSION_DURATION_MS || 8 * 60 * 60 * 1000);
const PASSWORD_HISTORY_LIMIT = 5;
const SCRYPT_LEGACY_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const SCRYPT_CURRENT_PARAMS = {
  N: Number(process.env.PASSWORD_SCRYPT_N || 131072),
  r: Number(process.env.PASSWORD_SCRYPT_R || 8),
  p: Number(process.env.PASSWORD_SCRYPT_P || 1),
  maxmem: Number(process.env.PASSWORD_SCRYPT_MAXMEM || 256 * 1024 * 1024),
};
const rateLimitBuckets = new Map();
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX_REQUESTS || 240);
const authFailureBuckets = new Map();
const AUTH_FAILURE_WINDOW_MS = Number(process.env.AUTH_FAILURE_WINDOW_MS || 15 * 60 * 1000);
const AUTH_FAILURE_MAX_ATTEMPTS = Number(process.env.AUTH_FAILURE_MAX_ATTEMPTS || 8);
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateLimitBuckets.entries()) {
    if (now > bucket.resetAt) rateLimitBuckets.delete(key);
  }
  for (const [key, bucket] of authFailureBuckets.entries()) {
    if (now > bucket.resetAt) authFailureBuckets.delete(key);
  }
}, RATE_LIMIT_WINDOW_MS).unref?.();

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(applySecurityHeaders);
app.use(rateLimitRequests);
app.use(validateRequestOrigin);
app.use(requireJsonContentType);
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || "2mb", strict: true }));
app.use(requireCsrfHeader);

function applySecurityHeaders(_req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "style-src 'self'",
    "script-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
  ].join("; "));
  if (process.env.ENABLE_HSTS === "true") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
}

function rateLimitRequests(req, res, next) {
  const now = Date.now();
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const bucket = rateLimitBuckets.get(ip) ?? { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }
  bucket.count += 1;
  rateLimitBuckets.set(ip, bucket);
  if (bucket.count > RATE_LIMIT_MAX_REQUESTS) {
    res.setHeader("Retry-After", String(Math.ceil((bucket.resetAt - now) / 1000)));
    res.status(429).json({ error: "rate_limited", detail: "Demasiadas peticiones. Espera unos segundos antes de continuar." });
    return;
  }
  next();
}

function validateRequestOrigin(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    next();
    return;
  }
  const origin = req.get("origin");
  if (!origin) {
    next();
    return;
  }
  const expectedOrigins = getExpectedOrigins(req);
  if (!expectedOrigins.has(origin)) {
    res.status(403).json({ error: "invalid_origin", detail: "Origen de peticion no permitido." });
    return;
  }
  next();
}

function getExpectedOrigins(req) {
  const origins = new Set();
  const protocols = [req.protocol, req.get("x-forwarded-proto")].filter(Boolean);
  const hosts = [req.get("host"), req.get("x-forwarded-host")].filter(Boolean);
  for (const protocol of protocols) {
    for (const host of hosts) {
      origins.add(`${protocol}://${host}`);
    }
  }
  return origins;
}

function requireJsonContentType(req, res, next) {
  const contentLength = Number(req.headers["content-length"] ?? 0);
  const hasBody = contentLength > 0 || req.headers["transfer-encoding"];
  if (hasBody && ["POST", "PUT", "PATCH"].includes(req.method) && req.path.startsWith("/api/") && !req.is("application/json")) {
    res.status(415).json({ error: "unsupported_media_type", detail: "Las peticiones API con cuerpo deben usar Content-Type application/json." });
    return;
  }
  next();
}

function requireCsrfHeader(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method) || !req.path.startsWith("/api/")) {
    next();
    return;
  }
  if (req.get(csrfHeaderName) !== "same-origin") {
    res.status(403).json({ error: "csrf_header_missing", detail: "Cabecera de proteccion CSRF no presente." });
    return;
  }
  next();
}

async function initDb() {
  reportSecurityConfiguration();
  await createDatabaseSchema();
  await pruneExpiredSessions();
  await migrateStoredAdPassword();
  await migrateStoredNutanixPassword();
  await migrateStoredJiraToken();
  await migrateStoredEncryptedSecrets();
  await migrateObsoleteStoredState();
}

async function createDatabaseSchema() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_users (
        id UUID PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        password_expires_at TIMESTAMPTZ,
        expiration_policy TEXT NOT NULL DEFAULT 'never',
        role TEXT NOT NULL DEFAULT 'admin',
        active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_password_history (
        id BIGSERIAL PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_sessions (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_app_sessions_user_id ON app_sessions(user_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_app_sessions_expires_at ON app_sessions(expires_at);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_app_password_history_user_created ON app_password_history(user_id, created_at DESC, id DESC);");
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function pruneExpiredSessions() {
  await pool.query("DELETE FROM app_sessions WHERE expires_at <= now()");
}

function reportSecurityConfiguration() {
  if (!process.env.APP_ENCRYPTION_KEY || process.env.APP_ENCRYPTION_KEY.includes("change-this") || process.env.APP_ENCRYPTION_KEY.length < 32) {
    console.warn("Security warning: APP_ENCRYPTION_KEY debe ser unico, secreto y de al menos 32 caracteres antes de usar produccion.");
    if (process.env.NODE_ENV === "production" && process.env.REQUIRE_STRONG_SECRETS !== "false") {
      throw new Error("APP_ENCRYPTION_KEY insegura en produccion. Define una clave aleatoria estable de al menos 32 caracteres.");
    }
  }
  if (process.env.LDAP_TLS_REJECT_UNAUTHORIZED === "false") {
    console.warn("Security warning: LDAP_TLS_REJECT_UNAUTHORIZED=false desactiva la validacion TLS de LDAPS. Usalo solo en laboratorio.");
  }
  if (SCRYPT_CURRENT_PARAMS.N < 131072 || SCRYPT_CURRENT_PARAMS.r < 8 || SCRYPT_CURRENT_PARAMS.p < 1) {
    console.warn("Security warning: PASSWORD_SCRYPT_* esta por debajo del minimo OWASP recomendado para scrypt.");
  }
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch (error) {
    res.status(503).json({ status: "error", detail: error.message });
  }
});

app.get("/api/auth/status", async (req, res) => {
  const setupRequired = await isSetupRequired();
  const user = setupRequired ? null : await getRequestUser(req);
  res.json({ setupRequired, authenticated: Boolean(user), user: user ? publicUser(user) : null });
});

app.post("/api/auth/setup", async (req, res) => {
  if (isAuthTemporarilyBlocked(req)) {
    res.status(429).json({ error: "auth_rate_limited", detail: "Demasiados intentos. Espera unos minutos antes de continuar." });
    return;
  }
  if (!(await isSetupRequired())) {
    res.status(409).json({ error: "setup_completed", detail: "La aplicacion ya tiene usuarios configurados." });
    return;
  }
  try {
    const { email, password, expirationPolicy = "never" } = req.body ?? {};
    const user = await createLocalUser({ email, password, expirationPolicy, role: "admin" });
    clearAuthFailures(req);
    await createSessionResponse({ req, res, user });
  } catch (error) {
    registerAuthFailure(req);
    res.status(400).json({ error: "setup_failed", detail: error instanceof Error ? error.message : "No se pudo crear el usuario inicial." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  if (isAuthTemporarilyBlocked(req)) {
    res.status(429).json({ error: "auth_rate_limited", detail: "Demasiados intentos de acceso. Espera unos minutos antes de continuar." });
    return;
  }
  try {
    const { email, password } = req.body ?? {};
    const user = await authenticateLocalUser({ email, password });
    clearAuthFailures(req);
    await createSessionResponse({ req, res, user });
  } catch (error) {
    registerAuthFailure(req);
    res.status(401).json({ error: "login_failed", detail: error instanceof Error ? error.message : "Credenciales no validas." });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  const token = getSessionToken(req);
  if (token) {
    await pool.query("DELETE FROM app_sessions WHERE token_hash = $1", [hashSessionToken(token)]);
  }
  clearSessionCookie(res);
  res.json({ status: "ok" });
});

app.get("/api/public/branding", async (_req, res) => {
  try {
    const branding = await readBranding();
    res.json(branding);
  } catch (error) {
    res.status(500).json({ error: "branding_read_failed", detail: error instanceof Error ? error.message : "No se pudo leer la marca de la aplicacion." });
  }
});

app.use("/api", requireAuthenticatedUser);

app.get("/api/auth/me", (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.put("/api/settings/branding", requireAdminUser, async (req, res) => {
  try {
    const branding = normalizeBranding(req.body?.value ?? req.body);
    const validation = validateBranding(branding);
    if (validation) {
      res.status(400).json({ error: "invalid_branding", detail: validation });
      return;
    }
    await writeState("branding", branding);
    res.json({ value: branding });
  } catch (error) {
    res.status(500).json({ error: "branding_save_failed", detail: error instanceof Error ? error.message : "No se pudo guardar la marca de la aplicacion." });
  }
});

app.get("/api/admin/users", requireAdminUser, async (_req, res) => {
  const result = await pool.query(`
    SELECT id, email, role, active, expiration_policy, password_changed_at, password_expires_at, created_at, updated_at
    FROM app_users
    ORDER BY email ASC
  `);
  res.json({ users: result.rows.map(publicUser) });
});

app.post("/api/admin/users", requireAdminUser, async (req, res) => {
  try {
    const { email, password, expirationPolicy = "never", active = true } = req.body ?? {};
    const user = await createLocalUser({ email, password, expirationPolicy, role: "admin", active });
    res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    res.status(400).json({ error: "user_create_failed", detail: error instanceof Error ? error.message : "No se pudo crear el usuario." });
  }
});

app.put("/api/admin/users/:id", requireAdminUser, async (req, res) => {
  try {
    const user = await updateLocalUser({ id: req.params.id, patch: req.body ?? {}, actorId: req.user.id });
    res.json({ user: publicUser(user) });
  } catch (error) {
    res.status(400).json({ error: "user_update_failed", detail: error instanceof Error ? error.message : "No se pudo actualizar el usuario." });
  }
});

app.post("/api/ad/test", async (req, res) => {
  const storedConfig = await readState("config");
  const storedAd = storedConfig?.ad ?? {};
  const { domain = storedAd.domain, url = storedAd.url, bindUser = storedAd.bindUser, bindPassword } = req.body ?? {};
  const storedPassword = decryptSecret(storedAd.bindPasswordEncrypted);
  const password = bindPassword || storedPassword || process.env.AD_BIND_PASSWORD;

  if (!domain || !url || !bindUser) {
    res.status(400).json({ error: "missing_fields", detail: "Dominio, URL LDAPS y usuario bind son obligatorios." });
    return;
  }

  if (!password) {
    res.status(400).json({ error: "missing_password", detail: "Indica Password bind o configura AD_BIND_PASSWORD en el contenedor app." });
    return;
  }

  try {
    validateLdapConnectionUrl(url);
  } catch (error) {
    res.status(400).json({ error: "invalid_ad_url", detail: error instanceof Error ? error.message : "URL LDAP no valida." });
    return;
  }

  const tcp = await testTcpConnectivity(url);
  if (!tcp.ok) {
    res.status(502).json({
      error: "ad_tcp_failed",
      detail: `${tcp.detail}. Verifica que el contenedor app puede resolver y alcanzar el controlador de dominio desde Docker.`,
      diagnostic: tcp,
    });
    return;
  }

  const client = new Client({
    url,
    timeout: 15000,
    connectTimeout: 10000,
    tlsOptions: {
      rejectUnauthorized: process.env.LDAP_TLS_REJECT_UNAUTHORIZED !== "false",
    },
  });

  try {
    const baseDn = domainToBaseDn(domain);
    await client.bind(bindUser, password);
    if (bindPassword) {
      await saveEncryptedAdPassword({ domain, url, bindUser, password: bindPassword });
    }
    const { searchEntries } = await client.search(baseDn, {
      scope: "sub",
      filter: "(objectClass=organizationalUnit)",
      attributes: ["distinguishedName", "ou", "name"],
      sizeLimit: 5000,
    });

    const ouDns = searchEntries
      .map((entry) => String(entry.distinguishedName || entry.dn || ""))
      .filter(Boolean);

    res.json({
      status: "ok",
      tree: buildOuTree(domain, baseDn, ouDns),
      organizationalUnits: ouDns.length,
      diagnostic: tcp,
    });
  } catch (error) {
    console.error("Active Directory test failed:", sanitizeLdapError(error));
    res.status(502).json({
      error: "ad_connection_failed",
      detail: explainLdapError(error, url),
    });
  } finally {
    await client.unbind().catch(() => undefined);
  }
});

app.post("/api/jira/test", async (req, res) => {
  const storedConfig = await readState("config");
  const storedJira = storedConfig?.jira ?? {};
  const {
    url = storedJira.url,
    cloudId = storedJira.cloudId,
    workspaceId = storedJira.workspaceId,
    email = storedJira.email,
    apiToken,
  } = req.body ?? {};
  const storedToken = decryptSecret(storedJira.apiTokenEncrypted);
  const token = apiToken || storedToken || process.env.JIRA_API_TOKEN;

  if (!url || !cloudId || !workspaceId || !email) {
    res.status(400).json({ error: "missing_fields", detail: "URL Jira, Cloud ID, Workspace ID y Correo API son obligatorios." });
    return;
  }

  if (!token) {
    res.status(400).json({ error: "missing_token", detail: "Indica el API token de Jira Assets o guarda uno previamente cifrado." });
    return;
  }

  try {
    const diagnostics = await validateJiraAssetsConnectionInputs({ url, cloudId, workspaceId, email, token });
    const schemas = await fetchJiraAssetsSchemas({ cloudId, workspaceId, email, token });
    await saveJiraAssetsCatalog({ url, cloudId, workspaceId, email, token: apiToken, schemas });
    res.json({ status: "ok", schemas, diagnostics, hasApiToken: Boolean(apiToken || storedToken) });
  } catch (error) {
    console.error("Jira Assets test failed:", sanitizeLdapError(error));
    res.status(502).json({
      error: "jira_connection_failed",
      detail: error instanceof Error ? error.message : "Error al conectar con Jira Assets.",
    });
  }
});

app.post("/api/nutanix/test", async (req, res) => {
  const storedConfig = await readState("config");
  const storedNutanix = storedConfig?.nutanix ?? {};
  const {
    prismUrl = storedNutanix.prismUrl,
    username = storedNutanix.username,
    password,
  } = req.body ?? {};
  const storedPassword = decryptSecret(storedNutanix.passwordEncrypted);
  const effectivePassword = password || storedPassword;

  if (!prismUrl || !username) {
    res.status(400).json({ error: "missing_fields", detail: "Prism Central y usuario son obligatorios." });
    return;
  }
  if (!effectivePassword) {
    res.status(400).json({ error: "missing_password", detail: "Indica la contrasena de Nutanix o guarda una previamente cifrada." });
    return;
  }

  try {
    const result = await testNutanixConnection({ prismUrl, username, password: effectivePassword });
    await saveEncryptedNutanixPassword({ prismUrl, username, password, clusters: result.clusters });
    res.json({ status: "ok", endpoint: result.endpoint, clusters: result.clusters });
  } catch (error) {
    console.error("Nutanix test failed:", sanitizeLdapError(error));
    res.status(502).json({
      error: "nutanix_connection_failed",
      detail: error instanceof Error ? error.message : "Error al conectar con Nutanix Prism Central.",
    });
  }
});

app.post("/api/sync/run", async (req, res) => {
  const mapping = req.body?.mapping;
  if (!mapping?.id || !mapping?.source || !mapping?.jiraSchema || !mapping?.objectType || !Array.isArray(mapping.fields)) {
    res.status(400).json({ error: "invalid_mapping", detail: "Mapeo invalido o incompleto." });
    return;
  }

  const config = await readState("config");
  const jira = config?.jira ?? {};
  const token = decryptSecret(jira.apiTokenEncrypted) || process.env.JIRA_API_TOKEN;
  if (!jira.cloudId || !jira.workspaceId || !jira.email || !token) {
    res.status(400).json({ error: "jira_not_configured", detail: "Configura y prueba Jira Assets antes de sincronizar." });
    return;
  }

  try {
    if (!["AD", "Nutanix"].includes(mapping.source)) throw new Error(`Origen no soportado: ${mapping.source}.`);
    const job = createSyncJob(mapping);
    res.status(202).json(getPublicSyncJob(job));
    setImmediate(async () => {
      syncContextStorage.run({ signal: job.abortController.signal, jobId: job.id }, async () => {
        try {
          updateSyncJob(job.id, {
            changes: [
              ...job.changes,
              { object: mapping.objectType, action: "Ejecutando", detail: `Trabajo iniciado en backend. Validando destino Jira Assets y preparando lectura de ${mapping.source}.` },
            ],
          });
          const runner = mapping.source === "Nutanix" ? runNutanixMappingSync : runAdMappingSync;
          let lastPersistedProgressAt = 0;
          const result = await runner({
            config,
            mapping,
            jira,
            token,
            isCancelled: () => Boolean(syncJobs.get(job.id)?.cancelRequested),
            onProgress: (progress) => {
              updateSyncJob(job.id, progress);
              const now = Date.now();
              if (now - lastPersistedProgressAt < 10_000) return;
              lastPersistedProgressAt = now;
              void upsertStoredSyncLog({
                id: job.id,
                mappingName: mapping.name,
                startedAt: job.startedAt,
                status: progress.status ?? "Ejecutando",
                created: progress.created ?? 0,
                updated: progress.updated ?? 0,
                unchanged: progress.unchanged ?? 0,
                errors: progress.errors ?? 0,
                changes: progress.changes ?? [],
              }).catch((persistError) => {
                console.warn("Could not persist manual sync progress:", persistError instanceof Error ? persistError.message : persistError);
              });
            },
          });
          const finalLog = {
            ...result,
            id: job.id,
            startedAt: job.startedAt,
          };
          await upsertStoredSyncLog(finalLog);
          await updateStoredMappingStatus(mapping.id, { lastSync: finalLog.startedAt, status: finalLog.status });
          updateSyncJob(job.id, { ...finalLog, done: true });
        } catch (error) {
          console.error("Mapping sync failed:", sanitizeLdapError(error));
          const failedLog = {
            id: job.id,
            mappingName: mapping.name,
            startedAt: job.startedAt,
            status: "Error",
            created: syncJobs.get(job.id)?.created ?? 0,
            updated: syncJobs.get(job.id)?.updated ?? 0,
            unchanged: syncJobs.get(job.id)?.unchanged ?? 0,
            errors: (syncJobs.get(job.id)?.errors ?? 0) + 1,
            changes: [
              ...(syncJobs.get(job.id)?.changes ?? []),
              { object: mapping.objectType, action: "Error", detail: error instanceof Error ? error.message : "Error al ejecutar la sincronizacion." },
            ],
          };
          await upsertStoredSyncLog(failedLog).catch((persistError) => {
            console.warn("Could not persist failed manual sync log:", persistError instanceof Error ? persistError.message : persistError);
          });
          await updateStoredMappingStatus(mapping.id, { lastSync: failedLog.startedAt, status: "Error" }).catch((persistError) => {
            console.warn("Could not persist failed manual sync mapping status:", persistError instanceof Error ? persistError.message : persistError);
          });
          updateSyncJob(job.id, {
            ...failedLog,
            done: true,
          });
        }
        });
    });
  } catch (error) {
    console.error("Mapping sync failed:", sanitizeLdapError(error));
    res.status(502).json({
      error: "sync_failed",
      detail: error instanceof Error ? error.message : "Error al ejecutar la sincronizacion.",
    });
  }
});

app.get("/api/sync/jobs/:id", (req, res) => {
  const job = syncJobs.get(req.params.id);
  if (!job) {
    res.status(404).json({ error: "sync_job_not_found", detail: "No se encontro la sincronizacion solicitada. Puede que el servidor se haya reiniciado." });
    return;
  }
  res.json(getPublicSyncJob(job));
});

app.post("/api/sync/jobs/:id/cancel", (req, res) => {
  const job = syncJobs.get(req.params.id);
  if (!job) {
    res.status(404).json({ error: "sync_job_not_found", detail: "No se encontro la sincronizacion solicitada. Puede que ya haya terminado o el servidor se haya reiniciado." });
    return;
  }
  if (job.done) {
    res.json(getPublicSyncJob(job));
    return;
  }
  const changes = [
    ...job.changes,
    { object: job.mappingName, action: "Cancelado", detail: "Cancelacion solicitada por el usuario. Se abortara la llamada Jira activa y la sincronizacion se detendra." },
  ];
  job.abortController?.abort();
  updateSyncJob(job.id, { cancelRequested: true, changes });
  res.json(getPublicSyncJob(syncJobs.get(job.id)));
});

function createSyncJob(mapping) {
  const job = {
    id: crypto.randomUUID(),
    mappingId: mapping.id,
    mappingName: mapping.name,
    startedAt: formatServerDate(new Date()),
    status: "Ejecutando",
    created: 0,
    updated: 0,
    unchanged: 0,
    errors: 0,
    done: false,
    cancelRequested: false,
    abortController: new AbortController(),
    changes: [{ object: mapping.objectType, action: "Ejecutando", detail: "Sincronizacion en cola. Preparando conexion con AD y Jira Assets." }],
  };
  syncJobs.set(job.id, job);
  return job;
}

function updateSyncJob(id, patch) {
  const current = syncJobs.get(id);
  if (!current) return;
  const next = {
    ...current,
    ...patch,
    id: current.id,
    changes: patch.changes ?? current.changes,
  };
  syncJobs.set(id, next);
  if (next.done) {
    setTimeout(() => syncJobs.delete(id), 60 * 60 * 1000).unref?.();
  }
}

function getPublicSyncJob(job) {
  return {
    id: job.id,
    mappingId: job.mappingId,
    mappingName: job.mappingName,
    startedAt: job.startedAt,
    status: job.status,
    created: job.created,
    updated: job.updated,
    unchanged: job.unchanged,
    errors: job.errors,
    changes: job.changes,
    done: Boolean(job.done),
    cancelRequested: Boolean(job.cancelRequested),
  };
}

app.get("/api/data/:key", async (req, res) => {
  if (!allowedStateKeys.has(req.params.key)) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  const value = await readState(req.params.key);
  if (!value) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  res.json(sanitizeForClient(req.params.key, value));
});

app.put("/api/data/:key", async (req, res) => {
  if (!allowedStateKeys.has(req.params.key)) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  await writeState(req.params.key, await sanitizeForStorage(req.params.key, req.body));
  res.json({ status: "saved" });
});

async function isSetupRequired() {
  const result = await pool.query("SELECT 1 FROM app_users LIMIT 1");
  return result.rowCount === 0;
}

async function getRequestUser(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  const result = await pool.query(
    `
      SELECT u.id, u.email, u.role, u.active, u.expiration_policy, u.password_changed_at, u.password_expires_at, u.created_at, u.updated_at
      FROM app_sessions s
      JOIN app_users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active = true
    `,
    [hashSessionToken(token)]
  );
  return result.rows[0] ?? null;
}

async function requireAuthenticatedUser(req, res, next) {
  const user = await getRequestUser(req);
  if (!user) {
    res.status(401).json({ error: "unauthenticated", detail: "Inicia sesion para continuar." });
    return;
  }
  req.user = user;
  next();
}

function requireAdminUser(req, res, next) {
  if (req.user?.role !== "admin") {
    res.status(403).json({ error: "forbidden", detail: "No tienes permisos para administrar usuarios." });
    return;
  }
  next();
}

async function createLocalUser({ email, password, expirationPolicy = "never", role = "admin", active = true }) {
  const normalizedEmail = normalizeEmail(email);
  validateEmail(normalizedEmail);
  validatePasswordPolicy(password);
  validateExpirationPolicy(expirationPolicy);
  const { salt, hash } = await hashPassword(password);
  const id = crypto.randomUUID();
  const expiresAt = getPasswordExpiresAt(expirationPolicy);
  const result = await pool.query(
    `
      INSERT INTO app_users (id, email, password_hash, password_salt, password_expires_at, expiration_policy, role, active)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id, email, role, active, expiration_policy, password_changed_at, password_expires_at, created_at, updated_at
    `,
    [id, normalizedEmail, hash, salt, expiresAt, expirationPolicy, role, Boolean(active)]
  );
  await addPasswordHistory({ userId: id, hash, salt });
  return result.rows[0];
}

async function updateLocalUser({ id, patch, actorId }) {
  const current = await getUserWithPassword(id);
  if (!current) throw new Error("Usuario no encontrado.");
  const expirationPolicy = patch.expirationPolicy ?? current.expiration_policy;
  validateExpirationPolicy(expirationPolicy);
  const active = patch.active == null ? current.active : Boolean(patch.active);
  if (String(id) === String(actorId) && !active) {
    throw new Error("No puedes desactivar tu propio usuario.");
  }

  let passwordHash = current.password_hash;
  let passwordSalt = current.password_salt;
  let passwordChangedAtSql = "password_changed_at";
  let expiresAt = current.password_expires_at;

  if (patch.password) {
    validatePasswordPolicy(patch.password);
    await assertPasswordNotRecentlyUsed({ userId: id, password: patch.password });
    const hashed = await hashPassword(patch.password);
    passwordHash = hashed.hash;
    passwordSalt = hashed.salt;
    passwordChangedAtSql = "now()";
    expiresAt = getPasswordExpiresAt(expirationPolicy);
    await addPasswordHistory({ userId: id, hash: passwordHash, salt: passwordSalt });
  } else if (expirationPolicy !== current.expiration_policy) {
    expiresAt = getPasswordExpiresAt(expirationPolicy, new Date(current.password_changed_at));
  }

  const result = await pool.query(
    `
      UPDATE app_users
      SET password_hash = $1,
          password_salt = $2,
          password_changed_at = ${passwordChangedAtSql},
          password_expires_at = $3,
          expiration_policy = $4,
          active = $5,
          updated_at = now()
      WHERE id = $6
      RETURNING id, email, role, active, expiration_policy, password_changed_at, password_expires_at, created_at, updated_at
    `,
    [passwordHash, passwordSalt, expiresAt, expirationPolicy, active, id]
  );
  if (!active) await pool.query("DELETE FROM app_sessions WHERE user_id = $1", [id]);
  return result.rows[0];
}

async function authenticateLocalUser({ email, password }) {
  const normalizedEmail = normalizeEmail(email);
  const user = await getUserByEmailWithPassword(normalizedEmail);
  if (!user?.active || !password) throw new Error("Usuario o contrasena no validos.");
  const matches = await verifyPassword({ password, salt: user.password_salt, hash: user.password_hash });
  if (!matches) throw new Error("Usuario o contrasena no validos.");
  if (user.password_expires_at && new Date(user.password_expires_at).getTime() <= Date.now()) {
    throw new Error("La contrasena ha caducado. Un administrador debe establecer una nueva contrasena.");
  }
  return user;
}

async function getUserByEmailWithPassword(email) {
  const result = await pool.query("SELECT * FROM app_users WHERE email = $1", [email]);
  return result.rows[0] ?? null;
}

async function getUserWithPassword(id) {
  const result = await pool.query("SELECT * FROM app_users WHERE id = $1", [id]);
  return result.rows[0] ?? null;
}

async function createSessionResponse({ req, res, user }) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);
  await pool.query(
    "INSERT INTO app_sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    [crypto.randomUUID(), user.id, hashSessionToken(token), expiresAt]
  );
  setSessionCookie({ req, res, token, expiresAt });
  res.json({ user: publicUser(user) });
}

function setSessionCookie({ req, res, token, expiresAt }) {
  const secure = process.env.COOKIE_SECURE !== "false" && (process.env.COOKIE_SECURE === "true" || req.secure || req.get("x-forwarded-proto") === "https" || process.env.NODE_ENV === "production");
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  res.setHeader("Set-Cookie", `${sessionCookieName}=${token}; Path=/; Max-Age=${maxAge}; Expires=${expiresAt.toUTCString()}; HttpOnly; SameSite=Strict; Priority=High${secure ? "; Secure" : ""}`);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `${sessionCookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Priority=High`);
}

function getSessionToken(req) {
  const cookie = req.headers.cookie ?? "";
  return cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${sessionCookieName}=`))
    ?.slice(sessionCookieName.length + 1) ?? "";
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("base64url");
  const hash = await scryptPassword(password, salt, SCRYPT_CURRENT_PARAMS);
  return { salt, hash };
}

function scryptPassword(password, salt, params) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(password), salt, 64, params, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(`scrypt:v2:${params.N}:${params.r}:${params.p}:${derivedKey.toString("base64url")}`);
    });
  });
}

async function verifyPassword({ password, salt, hash }) {
  const params = getStoredPasswordParams(hash);
  const candidate = await scryptPassword(password, salt, params);
  const expected = normalizeStoredPasswordHash(hash);
  const actual = normalizeStoredPasswordHash(candidate);
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function getStoredPasswordParams(hash) {
  const parts = String(hash ?? "").split(":");
  if (parts[0] === "scrypt" && parts[1] === "v2") {
    const params = {
      N: Number(parts[2]),
      r: Number(parts[3]),
      p: Number(parts[4]),
      maxmem: SCRYPT_CURRENT_PARAMS.maxmem,
    };
    if (Number.isInteger(params.N) && Number.isInteger(params.r) && Number.isInteger(params.p)) return params;
  }
  return SCRYPT_LEGACY_PARAMS;
}

function normalizeStoredPasswordHash(hash) {
  const parts = String(hash ?? "").split(":");
  if (parts[0] === "scrypt" && parts[1] === "v2") return parts.slice(5).join(":");
  return String(hash ?? "");
}

function authRateKey(req) {
  const email = normalizeEmail(req.body?.email);
  return `${req.ip || req.socket.remoteAddress || "unknown"}:${email || "setup"}`;
}

function isAuthTemporarilyBlocked(req) {
  const bucket = authFailureBuckets.get(authRateKey(req));
  return Boolean(bucket && Date.now() <= bucket.resetAt && bucket.count >= AUTH_FAILURE_MAX_ATTEMPTS);
}

function registerAuthFailure(req) {
  const key = authRateKey(req);
  const now = Date.now();
  const bucket = authFailureBuckets.get(key) ?? { count: 0, resetAt: now + AUTH_FAILURE_WINDOW_MS };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + AUTH_FAILURE_WINDOW_MS;
  }
  bucket.count += 1;
  authFailureBuckets.set(key, bucket);
}

function clearAuthFailures(req) {
  authFailureBuckets.delete(authRateKey(req));
}

async function assertPasswordNotRecentlyUsed({ userId, password }) {
  const result = await pool.query(
    `
      SELECT password_hash, password_salt
      FROM app_password_history
      WHERE user_id = $1
      ORDER BY created_at DESC, id DESC
      LIMIT $2
    `,
    [userId, PASSWORD_HISTORY_LIMIT]
  );
  for (const previous of result.rows) {
    if (await verifyPassword({ password, salt: previous.password_salt, hash: previous.password_hash })) {
      throw new Error("No se puede reutilizar ninguna de las ultimas 5 contrasenas.");
    }
  }
}

async function addPasswordHistory({ userId, hash, salt }) {
  await pool.query("INSERT INTO app_password_history (user_id, password_hash, password_salt) VALUES ($1, $2, $3)", [userId, hash, salt]);
  await pool.query(
    `
      DELETE FROM app_password_history
      WHERE user_id = $1
        AND id NOT IN (
          SELECT id FROM app_password_history
          WHERE user_id = $1
          ORDER BY created_at DESC, id DESC
          LIMIT $2
        )
    `,
    [userId, PASSWORD_HISTORY_LIMIT]
  );
}

function normalizeEmail(value) {
  return String(value ?? "").trim().toLowerCase();
}

function validateEmail(email) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("El usuario debe ser un correo electronico valido.");
}

function validatePasswordPolicy(password) {
  const value = String(password ?? "");
  if (value.length < 12) throw new Error("La contrasena debe tener al menos 12 caracteres.");
  if (!/[a-z]/.test(value)) throw new Error("La contrasena debe incluir al menos una minuscula.");
  if (!/[A-Z]/.test(value)) throw new Error("La contrasena debe incluir al menos una mayuscula.");
  if (!/\d/.test(value)) throw new Error("La contrasena debe incluir al menos un numero.");
  if (!/[^A-Za-z0-9]/.test(value)) throw new Error("La contrasena debe incluir al menos un simbolo.");
}

function validateExpirationPolicy(policy) {
  if (!["never", "6months", "1year"].includes(policy)) throw new Error("Politica de caducidad no valida.");
}

function getPasswordExpiresAt(policy, from = new Date()) {
  if (policy === "never") return null;
  const date = new Date(from);
  date.setMonth(date.getMonth() + (policy === "6months" ? 6 : 12));
  return date;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    active: Boolean(user.active),
    expirationPolicy: user.expiration_policy,
    passwordChangedAt: user.password_changed_at,
    passwordExpiresAt: user.password_expires_at,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
  };
}

async function readState(key) {
  const result = await pool.query("SELECT value FROM app_state WHERE key = $1", [key]);
  return result.rowCount === 0 ? null : result.rows[0].value;
}

async function writeState(key, value) {
  await pool.query(
    `
      INSERT INTO app_state (key, value, updated_at)
      VALUES ($1, $2::jsonb, now())
      ON CONFLICT (key)
      DO UPDATE SET value = EXCLUDED.value, updated_at = now();
    `,
    [key, JSON.stringify(value)]
  );
}

async function readBranding() {
  return normalizeBranding(await readState("branding"));
}

function normalizeBranding(value) {
  return {
    logoDataUrl: typeof value?.logoDataUrl === "string" ? value.logoDataUrl : "",
    faviconDataUrl: typeof value?.faviconDataUrl === "string" ? value.faviconDataUrl : "",
    appTitle: typeof value?.appTitle === "string" && value.appTitle.trim()
      ? value.appTitle.trim().slice(0, 80)
      : defaultBranding.appTitle,
  };
}

function validateBranding(branding) {
  if (!branding.appTitle || branding.appTitle.length > 80) return "El nombre de la web debe tener entre 1 y 80 caracteres.";
  if (branding.logoDataUrl && !isValidPngDataUrl(branding.logoDataUrl)) return "El logotipo debe ser un fichero PNG valido.";
  if (branding.faviconDataUrl && !isValidPngDataUrl(branding.faviconDataUrl)) return "El favicon debe ser un fichero PNG valido.";
  return null;
}

function isValidPngDataUrl(dataUrl) {
  if (!pngDataUrlPattern.test(dataUrl)) return false;
  const payload = dataUrl.split(",")[1] || "";
  const bytes = Buffer.from(payload, "base64");
  return bytes.subarray(0, pngSignature.length).equals(pngSignature);
}

async function sanitizeForStorage(key, value) {
  if (key !== "config") return value;
  const previous = (await readState("config")) ?? {};
  const next = structuredClone(value);
  next.ad = next.ad ?? {};
  next.nutanix = next.nutanix ?? {};
  next.jira = next.jira ?? {};
  next.ad.enabled = {
    Usuarios: true,
    Grupos: true,
    Equipos: true,
    ...(next.ad.enabled ?? {}),
  };
  next.ad.ous = {
    Usuarios: [],
    Grupos: [],
    Equipos: [],
    ...(next.ad.ous ?? {}),
  };
  next.ad.attributes = {
    Usuarios: [],
    Grupos: [],
    Equipos: [],
    ...(next.ad.attributes ?? {}),
  };
  next.ad.domainTree = next.ad.domainTree ?? [];
  next.nutanix.selectedClusters = next.nutanix.selectedClusters ?? [];
  next.nutanix.attributes = next.nutanix.attributes ?? [];
  next.nutanix.connected = Boolean(next.nutanix.connected);
  next.jira.cloudId = next.jira.cloudId ?? "";
  next.jira.workspaceId = next.jira.workspaceId ?? "";
  next.jira.schemas = next.jira.schemas ?? [];
  next.jira.connected = Boolean(next.jira.connected);

  if (next.ad.bindPassword) {
    next.ad.bindPasswordEncrypted = encryptSecret(next.ad.bindPassword);
  } else if (previous.ad?.bindPasswordEncrypted && !next.ad.bindPasswordEncrypted) {
    next.ad.bindPasswordEncrypted = previous.ad.bindPasswordEncrypted;
  }

  if (next.nutanix.password) {
    next.nutanix.passwordEncrypted = encryptSecret(next.nutanix.password);
  } else if (previous.nutanix?.passwordEncrypted && !next.nutanix.passwordEncrypted) {
    next.nutanix.passwordEncrypted = previous.nutanix.passwordEncrypted;
  }

  if (next.jira.apiToken) {
    next.jira.apiTokenEncrypted = encryptSecret(next.jira.apiToken);
  } else if (previous.jira?.apiTokenEncrypted && !next.jira.apiTokenEncrypted) {
    next.jira.apiTokenEncrypted = previous.jira.apiTokenEncrypted;
  }

  delete next.ad.bindPassword;
  delete next.nutanix.password;
  delete next.jira.apiToken;
  delete next.jira.tokenAlias;
  return next;
}

function sanitizeForClient(key, value) {
  if (key !== "config") return value;
  const next = structuredClone(value);
  next.ad = next.ad ?? {};
  next.nutanix = next.nutanix ?? {};
  next.jira = next.jira ?? {};
  next.ad.hasBindPassword = Boolean(next.ad.bindPasswordEncrypted);
  next.nutanix.hasPassword = Boolean(next.nutanix.passwordEncrypted);
  next.jira.hasApiToken = Boolean(next.jira.apiTokenEncrypted);
  delete next.ad.bindPassword;
  delete next.ad.bindPasswordEncrypted;
  delete next.nutanix.password;
  delete next.nutanix.passwordEncrypted;
  delete next.jira.apiToken;
  delete next.jira.apiTokenEncrypted;
  delete next.jira.tokenAlias;
  return next;
}

async function migrateStoredAdPassword() {
  const config = await readState("config");
  if (!config?.ad?.bindPassword) return;
  config.ad.bindPasswordEncrypted = encryptSecret(config.ad.bindPassword);
  delete config.ad.bindPassword;
  await writeState("config", config);
}

async function migrateStoredNutanixPassword() {
  const config = await readState("config");
  if (!config?.nutanix?.password) return;
  config.nutanix.passwordEncrypted = encryptSecret(config.nutanix.password);
  delete config.nutanix.password;
  await writeState("config", config);
}

async function migrateStoredJiraToken() {
  const config = await readState("config");
  if (!config?.jira?.apiToken && !config?.jira?.tokenAlias) return;
  if (config.jira.apiToken) {
    config.jira.apiTokenEncrypted = encryptSecret(config.jira.apiToken);
  }
  delete config.jira.apiToken;
  delete config.jira.tokenAlias;
  await writeState("config", config);
}

async function migrateStoredEncryptedSecrets() {
  const config = await readState("config");
  if (!config) return;
  let changed = false;

  const adPassword = decryptSecretWithMetadata(config.ad?.bindPasswordEncrypted);
  if (adPassword.value && !adPassword.usingCurrentKey) {
    config.ad.bindPasswordEncrypted = encryptSecret(adPassword.value);
    changed = true;
  }

  const jiraToken = decryptSecretWithMetadata(config.jira?.apiTokenEncrypted);
  if (jiraToken.value && !jiraToken.usingCurrentKey) {
    config.jira.apiTokenEncrypted = encryptSecret(jiraToken.value);
    changed = true;
  }

  const nutanixPassword = decryptSecretWithMetadata(config.nutanix?.passwordEncrypted);
  if (nutanixPassword.value && !nutanixPassword.usingCurrentKey) {
    config.nutanix.passwordEncrypted = encryptSecret(nutanixPassword.value);
    changed = true;
  }

  if (changed) await writeState("config", config);
}

async function migrateObsoleteStoredState() {
  const config = await readState("config");
  if (config?.jira && ("activeStatusId" in config.jira || "inactiveStatusId" in config.jira)) {
    delete config.jira.activeStatusId;
    delete config.jira.inactiveStatusId;
    await writeState("config", config);
  }

  const mappings = await readState("mappings");
  if (Array.isArray(mappings)) {
    const nextMappings = mappings.filter((mapping) => !["map-users", "map-vms"].includes(String(mapping?.id)));
    if (nextMappings.length !== mappings.length) await writeState("mappings", nextMappings);
  }

  const logs = await readState("logs");
  if (Array.isArray(logs)) {
    const nextLogs = logs.filter((log) => !["log-1", "log-2"].includes(String(log?.id)));
    if (nextLogs.length !== logs.length) await writeState("logs", nextLogs);
  }
}

let jiraCatalogRefreshRunning = false;
let mappingSchedulerTickRunning = false;

function startJiraCatalogRefreshTask() {
  setInterval(() => {
    refreshJiraAssetsCatalogFromStoredConfig().catch((error) => {
      console.warn("Scheduled Jira Assets catalog refresh failed:", error instanceof Error ? error.message : error);
    });
  }, 60 * 60 * 1000);
}

function startMappingSchedulerTask() {
  console.log(`Mapping scheduler enabled. Tick interval: ${MAPPING_SCHEDULER_INTERVAL_MS} ms.`);
  setTimeout(() => {
    runScheduledMappingsTick("startup").catch((error) => {
      console.warn("Startup mapping sync tick failed:", error instanceof Error ? error.message : error);
    });
  }, Number(process.env.MAPPING_SCHEDULER_STARTUP_DELAY_MS || 5000)).unref?.();
  setInterval(() => {
    runScheduledMappingsTick("interval").catch((error) => {
      console.warn("Scheduled mapping sync tick failed:", error instanceof Error ? error.message : error);
    });
  }, MAPPING_SCHEDULER_INTERVAL_MS).unref?.();
}

async function runScheduledMappingsTick(reason = "interval") {
  if (mappingSchedulerTickRunning) return;
  mappingSchedulerTickRunning = true;
  try {
    const config = await readState("config");
    const jira = config?.jira ?? {};
    const token = decryptSecret(jira.apiTokenEncrypted) || process.env.JIRA_API_TOKEN;
    if (!config || !jira.cloudId || !jira.workspaceId || !jira.email || !token) {
      if (reason === "startup") console.warn("Mapping scheduler skipped on startup: Jira Assets no esta configurado completamente.");
      return;
    }

    const mappings = await readStoredMappings();
    const dueMappings = mappings.filter((mapping) => isScheduledMappingDue(mapping, new Date()));
    if (dueMappings.length) {
      console.log(`Mapping scheduler ${reason}: ${dueMappings.length} mapeo(s) vencido(s): ${dueMappings.map((mapping) => mapping.name).join(", ")}.`);
    } else if (reason === "startup") {
      const scheduledMappings = mappings.filter((mapping) => mapping?.automatic && getMappingFrequencyMs(mapping));
      console.log(`Mapping scheduler startup: ${scheduledMappings.length} mapeo(s) programado(s), ninguno vencido.`);
    }
    for (const mapping of dueMappings) {
      void runScheduledMappingSync({ mapping, config, jira, token });
    }
  } finally {
    mappingSchedulerTickRunning = false;
  }
}

async function runScheduledMappingSync({ mapping, config, jira, token }) {
  if (!mapping?.id || scheduledSyncs.has(mapping.id)) return;
  scheduledSyncs.add(mapping.id);
  const startedAt = formatServerDate(new Date());
  const logId = crypto.randomUUID();
  try {
    await updateStoredMappingStatus(mapping.id, { lastSync: "Ejecutando", status: "Ejecutando" });
    await upsertStoredSyncLog({
      id: logId,
      mappingName: mapping.name,
      startedAt,
      status: "Ejecutando",
      created: 0,
      updated: 0,
      unchanged: 0,
      errors: 0,
      changes: [{ object: mapping.objectType, action: "Información", detail: `Sincronizacion automatica iniciada por programacion: ${mapping.frequency}.` }],
    });

    if (!["AD", "Nutanix"].includes(mapping.source)) {
      throw new Error(`Origen no soportado en sincronizacion programada: ${mapping.source}.`);
    }

    let lastPersistedProgressAt = 0;
    const runner = mapping.source === "Nutanix" ? runNutanixMappingSync : runAdMappingSync;
    const result = await runner({
      config,
      mapping,
      jira,
      token,
      isCancelled: () => false,
      onProgress: (progress) => {
        const now = Date.now();
        if (now - lastPersistedProgressAt < 10_000) return;
        lastPersistedProgressAt = now;
        void upsertStoredSyncLog({
          id: logId,
          mappingName: mapping.name,
          startedAt,
          status: "Ejecutando",
          created: progress.created ?? 0,
          updated: progress.updated ?? 0,
          unchanged: progress.unchanged ?? 0,
          errors: progress.errors ?? 0,
          changes: progress.changes ?? [],
        }).catch((error) => {
          console.warn("Could not persist scheduled sync progress:", error instanceof Error ? error.message : error);
        });
      },
    });
    const finalLog = { ...result, id: logId, startedAt };
    await upsertStoredSyncLog(finalLog);
    await updateStoredMappingStatus(mapping.id, { lastSync: startedAt, status: finalLog.status });
  } catch (error) {
    console.error("Scheduled mapping sync failed:", sanitizeLdapError(error));
    const failedLog = {
      id: logId,
      mappingName: mapping.name,
      startedAt,
      status: "Error",
      created: 0,
      updated: 0,
      unchanged: 0,
      errors: 1,
      changes: [{ object: mapping.objectType || mapping.name, action: "Error", detail: error instanceof Error ? error.message : "Error al ejecutar la sincronizacion programada." }],
    };
    await upsertStoredSyncLog(failedLog);
    await updateStoredMappingStatus(mapping.id, { lastSync: startedAt, status: "Error" });
  } finally {
    scheduledSyncs.delete(mapping.id);
  }
}

async function readStoredMappings() {
  const mappings = await readState("mappings");
  return Array.isArray(mappings) ? mappings : [];
}

function getMappingFrequencyMs(mapping) {
  const frequency = String(mapping?.frequency ?? "");
  if (frequency === "Cada hora" || frequency === "Cada 1 hora") return 60 * 60 * 1000;
  if (frequency === "Cada 6 horas") return 6 * 60 * 60 * 1000;
  if (frequency === "Cada 24 horas") return 24 * 60 * 60 * 1000;
  return 0;
}

function isScheduledMappingDue(mapping, now) {
  if (!mapping?.id || !mapping.automatic || scheduledSyncs.has(mapping.id)) return false;
  const frequencyMs = getMappingFrequencyMs(mapping);
  if (!frequencyMs) return false;
  const lastSync = parseStoredMappingDate(mapping.lastSync);
  if (!lastSync) return true;
  return now.getTime() - lastSync.getTime() >= frequencyMs;
}

function parseStoredMappingDate(value) {
  if (!value || ["Pendiente", "Ejecutando", "Manual"].includes(String(value))) return null;
  const spanishMatch = String(value).trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2}))?$/);
  if (spanishMatch) {
    const [, day, month, year, hour = "0", minute = "0"] = spanishMatch;
    const date = new Date(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute));
    return Number.isNaN(date.getTime()) ? null : date;
  }
  const normalized = String(value).includes("T") ? String(value) : String(value).replace(" ", "T");
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

async function updateStoredMappingStatus(mappingId, patch) {
  const mappings = await readStoredMappings();
  const next = mappings.map((mapping) => (mapping.id === mappingId ? { ...mapping, ...patch } : mapping));
  await writeState("mappings", next);
}

async function upsertStoredSyncLog(log) {
  const current = await readState("logs");
  const logs = Array.isArray(current) ? current : [];
  const next = logs.some((item) => item.id === log.id) ? logs.map((item) => (item.id === log.id ? log : item)) : [log, ...logs];
  await writeState("logs", next);
}

async function refreshJiraAssetsCatalogFromStoredConfig() {
  if (jiraCatalogRefreshRunning) return;
  jiraCatalogRefreshRunning = true;
  try {
    const config = await readState("config");
    const jira = config?.jira ?? {};
    const token = decryptSecret(jira.apiTokenEncrypted) || process.env.JIRA_API_TOKEN;
    if (!jira.cloudId || !jira.workspaceId || !jira.email || !token) return;

    const schemas = await fetchJiraAssetsSchemas({
      cloudId: jira.cloudId,
      workspaceId: jira.workspaceId,
      email: jira.email,
      token,
    });

    config.jira = {
      ...jira,
      schemas,
      connected: true,
      testedAt: new Date().toISOString(),
    };
    await writeState("config", config);
  } finally {
    jiraCatalogRefreshRunning = false;
  }
}

async function saveEncryptedAdPassword({ domain, url, bindUser, password }) {
  const config = (await readState("config")) ?? {};
  config.ad = {
    ...(config.ad ?? {}),
    domain,
    url,
    bindUser,
    bindPasswordEncrypted: encryptSecret(password),
  };
  delete config.ad.bindPassword;
  await writeState("config", config);
}

async function saveEncryptedNutanixPassword({ prismUrl, username, password, clusters }) {
  const config = (await readState("config")) ?? {};
  config.nutanix = {
    ...(config.nutanix ?? {}),
    prismUrl,
    username,
    connected: true,
    testedAt: new Date().toISOString(),
  };
  if (password) config.nutanix.passwordEncrypted = encryptSecret(password);
  if ((!Array.isArray(config.nutanix.selectedClusters) || !config.nutanix.selectedClusters.length) && clusters?.length) {
    config.nutanix.selectedClusters = clusters;
  }
  delete config.nutanix.password;
  await writeState("config", config);
}

async function saveJiraAssetsCatalog({ url, cloudId, workspaceId, email, token, schemas }) {
  const config = (await readState("config")) ?? {};
  config.jira = {
    ...(config.jira ?? {}),
    url,
    cloudId,
    workspaceId,
    email,
    schemas,
    connected: true,
    testedAt: new Date().toISOString(),
  };
  if (token) {
    config.jira.apiTokenEncrypted = encryptSecret(token);
  }
  delete config.jira.apiToken;
  delete config.jira.tokenAlias;
  await writeState("config", config);
}

async function runAdMappingSync({ config, mapping, jira, token, onProgress, isCancelled }) {
  const changes = [];
  let created = 0;
  let updated = 0;
  let unchanged = 0;
  let errors = 0;
  let cancelled = false;
  const emitProgress = () => {
    onProgress?.({
      mappingName: mapping.name,
      status: cancelled ? "Aviso" : "Ejecutando",
      created,
      updated,
      unchanged,
      errors,
      changes: [...changes],
    });
  };
  const addPhase = (detail) => {
    changes.push({ object: mapping.objectType, action: "Ejecutando", detail });
    emitProgress();
  };

  addPhase("Validando configuracion de Active Directory.");
  const ad = config.ad ?? {};
  const adPassword = decryptSecret(ad.bindPasswordEncrypted) || process.env.AD_BIND_PASSWORD;
  if (!ad.domain || !ad.url || !ad.bindUser || !adPassword) {
    throw new Error("Active Directory no tiene conexion completa o password bind cifrada guardada.");
  }
  if (!mapping.sourceScope?.length) {
    throw new Error("El mapeo no tiene OUs seleccionadas.");
  }

  addPhase("Resolviendo esquema, tipo de objeto y atributos de Jira Assets.");
  const target = await resolveJiraMappingTarget({ config, mapping, jira, token });
  const sourceAttributes = buildAdSourceAttributeList(mapping);
  addPhase(`Leyendo entradas directas de Active Directory en ${mapping.sourceScope.length} OUs seleccionadas. No se buscan objetos dentro de OUs hijas no seleccionadas.`);
  const rawEntries = await readAdEntriesForMapping({ ad, password: adPassword, mapping, attributes: sourceAttributes });
  addPhase(`Active Directory ha devuelto ${rawEntries.length} entradas directas. Deduplicando por clave por seguridad.`);
  const deduped = dedupeAdEntriesByMappedKey({ entries: rawEntries, target });
  const entries = deduped.entries;
  addPhase(`Leyendo objetos existentes de Jira Assets para indexarlos por ${target.keyAttribute.name}.`);
  const existingJiraObjects = await findJiraObjectsForMappingTarget({ jira, token, target, action: "leer objetos existentes de Jira Assets para sincronizacion" });
  const existingIndex = indexJiraObjectsByKeyAttribute({ objects: existingJiraObjects, target });
  addPhase(`Jira Assets ha devuelto ${existingJiraObjects.length} objetos existentes. Claves unicas indexadas: ${existingIndex.byKey.size}; claves duplicadas detectadas: ${existingIndex.duplicateKeys.size}.`);
  const referenceIndexes = await buildJiraReferenceIndexes({
    mapping,
    target,
    jira,
    token,
    onProgress: (detail) => addPhase(detail),
  });
  addPhase("Resolviendo configuracion de ciclo de vida y estado Activo/Inactivo.");
  const lifecycle = await resolveJiraUserLifecycle({ mapping, target, jira, token, jiraObjects: existingJiraObjects });
  const activeKeyValues = new Set();

  if (deduped.duplicates.length) {
    unchanged += deduped.duplicates.length;
    changes.push(...deduped.duplicates.map((duplicate) => ({
      object: getAdDisplayName(duplicate.entry),
      action: "Sin cambios",
        detail: `Entrada AD duplicada omitida antes de sincronizar. Clave ${target.keyAttribute.name}: ${duplicate.keyValue}. Si aparece con ObjectSID, revisa si AD ha devuelto el mismo objeto por referencias o bases LDAP externas al arbol seleccionado.`,
    })));
  }

  const batches = chunkArray(entries, Math.max(1, SYNC_BATCH_SIZE));
  changes.push({
    object: mapping.objectType,
    action: "Información",
    detail: `Preparada sincronizacion de ${entries.length} entradas AD en ${batches.length} lotes de hasta ${Math.max(1, SYNC_BATCH_SIZE)} objetos. OUs consultadas directamente: ${mapping.sourceScope.length}; leidos en AD: ${rawEntries.length}; duplicados AD omitidos: ${deduped.duplicates.length}.`,
  });
  emitProgress();

  for (const [batchIndex, batch] of batches.entries()) {
    if (isCancelled?.()) {
      cancelled = true;
      changes.push({ object: mapping.objectType, action: "Cancelado", detail: `Sincronizacion detenida antes de iniciar el lote ${batchIndex + 1}/${batches.length}.` });
      emitProgress();
      break;
    }
    const before = { created, updated, unchanged, errors };
    for (const [entryIndex, entry] of batch.entries()) {
      if (isCancelled?.()) {
        cancelled = true;
        changes.push({ object: getAdDisplayName(entry), action: "Cancelado", detail: "Sincronizacion detenida antes de procesar este objeto." });
        break;
      }
      changes.push({
        object: getAdDisplayName(entry),
        action: "Ejecutando",
        detail: `Procesando objeto ${entryIndex + 1}/${batch.length} del lote ${batchIndex + 1}/${batches.length}.`,
      });
      emitProgress();
      const result = await syncSingleAdEntry({ entry, mapping, target, jira, token, lifecycle, activeKeyValues, existingIndex, referenceIndexes, isCancelled });
      created += result.created;
      updated += result.updated;
      unchanged += result.unchanged;
      errors += result.errors;
      changes.push(...result.changes);
    }
    changes.push({
      object: mapping.objectType,
      action: "Información",
      detail: `Lote ${batchIndex + 1}/${batches.length} completado. Objetos procesados: ${batch.length}. Creados: ${created - before.created}; actualizados: ${updated - before.updated}; sin cambios: ${unchanged - before.unchanged}; errores: ${errors - before.errors}.`,
    });
    emitProgress();
    if (cancelled) break;
  }

  if (lifecycle && !cancelled) {
    try {
      addPhase(`Comprobando usuarios de Jira Assets que ya no estan en las OUs seleccionadas de AD. Usuarios activos en esta sync: ${activeKeyValues.size}; objetos Jira revisados: ${existingJiraObjects.length}.`);
      const inactiveResult = await markMissingAdUsersInactiveInJira({
        jira,
        token,
        target,
        activeKeyValues,
        statusAttribute: lifecycle.statusAttribute,
        inactiveStatus: lifecycle.inactiveStatus,
        jiraObjects: existingJiraObjects,
        onProgress: (detail) => addPhase(detail),
      });
      updated += inactiveResult.updated;
      unchanged += inactiveResult.unchanged;
      errors += inactiveResult.errors;
      changes.push(...inactiveResult.changes);
    } catch (error) {
      errors += 1;
      changes.push({
        object: mapping.objectType,
        action: "Error",
        detail: `No se pudo completar el control de usuarios inactivos despues de sincronizar altas/actualizaciones: ${error instanceof Error ? error.message : "Error desconocido."}`,
      });
    }
    emitProgress();
  }
  if (cancelled) {
    changes.push({ object: mapping.objectType, action: "Cancelado", detail: `Sincronizacion detenida por el usuario. Totales conservados: creados ${created}, actualizados ${updated}, sin cambios ${unchanged}, errores ${errors}.` });
  }

  return {
    id: crypto.randomUUID(),
    mappingName: mapping.name,
    startedAt: formatServerDate(new Date()),
    status: cancelled || errors ? "Aviso" : "Correcta",
    created,
    updated,
    unchanged,
    errors,
    changes,
  };
}

async function runNutanixMappingSync({ config, mapping, jira, token, onProgress, isCancelled }) {
  const changes = [];
  let created = 0;
  let updated = 0;
  let unchanged = 0;
  let errors = 0;
  let cancelled = false;
  const emitProgress = () => {
    onProgress?.({
      mappingName: mapping.name,
      status: cancelled ? "Aviso" : "Ejecutando",
      created,
      updated,
      unchanged,
      errors,
      changes: [...changes],
    });
  };
  const addPhase = (detail) => {
    changes.push({ object: mapping.objectType, action: "Ejecutando", detail });
    emitProgress();
  };

  addPhase("Validando configuracion de Nutanix Prism Central.");
  const nutanix = config.nutanix ?? {};
  const nutanixPassword = decryptSecret(nutanix.passwordEncrypted);
  if (!nutanix.prismUrl || !nutanix.username || !nutanixPassword) {
    throw new Error("Nutanix no tiene conexion completa o contrasena cifrada guardada.");
  }

  addPhase("Resolviendo esquema, tipo de objeto y atributos de Jira Assets.");
  const target = await resolveJiraMappingTarget({ config, mapping, jira, token });
  const requestedAttributes = [...new Set((mapping.fields ?? []).map((field) => field.sourceAttribute).filter(Boolean))];
  addPhase(`Leyendo VMs de Nutanix Prism Central. Clusters configurados en el mapeo: ${mapping.sourceScope?.length ? mapping.sourceScope.join(", ") : "todos"}.`);
  const rawVms = await readNutanixVmsForMapping({ nutanix, password: nutanixPassword, mapping });
  const entries = dedupeNutanixVmsByMappedKey({ entries: rawVms, target });
  addPhase(`Nutanix ha devuelto ${rawVms.length} VMs tras filtrar clusters. VMs unicas por clave: ${entries.entries.length}; duplicadas omitidas: ${entries.duplicates.length}.`);

  addPhase(`Leyendo objetos existentes de Jira Assets para indexarlos por ${target.keyAttribute.name}.`);
  const existingJiraObjects = await findJiraObjectsForMappingTarget({ jira, token, target, action: "leer objetos existentes de Jira Assets para sincronizacion Nutanix" });
  const existingIndex = indexJiraObjectsByKeyAttribute({ objects: existingJiraObjects, target });
  addPhase(`Jira Assets ha devuelto ${existingJiraObjects.length} objetos existentes. Claves unicas indexadas: ${existingIndex.byKey.size}; claves duplicadas detectadas: ${existingIndex.duplicateKeys.size}.`);
  const referenceIndexes = await buildJiraReferenceIndexes({
    mapping,
    target,
    jira,
    token,
    onProgress: (detail) => addPhase(detail),
  });

  if (entries.duplicates.length) {
    unchanged += entries.duplicates.length;
    changes.push(...entries.duplicates.map((duplicate) => ({
      object: getNutanixVmDisplayName(duplicate.entry),
      action: "Sin cambios",
      detail: `VM duplicada omitida antes de sincronizar. Clave ${target.keyAttribute.name}: ${duplicate.keyValue}.`,
    })));
  }

  const batches = chunkArray(entries.entries, Math.max(1, SYNC_BATCH_SIZE));
  changes.push({
    object: mapping.objectType,
    action: "Información",
    detail: `Preparada sincronizacion Nutanix de ${entries.entries.length} VMs en ${batches.length} lotes de hasta ${Math.max(1, SYNC_BATCH_SIZE)} objetos. Atributos solicitados: ${requestedAttributes.join(", ") || "ninguno"}.`,
  });
  emitProgress();

  for (const [batchIndex, batch] of batches.entries()) {
    if (isCancelled?.()) {
      cancelled = true;
      changes.push({ object: mapping.objectType, action: "Cancelado", detail: `Sincronizacion detenida antes de iniciar el lote ${batchIndex + 1}/${batches.length}.` });
      emitProgress();
      break;
    }
    const before = { created, updated, unchanged, errors };
    for (const [entryIndex, entry] of batch.entries()) {
      if (isCancelled?.()) {
        cancelled = true;
        changes.push({ object: getNutanixVmDisplayName(entry), action: "Cancelado", detail: "Sincronizacion detenida antes de procesar esta VM." });
        break;
      }
      changes.push({
        object: getNutanixVmDisplayName(entry),
        action: "Ejecutando",
        detail: `Procesando VM ${entryIndex + 1}/${batch.length} del lote ${batchIndex + 1}/${batches.length}.`,
      });
      emitProgress();
      const result = await syncSingleNutanixVm({ entry, mapping, target, jira, token, existingIndex, referenceIndexes, isCancelled });
      created += result.created;
      updated += result.updated;
      unchanged += result.unchanged;
      errors += result.errors;
      changes.push(...result.changes);
    }
    changes.push({
      object: mapping.objectType,
      action: "Información",
      detail: `Lote ${batchIndex + 1}/${batches.length} completado. VMs procesadas: ${batch.length}. Creadas: ${created - before.created}; actualizadas: ${updated - before.updated}; sin cambios: ${unchanged - before.unchanged}; errores: ${errors - before.errors}.`,
    });
    emitProgress();
    if (cancelled) break;
  }

  if (cancelled) {
    changes.push({ object: mapping.objectType, action: "Cancelado", detail: `Sincronizacion detenida por el usuario. Totales conservados: creados ${created}, actualizados ${updated}, sin cambios ${unchanged}, errores ${errors}.` });
  }

  return {
    id: crypto.randomUUID(),
    mappingName: mapping.name,
    startedAt: formatServerDate(new Date()),
    status: cancelled || errors ? "Aviso" : "Correcta",
    created,
    updated,
    unchanged,
    errors,
    changes,
  };
}

async function readAdEntriesForMapping({ ad, password, mapping, attributes }) {
  const client = new Client({
    url: ad.url,
    timeout: 30000,
    connectTimeout: 10000,
    tlsOptions: {
      rejectUnauthorized: process.env.LDAP_TLS_REJECT_UNAUTHORIZED !== "false",
    },
  });
  const filter = getAdEntityFilter(mapping.entity);
  try {
    await client.bind(ad.bindUser, password);
    const results = [];
    for (const baseDn of mapping.sourceScope) {
      // AD is read-only in sync runs: bind + search + unbind, no LDAP modify/add/delete operations.
      const { searchEntries } = await client.search(baseDn, {
        scope: "one",
        filter,
        attributes: [...new Set(["distinguishedName", "name", "cn", ...attributes])],
        sizeLimit: 10000,
      });
      results.push(...searchEntries);
    }
    return results;
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

async function readNutanixVmsForMapping({ nutanix, password, mapping }) {
  const vms = await fetchNutanixVms({ prismUrl: nutanix.prismUrl, username: nutanix.username, password });
  const selectedClusters = new Set((mapping.sourceScope?.length ? mapping.sourceScope : nutanix.selectedClusters ?? []).map((item) => normalizeSyncKeyValue(item)));
  if (!selectedClusters.size) return vms;
  return vms.filter((vm) => {
    const clusterName = normalizeSyncKeyValue(getNutanixAttributeValue(vm, "clusterName"));
    const clusterUuid = normalizeSyncKeyValue(getNutanixAttributeValue(vm, "clusterUuid"));
    return selectedClusters.has(clusterName) || selectedClusters.has(clusterUuid);
  });
}

async function fetchNutanixVms({ prismUrl, username, password }) {
  const baseUrl = normalizeNutanixPrismUrl(prismUrl);
  const auth = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
  const pageSize = Number(process.env.NUTANIX_VM_PAGE_SIZE || 100);
  const vms = [];

  for (let offset = 0; offset <= 250000; offset += pageSize) {
    const response = await fetchNutanixResponse({
      url: `${baseUrl}/api/nutanix/v3/vms/list`,
      method: "POST",
      auth,
      body: { kind: "vm", offset, length: pageSize },
    });
    const payload = await readJsonResponse(response);
    if (!response.ok) {
      throw new Error(`Nutanix devolvio HTTP ${response.status} al leer VMs en /api/nutanix/v3/vms/list: ${trimForError(payload.detail || response.statusText)}.`);
    }
    const page = Array.isArray(payload.raw?.entities) ? payload.raw.entities : [];
    vms.push(...page);
    const total = Number(payload.raw?.metadata?.total_matches ?? payload.raw?.total_matches ?? NaN);
    if (page.length < pageSize || (Number.isFinite(total) && vms.length >= total)) break;
  }

  return vms;
}

async function fetchNutanixResponse({ url, method, auth, body }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Number(process.env.NUTANIX_REQUEST_TIMEOUT_MS || 15000));
  try {
    return await fetch(url, {
      method,
      headers: {
        Authorization: auth,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      signal: controller.signal,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch (error) {
    throw new Error(`No se recibio respuesta de Nutanix Prism Central al llamar ${url}: ${explainNutanixNetworkError(error)}.`);
  } finally {
    clearTimeout(timeout);
  }
}

async function syncSingleAdEntry({ entry, mapping, target, jira, token, lifecycle, activeKeyValues, existingIndex, referenceIndexes, isCancelled }) {
  const changes = [];
  let created = 0;
  let updated = 0;
  let unchanged = 0;
  let errors = 0;

  try {
    const keyValue = getAdAttributeValue(entry, target.keyField.sourceAttribute, target.keyAttribute);
    if (!keyValue) {
      return {
        created,
        updated,
        unchanged,
        errors: 1,
        changes: [{ object: getAdDisplayName(entry), action: "Error", detail: "No se pudo obtener valor para el atributo clave." }],
      };
    }
    activeKeyValues.add(normalizeSyncKeyValue(keyValue));
    const values = await buildMappedValues({ entry, mapping, target, jira, token, referenceIndexes });
    if (lifecycle) addMappedConstantValue({ values, attribute: lifecycle.statusAttribute, value: lifecycle.activeStatus.id, displayValue: lifecycle.activeStatus.name });
    if (!values.syncAttributes.length) {
      return { created, updated, unchanged: 1, errors, changes };
    }

    const normalizedKey = normalizeSyncKeyValue(keyValue);
    let existingObject = existingIndex?.byKey.get(normalizedKey) ?? null;
    let duplicateObjects = existingIndex?.duplicatesByKey.get(normalizedKey) ?? [];
    if (!existingObject) {
      const lookup = await findJiraObjectByMappedKey({ jira, token, target, keyValue });
      existingObject = lookup.object;
      duplicateObjects = lookup.duplicates;
      if (existingObject) existingIndex?.byKey.set(normalizedKey, existingObject);
      if (lookup.duplicates.length) existingIndex?.duplicatesByKey.set(normalizedKey, lookup.duplicates);
    }
    if (duplicateObjects.length) {
      errors += 1;
      changes.push({
        object: getAdDisplayName(entry),
        action: "Error",
        detail: `Jira Assets ya contiene ${duplicateObjects.length + 1} objetos con la misma clave ${target.keyAttribute.name} = ${keyValue}. Se actualizara solo el primero (${getJiraObjectDisplayName(existingObject, keyValue)}) y no se crearan objetos nuevos con esa clave.`,
      });
    }
    const existingObjectId = existingObject ? getJiraObjectId(existingObject) : "";
    if (existingObjectId) {
      assertJiraObjectMatchesTarget(existingObject, target);
      const diff = getJiraAttributeDiff({ existing: existingObject, values, target });
      if (!diff.changedAttributes.length) {
        unchanged += 1;
      } else {
        await updateJiraObject({ jira, token, objectId: existingObjectId, objectTypeId: target.objectType.id, attributes: diff.changedAttributes, target });
        updated += 1;
        changes.push({ object: getAdDisplayName(entry), action: "Actualizado", detail: `${mapping.objectType} actualizado en Jira Assets. Atributos modificados: ${diff.details.join("; ")}.` });
      }
    } else {
      assertRequiredJiraValuesForCreate({ values, target });
      const createdObject = await createJiraObject({ jira, token, objectTypeId: target.objectType.id, attributes: values.attributes, target });
      if (createdObject.payload.raw) existingIndex?.byKey.set(normalizedKey, { ...createdObject.payload.raw, attributes: values.attributes });
      created += 1;
      changes.push({ object: getAdDisplayName(entry), action: "Creado", detail: `${mapping.objectType} creado en Jira Assets (${createdObject.payload.raw?.objectKey ?? createdObject.payload.raw?.id ?? "sin clave"}).${lifecycle ? " Estado inicial: Activo." : ""}` });
    }
    if (values.fieldErrors.length) {
      errors += values.fieldErrors.length;
      changes.push(...values.fieldErrors.map((detail) => ({ object: getAdDisplayName(entry), action: "Error", detail })));
    }
  } catch (error) {
    if (isCancelled?.() || String(error?.message ?? "").toLowerCase().includes("cancelada")) {
      return {
        created,
        updated,
        unchanged,
        errors,
        changes: [{ object: getAdDisplayName(entry), action: "Cancelado", detail: error instanceof Error ? error.message : "Sincronizacion cancelada por el usuario." }],
      };
    }
    errors += 1;
    changes.push({ object: getAdDisplayName(entry), action: "Error", detail: error instanceof Error ? error.message : "Error al sincronizar objeto." });
  }

  return { created, updated, unchanged, errors, changes };
}

async function syncSingleNutanixVm({ entry, mapping, target, jira, token, existingIndex, referenceIndexes, isCancelled }) {
  const changes = [];
  let created = 0;
  let updated = 0;
  let unchanged = 0;
  let errors = 0;

  try {
    const keyValue = getNutanixAttributeValue(entry, target.keyField.sourceAttribute);
    if (!keyValue) {
      return {
        created,
        updated,
        unchanged,
        errors: 1,
        changes: [{ object: getNutanixVmDisplayName(entry), action: "Error", detail: "No se pudo obtener valor para el atributo clave Nutanix." }],
      };
    }
    const values = await buildMappedValues({
      entry,
      mapping,
      target,
      jira,
      token,
      referenceIndexes,
      getSourceValue: (sourceEntry, sourceAttribute) => getNutanixAttributeValue(sourceEntry, sourceAttribute),
    });
    if (!values.syncAttributes.length) {
      return { created, updated, unchanged: 1, errors, changes };
    }

    const normalizedKey = normalizeSyncKeyValue(keyValue);
    let existingObject = existingIndex?.byKey.get(normalizedKey) ?? null;
    let duplicateObjects = existingIndex?.duplicatesByKey.get(normalizedKey) ?? [];
    if (!existingObject) {
      const lookup = await findJiraObjectByMappedKey({ jira, token, target, keyValue });
      existingObject = lookup.object;
      duplicateObjects = lookup.duplicates;
      if (existingObject) existingIndex?.byKey.set(normalizedKey, existingObject);
      if (lookup.duplicates.length) existingIndex?.duplicatesByKey.set(normalizedKey, lookup.duplicates);
    }
    if (duplicateObjects.length) {
      errors += 1;
      changes.push({
        object: getNutanixVmDisplayName(entry),
        action: "Error",
        detail: `Jira Assets ya contiene ${duplicateObjects.length + 1} objetos con la misma clave ${target.keyAttribute.name} = ${keyValue}. Se actualizara solo el primero y no se crearan objetos nuevos con esa clave.`,
      });
    }

    const existingObjectId = existingObject ? getJiraObjectId(existingObject) : "";
    if (existingObjectId) {
      assertJiraObjectMatchesTarget(existingObject, target);
      const diff = getJiraAttributeDiff({ existing: existingObject, values, target });
      if (!diff.changedAttributes.length) {
        unchanged += 1;
      } else {
        await updateJiraObject({ jira, token, objectId: existingObjectId, objectTypeId: target.objectType.id, attributes: diff.changedAttributes, target });
        updated += 1;
        changes.push({ object: getNutanixVmDisplayName(entry), action: "Actualizado", detail: `${mapping.objectType} actualizado en Jira Assets. Atributos modificados: ${diff.details.join("; ")}.` });
      }
    } else {
      assertRequiredJiraValuesForCreate({ values, target });
      const createdObject = await createJiraObject({ jira, token, objectTypeId: target.objectType.id, attributes: values.attributes, target });
      if (createdObject.payload.raw) existingIndex?.byKey.set(normalizedKey, { ...createdObject.payload.raw, attributes: values.attributes });
      created += 1;
      changes.push({ object: getNutanixVmDisplayName(entry), action: "Creado", detail: `${mapping.objectType} creado en Jira Assets (${createdObject.payload.raw?.objectKey ?? createdObject.payload.raw?.id ?? "sin clave"}).` });
    }
    if (values.fieldErrors.length) {
      errors += values.fieldErrors.length;
      changes.push(...values.fieldErrors.map((detail) => ({ object: getNutanixVmDisplayName(entry), action: "Error", detail })));
    }
  } catch (error) {
    if (isCancelled?.() || String(error?.message ?? "").toLowerCase().includes("cancelada")) {
      return {
        created,
        updated,
        unchanged,
        errors,
        changes: [{ object: getNutanixVmDisplayName(entry), action: "Cancelado", detail: error instanceof Error ? error.message : "Sincronizacion cancelada por el usuario." }],
      };
    }
    errors += 1;
    changes.push({ object: getNutanixVmDisplayName(entry), action: "Error", detail: error instanceof Error ? error.message : "Error al sincronizar VM." });
  }

  return { created, updated, unchanged, errors, changes };
}

function buildAdSourceAttributeList(mapping) {
  const attributes = mapping.fields.map((field) => field.sourceAttribute).filter(Boolean);
  if (attributes.some((attribute) => String(attribute).toLowerCase() === "msds-userpasswordexpirytimecomputed")) {
    attributes.push("userAccountControl");
  }
  return [...new Set(attributes)];
}

function dedupeAdEntriesByMappedKey({ entries, target }) {
  const seen = new Set();
  const uniqueEntries = [];
  const duplicates = [];

  for (const entry of entries) {
    const keyValue = getAdAttributeValue(entry, target.keyField.sourceAttribute, target.keyAttribute);
    const normalized = normalizeSyncKeyValue(keyValue);
    if (!normalized) {
      uniqueEntries.push(entry);
      continue;
    }
    if (seen.has(normalized)) {
      duplicates.push({ entry, keyValue });
      continue;
    }
    seen.add(normalized);
    uniqueEntries.push(entry);
  }

  return { entries: uniqueEntries, duplicates };
}

function dedupeNutanixVmsByMappedKey({ entries, target }) {
  const seen = new Set();
  const uniqueEntries = [];
  const duplicates = [];

  for (const entry of entries) {
    const keyValue = getNutanixAttributeValue(entry, target.keyField.sourceAttribute);
    const normalized = normalizeSyncKeyValue(keyValue);
    if (!normalized) {
      uniqueEntries.push(entry);
      continue;
    }
    if (seen.has(normalized)) {
      duplicates.push({ entry, keyValue });
      continue;
    }
    seen.add(normalized);
    uniqueEntries.push(entry);
  }

  return { entries: uniqueEntries, duplicates };
}

function getAdEntityFilter(entity) {
  if (entity === "Usuarios") return "(&(objectCategory=person)(objectClass=user))";
  if (entity === "Grupos") return "(objectClass=group)";
  if (entity === "Equipos") return "(objectClass=computer)";
  return "(objectClass=*)";
}

async function resolveJiraMappingTarget({ config, mapping, jira, token }) {
  const schema = (config.jira?.schemas ?? []).find((item) => item.name === mapping.jiraSchema);
  if (!schema) throw new Error(`No se encontro el esquema Jira ${mapping.jiraSchema}. Ejecuta Probar conexion.`);
  if (!schema.id || Number.isNaN(Number(schema.id))) throw new Error(`El esquema Jira ${mapping.jiraSchema} no tiene ID valido. Ejecuta Probar conexion.`);
  const objectTypes = (schema.objectTypes ?? []).map((objectType) => (typeof objectType === "string" ? { name: objectType, attributes: [] } : objectType));
  let objectType = objectTypes.find((item) => item.name === mapping.objectType);
  if (!objectType?.id) throw new Error(`No se encontro el tipo de objeto Jira ${mapping.objectType}. Ejecuta Probar conexion.`);
  if (Number.isNaN(Number(objectType.id))) throw new Error(`El tipo de objeto Jira ${mapping.objectType} no tiene ID valido. Ejecuta Probar conexion.`);

  let attributes = await fetchJiraObjectTypeAttributes({ jira, token, objectTypeId: objectType.id });
  objectType = { ...objectType, attributes };

  const mappedAttributes = new Map(attributes.map((attribute) => [attribute.name, attribute]));
  for (const field of mapping.fields) {
    const attribute = mappedAttributes.get(field.jiraAttribute);
    if (!attribute?.id) throw new Error(`No se encontro el atributo Jira ${field.jiraAttribute} en ${mapping.objectType}.`);
    if (!isWritableJiraAttribute(attribute)) throw new Error(`El atributo Jira ${field.jiraAttribute} es de sistema o no editable. Jira Assets lo gestiona automaticamente y no debe incluirse en el mapeo.`);
  }

  const keyField = mapping.fields.find((field) => field.key) ?? mapping.fields[0];
  const keyAttribute = mappedAttributes.get(keyField?.jiraAttribute);
  if (!keyAttribute?.id) throw new Error("No se pudo resolver el atributo clave Jira.");

  return {
    schema,
    objectType,
    attributes,
    mappedAttributes,
    requiredAttributes: attributes.filter((attribute) => isWritableJiraAttribute(attribute) && (attribute.required || attribute.label)),
    allSchemas: config.jira?.schemas ?? [],
    keyField,
    keyAttribute,
  };
}

function normalizeJiraAttributeDefinitions(attributes) {
  return attributes
    .map((attribute) => (typeof attribute === "string" ? { id: "", name: attribute, editable: true, system: false } : {
      id: String(attribute.id ?? attribute.objectTypeAttributeId ?? ""),
      name: String(attribute.name ?? attribute.label ?? ""),
      editable: attribute.editable !== false,
      system: Boolean(attribute.system),
      required: Number(attribute.minimumCardinality ?? attribute.minCardinality ?? 0) > 0,
      label: Boolean(attribute.label === true),
      type: getJiraAttributeTypeName(attribute),
    }))
    .filter((attribute) => attribute.name);
}

function getJiraAttributeTypeName(attribute) {
  return String(
    attribute.defaultType?.name ??
    attribute.type?.name ??
    attribute.typeValue ??
    attribute.typeName ??
    attribute.type ??
    ""
  );
}

function isWritableJiraAttribute(attribute) {
  return attribute?.editable !== false && !attribute?.system && !["key", "created", "updated"].includes(String(attribute?.name ?? "").toLowerCase());
}

async function fetchJiraObjectTypeAttributes({ jira, token, objectTypeId }) {
  const baseUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(jira.cloudId)}/jsm/assets/workspace/${encodeURIComponent(jira.workspaceId)}/v1`;
  const result = await fetchJiraJsonWithAuthFallbacks({
    attempts: [
      { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/objecttype/${encodeURIComponent(objectTypeId)}/attributes`, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/objecttype/${encodeURIComponent(objectTypeId)}/attributes`, auth: "bearer" },
    ],
    email: jira.email,
    token,
    action: "leer atributos del tipo de objeto Jira",
  });
  return normalizeJiraAttributeDefinitions(extractArray(result.payload.raw));
}

async function buildMappedValues({ entry, mapping, target, jira, token, referenceIndexes, getSourceValue = getAdAttributeValue }) {
  const attributes = [];
  const syncAttributes = [];
  let keyValue = "";
  const valuesByAttributeId = new Map();
  const displayValuesByAttributeId = new Map();
  const referenceAttributeIds = new Set();
  const fieldErrors = [];
  for (const field of mapping.fields) {
    const attribute = target.mappedAttributes.get(field.jiraAttribute);
    if (!attribute?.id || attribute.editable === false) continue;
    const sourceValue = getSourceValue(entry, field.sourceAttribute, attribute);
    let value = sourceValue;
    let comparableValue = sourceValue;
    if ((field.kind ?? "attribute") === "jiraObject") {
      try {
        const referenceObject = await resolveJiraReferenceObject({ jira, token, target, field, sourceValue, referenceIndexes });
        value = referenceObject.objectKey;
        comparableValue = referenceObject.id ? `${referenceObject.objectKey} | ${referenceObject.id}` : referenceObject.objectKey;
        if (referenceObject.label) displayValuesByAttributeId.set(String(attribute.id), referenceObject.label);
        referenceAttributeIds.add(String(attribute.id));
      } catch (error) {
        fieldErrors.push(error instanceof Error ? error.message : `No se pudo resolver la referencia ${field.jiraAttribute}.`);
        continue;
      }
    }
    if (field.key) keyValue = value;
    valuesByAttributeId.set(String(attribute.id), comparableValue);
    const payload = {
      objectTypeAttributeId: attribute.id,
      objectAttributeValues: value === "" ? [] : [{ value }],
    };
    syncAttributes.push(payload);
    if (value !== "") attributes.push(payload);
  }
  if (!keyValue && target.keyField) {
    keyValue = getSourceValue(entry, target.keyField.sourceAttribute);
  }
  return { attributes, syncAttributes, keyValue, valuesByAttributeId, displayValuesByAttributeId, referenceAttributeIds, fieldErrors };
}

async function resolveJiraUserLifecycle({ mapping, target, jira, token, jiraObjects }) {
  if (mapping.source !== "AD" || mapping.entity !== "Usuarios") return null;
  if (mapping.statusConfig?.enabled === false) return null;
  const statusAttribute = mapping.statusConfig?.jiraAttribute
    ? findJiraAttributeByName(target.attributes, mapping.statusConfig.jiraAttribute)
    : findJiraStatusAttribute(target.attributes);
  if (!statusAttribute?.id) {
    throw new Error(`El tipo de objeto Jira seleccionado para Usuarios no tiene un atributo Estado/Status detectable. Atributos leidos de Jira: ${target.attributes.map((attribute) => attribute.name).join(", ") || "ninguno"}.`);
  }
  if (!isWritableJiraAttribute(statusAttribute)) {
    throw new Error("El atributo Jira Estado no es editable. No se puede gestionar Activo/Inactivo desde la sincronizacion.");
  }
  const activeStatusId = String(mapping.statusConfig?.activeValue ?? "").trim();
  const inactiveStatusId = String(mapping.statusConfig?.inactiveValue ?? "").trim();
  if (activeStatusId && inactiveStatusId) {
    return {
      statusAttribute,
      activeStatus: { id: activeStatusId, name: "Activo" },
      inactiveStatus: { id: inactiveStatusId, name: "Inactivo" },
    };
  }

  const inferred = await inferJiraStatusIdsFromObjects({ jira, token, target, statusAttribute, jiraObjects });
  if (inferred.activeStatus?.id && inferred.inactiveStatus?.id) {
    return { statusAttribute, activeStatus: inferred.activeStatus, inactiveStatus: inferred.inactiveStatus };
  }

  throw new Error(`Configura en Jira Assets los campos ID estado Activo e ID estado Inactivo. No se pudieron deducir desde objetos existentes del tipo ${target.objectType.name}. Detectado Activo: ${inferred.activeStatus?.id ?? "no"}; Inactivo: ${inferred.inactiveStatus?.id ?? "no"}.`);
}

function findJiraAttributeByName(attributes, name) {
  const normalizedName = normalizeName(name);
  return attributes.find((attribute) => normalizeName(attribute.name) === normalizedName);
}

function findJiraStatusAttribute(attributes) {
  return (
    findJiraAttributeByName(attributes, "Estado") ??
    findJiraAttributeByName(attributes, "Status") ??
    attributes.find((attribute) => ["estado", "status"].includes(normalizeName(attribute.type)))
  );
}

async function inferJiraStatusIdsFromObjects({ jira, token, target, statusAttribute, jiraObjects }) {
  const objects = jiraObjects ?? await findJiraObjectsForMappingTarget({ jira, token, target, action: "leer objetos existentes de Jira Assets para deducir estados" });
  const found = { activeStatus: null, inactiveStatus: null };

  for (const object of objects) {
    const attributeValues = getExistingJiraAttributeValues(object);
    const values = getJiraAttributeLookupKeys(statusAttribute).map((key) => attributeValues.get(key)).find((item) => item != null) ?? [];
    for (const value of Array.isArray(values) ? values : [values]) {
      const candidate = extractJiraStatusCandidate(value);
      if (!candidate.id) continue;
      const normalized = normalizeName(candidate.name);
      if (!found.activeStatus && ["activo", "active"].includes(normalized)) {
        found.activeStatus = { id: candidate.id, name: candidate.name || "Activo" };
      }
      if (!found.inactiveStatus && ["inactivo", "inactive"].includes(normalized)) {
        found.inactiveStatus = { id: candidate.id, name: candidate.name || "Inactivo" };
      }
    }
    if (found.activeStatus && found.inactiveStatus) break;
  }

  return found;
}

function extractJiraStatusCandidate(value) {
  if (value == null) return { id: "", name: "" };
  if (typeof value !== "object") return { id: String(value), name: "" };
  const id = String(value.status?.id ?? value.referencedStatus?.id ?? value.value ?? "");
  const name = String(value.status?.name ?? value.referencedStatus?.name ?? value.displayValue ?? value.searchValue ?? "");
  return { id, name };
}

function normalizeName(value) {
  return String(value ?? "").trim().toLowerCase();
}

function addMappedConstantValue({ values, attribute, value, displayValue }) {
  const payload = {
    objectTypeAttributeId: attribute.id,
    objectAttributeValues: value === "" ? [] : [{ value }],
  };
  values.valuesByAttributeId.set(String(attribute.id), value);
  if (displayValue) values.displayValuesByAttributeId.set(String(attribute.id), displayValue);
  values.syncAttributes = values.syncAttributes.filter((item) => String(item.objectTypeAttributeId) !== String(attribute.id));
  values.syncAttributes.push(payload);
  values.attributes = values.attributes.filter((item) => String(item.objectTypeAttributeId) !== String(attribute.id));
  if (value !== "") values.attributes.push(payload);
}

function indexJiraObjectsByKeyAttribute({ objects, target }) {
  const byKey = new Map();
  const duplicatesByKey = new Map();
  for (const object of objects) {
    const keyValue = getExistingJiraAttributeValue(object, target.keyAttribute);
    const normalized = normalizeSyncKeyValue(keyValue);
    if (!normalized) continue;
    if (byKey.has(normalized)) {
      const duplicates = duplicatesByKey.get(normalized) ?? [];
      duplicates.push(object);
      duplicatesByKey.set(normalized, duplicates);
      continue;
    }
    byKey.set(normalized, object);
  }
  return { byKey, duplicatesByKey, duplicateKeys: new Set(duplicatesByKey.keys()) };
}

async function markMissingAdUsersInactiveInJira({ jira, token, target, activeKeyValues, statusAttribute, inactiveStatus, jiraObjects, onProgress }) {
  const objects = jiraObjects ?? await findJiraObjectsForMappingTarget({ jira, token, target, action: "leer objetos existentes en Jira Assets para control de estado" });
  const changes = [];
  let updated = 0;
  let unchanged = 0;
  let errors = 0;
  let withKey = 0;
  let withoutKey = 0;
  let stillInAd = 0;
  let missingInAd = 0;

  for (const [index, object] of objects.entries()) {
    try {
      assertJiraObjectMatchesTarget(object, target);
      const keyValue = getExistingJiraAttributeValue(object, target.keyAttribute);
      if (!keyValue) {
        withoutKey += 1;
        errors += 1;
        changes.push({
          object: getJiraObjectDisplayName(object, "Objeto Jira"),
          action: "Error",
          detail: `No se puede evaluar baja porque no se pudo leer el atributo clave ${target.keyAttribute.name} en este objeto Jira. Revisa que el atributo este visible y tenga valor.`,
        });
        continue;
      }
      withKey += 1;
      if (activeKeyValues.has(normalizeSyncKeyValue(keyValue))) {
        stillInAd += 1;
        continue;
      }
      missingInAd += 1;

      if (index % Math.max(1, SYNC_BATCH_SIZE) === 0) {
        onProgress?.(`Control de bajas Jira: revisados ${index + 1}/${objects.length}; siguen en AD ${stillInAd}; candidatos a Baja ${missingInAd}; sin clave ${withoutKey}.`);
      }

      const values = createSingleAttributeValues({ attribute: statusAttribute, value: inactiveStatus.id, displayValue: inactiveStatus.name });
      const diff = getJiraAttributeDiff({ existing: object, values, target });
      if (!diff.changedAttributes.length) {
        unchanged += 1;
        continue;
      }

      const objectId = getJiraObjectId(object);
      if (!objectId) throw new Error("No se pudo resolver el ID del objeto Jira para marcarlo como Inactivo.");
      await updateJiraObject({ jira, token, objectId, objectTypeId: target.objectType.id, attributes: diff.changedAttributes, target });
      updated += 1;
      changes.push({ object: getJiraObjectDisplayName(object, keyValue), action: "Actualizado", detail: `${target.objectType.name} marcado como Inactivo porque no existe en AD. Atributos modificados: ${diff.details.join("; ")}.` });
    } catch (error) {
      errors += 1;
      changes.push({ object: getJiraObjectDisplayName(object, "Objeto Jira"), action: "Error", detail: error instanceof Error ? error.message : "Error al marcar usuario como Inactivo." });
    }
  }

  changes.push({
    object: target.objectType.name,
    action: errors ? "Aviso" : "Sin cambios",
    detail: `Control de bajas finalizado. Objetos Jira revisados: ${objects.length}; con clave ${target.keyAttribute.name}: ${withKey}; sin clave: ${withoutKey}; siguen en AD: ${stillInAd}; candidatos fuera de AD: ${missingInAd}; marcados como Baja: ${updated}; ya estaban en Baja: ${unchanged}; errores: ${errors}.`,
  });

  return { updated, unchanged, errors, changes };
}

function normalizeSyncKeyValue(value) {
  return String(value ?? "").trim().toLowerCase();
}

function createSingleAttributeValues({ attribute, value, displayValue }) {
  const payload = {
    objectTypeAttributeId: attribute.id,
    objectAttributeValues: value === "" ? [] : [{ value }],
  };
  return {
    attributes: value === "" ? [] : [payload],
    syncAttributes: [payload],
    valuesByAttributeId: new Map([[String(attribute.id), value]]),
    displayValuesByAttributeId: new Map(displayValue ? [[String(attribute.id), displayValue]] : []),
    referenceAttributeIds: new Set(),
  };
}

function assertRequiredJiraValuesForCreate({ values, target }) {
  const missing = target.requiredAttributes
    .filter((attribute) => !values.valuesByAttributeId.get(String(attribute.id)))
    .map((attribute) => attribute.name);
  if (missing.length) {
    throw new Error(`No se puede crear el objeto en Jira Assets porque faltan atributos obligatorios del tipo ${target.objectType.name}: ${missing.join(", ")}. Anade esos atributos al mapeo y asegurate de que AD devuelve valor.`);
  }
}

function getJiraAttributeDiff({ existing, values, target }) {
  const currentValues = getExistingJiraAttributeValues(existing);
  const attributesById = new Map(target.attributes.map((attribute) => [String(attribute.id), attribute]));
  const changedAttributes = [];
  const details = [];

  for (const attributePayload of values.syncAttributes) {
    const attributeId = String(attributePayload.objectTypeAttributeId ?? "");
    if (!attributeId) continue;
    const expectedComparableValue = values.valuesByAttributeId?.get(attributeId);
    const nextValue = expectedComparableValue != null ? normalizeComparableAttributeValues(String(expectedComparableValue).split(" | ")) : normalizeComparableAttributeValues(attributePayload.objectAttributeValues);
    const currentAttribute = attributesById.get(attributeId) ?? attributeId;
    const currentValue = getExistingJiraAttributeValue(existing, currentAttribute) || normalizeComparableAttributeValues(currentValues.get(attributeId) ?? []);
    const matches = values.referenceAttributeIds?.has(attributeId) ? comparableValuesOverlap(nextValue, currentValue) : nextValue === currentValue;
    if (matches) continue;

    changedAttributes.push(attributePayload);
    const attributeName = attributesById.get(attributeId)?.name ?? attributeId;
    const displayNextValue = values.displayValuesByAttributeId?.get(attributeId) ?? nextValue;
    details.push(`${attributeName}: ${formatDiffValue(currentValue)} -> ${formatDiffValue(displayNextValue)}`);
  }

  return { changedAttributes, details };
}

function comparableValuesOverlap(nextValue, currentValue) {
  if (nextValue === currentValue) return true;
  const nextParts = splitComparableValue(nextValue);
  const currentParts = splitComparableValue(currentValue);
  return nextParts.some((value) => currentParts.includes(value));
}

function splitComparableValue(value) {
  return String(value ?? "").split(" | ").map((item) => item.trim()).filter(Boolean);
}

function getExistingJiraAttributeValues(object) {
  const values = new Map();
  const attributes = Array.isArray(object.attributes) ? object.attributes : [];
  for (const attribute of attributes) {
    const attributeValues = attribute.objectAttributeValues ?? attribute.values ?? [];
    const keys = [
      attribute.objectTypeAttributeId,
      attribute.objectTypeAttribute?.id,
      attribute.objectTypeAttribute?.objectTypeAttributeId,
      attribute.id,
    ].map((value) => String(value ?? "")).filter(Boolean);
    const names = [
      attribute.objectTypeAttribute?.name,
      attribute.name,
      attribute.label,
    ].map((value) => String(value ?? "")).filter(Boolean);

    for (const key of keys) values.set(key, attributeValues);
    for (const name of names) values.set(getJiraAttributeNameLookupKey(name), attributeValues);
  }
  return values;
}

function getExistingJiraAttributeValue(object, attribute) {
  const values = getExistingJiraAttributeValues(object);
  for (const key of getJiraAttributeLookupKeys(attribute)) {
    if (values.has(key)) return normalizeComparableAttributeValues(values.get(key) ?? []);
  }
  return "";
}

function getJiraAttributeLookupKeys(attribute) {
  if (attribute == null) return [];
  if (typeof attribute !== "object") return [String(attribute)];
  return [
    attribute.id,
    attribute.objectTypeAttributeId,
    attribute.name ? getJiraAttributeNameLookupKey(attribute.name) : "",
  ].map((value) => String(value ?? "")).filter(Boolean);
}

function getJiraAttributeNameLookupKey(name) {
  return `name:${normalizeName(name)}`;
}

function getJiraObjectId(object) {
  return String(object.id ?? object.objectId ?? object.globalId ?? "").replace(/^.*:/, "");
}

function getJiraObjectDisplayName(object, fallback) {
  return String(object.label ?? object.name ?? object.objectKey ?? object.id ?? fallback);
}

function normalizeComparableAttributeValues(values) {
  const items = (Array.isArray(values) ? values : [values])
    .map(extractComparableAttributeValue)
    .filter((value) => value !== "")
    .map((value) => value.trim())
    .sort((a, b) => a.localeCompare(b, "es"));
  return items.join(" | ");
}

function extractComparableAttributeValue(value) {
  if (value == null) return "";
  if (typeof value !== "object") return String(value);
  if (value.status?.id != null) return String(value.status.id);
  if (value.status?.name != null) return String(value.status.name);
  if (value.referencedStatus?.id != null) return String(value.referencedStatus.id);
  if (value.referencedStatus?.name != null) return String(value.referencedStatus.name);
  if (value.referencedObject?.objectKey != null) return String(value.referencedObject.objectKey);
  if (value.referencedObject?.id != null) return String(value.referencedObject.id);
  if (value.referencedObject?.objectId != null) return String(value.referencedObject.objectId);
  if (value.referencedObject?.globalId != null) return String(value.referencedObject.globalId).replace(/^.*:/, "");
  if (value.value != null) return String(value.value);
  if (value.displayValue != null) return String(value.displayValue);
  if (value.searchValue != null) return String(value.searchValue);
  if (value.referencedObject?.label != null) return String(value.referencedObject.label);
  if (value.user?.accountId != null) return String(value.user.accountId);
  return "";
}

function formatDiffValue(value) {
  if (!value) return "(vacio)";
  return value.length > 80 ? `${value.slice(0, 77)}...` : value;
}

const AD_WINDOWS_FILETIME_ATTRIBUTES = new Set([
  "accountexpires",
  "badpasswordtime",
  "lastlogoff",
  "lastlogon",
  "lastlogontimestamp",
  "lockouttime",
  "msds-userpasswordexpirytimecomputed",
  "pwdlastset",
]);

const AD_GENERALIZED_TIME_ATTRIBUTES = new Set([
  "createtimestamp",
  "modifytimestamp",
  "whenchanged",
  "whencreated",
]);

function getAdAttributeValue(entry, attributeName, targetAttribute) {
  if (String(attributeName).toLowerCase() === "msds-userpasswordexpirytimecomputed" && adUserPasswordNeverExpires(entry)) return "";
  const key = Object.keys(entry).find((item) => item.toLowerCase() === String(attributeName).toLowerCase());
  if (!key) return "";
  const value = entry[key];
  if (attributeName.toLowerCase() === "objectsid") return formatSidValue(value);
  if (attributeName.toLowerCase() === "distinguishedname") return formatAdContainerDn(value);
  if (Array.isArray(value)) return value.map((item) => formatSingleAdValue(item, attributeName, targetAttribute)).filter(Boolean).join(", ");
  return formatSingleAdValue(value, attributeName, targetAttribute);
}

function formatAdContainerDn(value) {
  const dn = formatSingleAdValue(Array.isArray(value) ? value[0] : value).trim();
  const separatorIndex = dn.indexOf(",");
  return separatorIndex >= 0 ? dn.slice(separatorIndex + 1).trim() : dn;
}

function adUserPasswordNeverExpires(entry) {
  const key = Object.keys(entry).find((item) => item.toLowerCase() === "useraccountcontrol");
  const value = key ? Number(entry[key]) : 0;
  return Number.isFinite(value) && (value & 0x10000) !== 0;
}

function formatSingleAdValue(value, attributeName = "", targetAttribute) {
  if (value == null) return "";
  const adDate = parseAdDateValue(value, attributeName);
  if (adDate) return formatDateForJiraAttribute(adDate, targetAttribute);
  if (isAdDateAttribute(attributeName)) return "";
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseAdDateValue(value, attributeName) {
  const name = String(attributeName).toLowerCase();
  if (AD_WINDOWS_FILETIME_ATTRIBUTES.has(name)) {
    return parseWindowsFileTime(value);
  }
  if (AD_GENERALIZED_TIME_ATTRIBUTES.has(name)) {
    return parseAdGeneralizedDate(value);
  }
  return null;
}

function isAdDateAttribute(attributeName) {
  const name = String(attributeName).toLowerCase();
  return AD_WINDOWS_FILETIME_ATTRIBUTES.has(name) || AD_GENERALIZED_TIME_ATTRIBUTES.has(name);
}

function parseWindowsFileTime(value) {
  const raw = Buffer.isBuffer(value) ? value.toString("utf8") : String(value ?? "");
  if (!/^\d+$/.test(raw)) return null;
  const fileTime = BigInt(raw);
  if (fileTime === 0n || fileTime >= 9223372036854775807n) return null;
  const milliseconds = fileTime / 10000n - 11644473600000n;
  const date = new Date(Number(milliseconds));
  return Number.isNaN(date.getTime()) ? null : date;
}

function parseAdGeneralizedDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  const raw = Buffer.isBuffer(value) ? value.toString("utf8") : String(value ?? "");
  const match = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$/);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match;
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)));
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDateForJiraAttribute(date, targetAttribute) {
  const type = normalizeName(targetAttribute?.type);
  if (type === "date") return date.toISOString().slice(0, 10);
  return date.toISOString();
}

function formatSidValue(value) {
  const item = Array.isArray(value) ? value[0] : value;
  const buffer = Buffer.isBuffer(item) ? item : Buffer.from(item ?? "");
  if (buffer.length < 8) return formatSingleAdValue(item);
  const revision = buffer.readUInt8(0);
  const subAuthorityCount = buffer.readUInt8(1);
  let authority = 0n;
  for (let index = 2; index < 8; index += 1) authority = (authority << 8n) + BigInt(buffer[index]);
  const parts = [`S-${revision}-${authority.toString()}`];
  for (let index = 0; index < subAuthorityCount; index += 1) {
    const offset = 8 + index * 4;
    if (offset + 4 <= buffer.length) parts.push(String(buffer.readUInt32LE(offset)));
  }
  return parts.join("-");
}

function getAdDisplayName(entry) {
  return getAdAttributeValue(entry, "sAMAccountName") || getAdAttributeValue(entry, "name") || getAdAttributeValue(entry, "cn") || getAdAttributeValue(entry, "distinguishedName") || "Objeto AD";
}

function getNutanixVmDisplayName(vm) {
  return getNutanixAttributeValue(vm, "name") || getNutanixAttributeValue(vm, "vmUuid") || "VM Nutanix";
}

function getNutanixAttributeValue(vm, attributeName) {
  const name = String(attributeName ?? "");
  const metadata = vm?.metadata ?? {};
  const spec = vm?.spec ?? {};
  const status = vm?.status ?? {};
  const specResources = spec.resources ?? {};
  const statusResources = status.resources ?? {};
  const resources = { ...specResources, ...statusResources };
  const clusterRef = status.cluster_reference ?? spec.cluster_reference ?? resources.cluster_reference ?? {};
  const hostRef = status.host_reference ?? spec.host_reference ?? resources.host_reference ?? {};
  const projectRef = metadata.project_reference ?? status.project_reference ?? spec.project_reference ?? {};
  const ownerRef = metadata.owner_reference ?? status.owner_reference ?? spec.owner_reference ?? {};
  const disks = Array.isArray(resources.disk_list) ? resources.disk_list : [];
  const nics = Array.isArray(resources.nic_list) ? resources.nic_list : [];
  const categories = metadata.categories ?? {};

  const lookup = {
    vmUuid: metadata.uuid ?? vm.uuid ?? status.uuid ?? spec.uuid,
    name: status.name ?? spec.name ?? vm.name,
    description: status.description ?? spec.description ?? vm.description,
    powerState: resources.power_state,
    numSockets: resources.num_sockets,
    numVcpusPerSocket: resources.num_vcpus_per_socket,
    numVcpus: getNutanixTotalVcpus(resources),
    numThreadsPerCore: resources.num_threads_per_core,
    memoryMb: resources.memory_size_mib,
    memoryGiB: bytesOrMibToGib(resources.memory_size_mib, "mib"),
    clusterUuid: clusterRef.uuid,
    clusterName: clusterRef.name,
    hostUuid: hostRef.uuid,
    hostName: hostRef.name,
    hypervisorType: resources.hypervisor_type,
    machineType: resources.machine_type,
    guestOsName: resources.guest_os_name ?? resources.guest_os_id,
    guestOsVersion: resources.guest_os_version,
    ngtInstalled: resources.guest_tools?.nutanix_guest_tools?.state ? "true" : "",
    ngtEnabled: resources.guest_tools?.nutanix_guest_tools?.enabled,
    ngtVersion: resources.guest_tools?.nutanix_guest_tools?.version,
    ipAddresses: extractNutanixIpAddresses(nics),
    macAddresses: extractNutanixMacAddresses(nics),
    nics: formatNutanixNics(nics),
    disks: formatNutanixDisks(disks),
    diskSizeBytes: sumNutanixDiskBytes(disks),
    diskSizeGb: bytesOrMibToGib(sumNutanixDiskBytes(disks), "bytes"),
    categories: formatNutanixCategories(categories),
    projectName: projectRef.name,
    projectUuid: projectRef.uuid,
    owner: ownerRef.name ?? ownerRef.uuid,
    creationTime: formatNutanixDate(metadata.creation_time ?? status.creation_time),
    lastUpdateTime: formatNutanixDate(metadata.last_update_time ?? status.last_update_time),
    protectionType: resources.protection_type,
    availabilityZone: resources.availability_zone_reference?.name ?? resources.availability_zone_reference?.uuid,
    subnets: formatNutanixSubnetNames(nics),
    vpc: resources.vpc_reference?.name ?? resources.vpc_reference?.uuid,
    clusterExternalIp: clusterRef.external_ip,
    clusterVirtualIp: clusterRef.virtual_ip,
    timezone: resources.timezone,
    hypervisorTypes: resources.hypervisor_types,
    redundancyFactor: resources.redundancy_factor,
    nodesCount: resources.nodes_count,
    storageCapacityBytes: resources.storage_capacity_bytes,
    storageUsageBytes: resources.storage_usage_bytes,
    cpuCapacityHz: resources.cpu_capacity_hz,
    cpuUsageHz: resources.cpu_usage_hz,
    memoryCapacityBytes: resources.memory_capacity_bytes,
    memoryUsageBytes: resources.memory_usage_bytes,
    aosVersion: resources.aos_version,
    nccVersion: resources.ncc_version,
  };

  const value = lookup[name] ?? getNestedNutanixValue(vm, name);
  return formatNutanixValue(value);
}

function getNutanixTotalVcpus(resources) {
  const sockets = Number(resources.num_sockets ?? 0);
  const perSocket = Number(resources.num_vcpus_per_socket ?? 0);
  if (sockets && perSocket) return sockets * perSocket;
  return resources.num_vcpus ?? "";
}

function bytesOrMibToGib(value, unit) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return "";
  const gib = unit === "bytes" ? number / 1024 / 1024 / 1024 : number / 1024;
  return Math.round(gib * 100) / 100;
}

function extractNutanixIpAddresses(nics) {
  return nics.flatMap((nic) => (nic.ip_endpoint_list ?? []).map((ip) => ip.ip).filter(Boolean));
}

function extractNutanixMacAddresses(nics) {
  return nics.map((nic) => nic.mac_address).filter(Boolean);
}

function formatNutanixNics(nics) {
  return nics.map((nic) => [
    nic.mac_address,
    nic.subnet_reference?.name ?? nic.subnet_reference?.uuid,
    ...(nic.ip_endpoint_list ?? []).map((ip) => ip.ip).filter(Boolean),
  ].filter(Boolean).join(" / ")).filter(Boolean);
}

function formatNutanixDisks(disks) {
  return disks.filter(isNutanixScsiDisk).map((disk) => {
    const address = disk.device_properties?.disk_address;
    const id = [address?.adapter_type, address?.device_index].filter((item) => item != null).join("-");
    const size = bytesOrMibToGib(disk.disk_size_bytes ?? disk.disk_size_mib, disk.disk_size_bytes != null ? "bytes" : "mib");
    return [id || disk.uuid, size ? `${size} GB` : ""].filter(Boolean).join(" ");
  }).filter(Boolean);
}

function isNutanixScsiDisk(disk) {
  const adapterType = String(disk?.device_properties?.disk_address?.adapter_type ?? "").toLowerCase();
  return adapterType === "scsi";
}

function sumNutanixDiskBytes(disks) {
  return disks.reduce((sum, disk) => {
    if (disk.disk_size_bytes != null) return sum + Number(disk.disk_size_bytes || 0);
    if (disk.disk_size_mib != null) return sum + Number(disk.disk_size_mib || 0) * 1024 * 1024;
    return sum;
  }, 0);
}

function formatNutanixCategories(categories) {
  if (!categories || typeof categories !== "object") return "";
  return Object.entries(categories).map(([key, value]) => `${key}:${value}`).sort((a, b) => a.localeCompare(b, "es"));
}

function formatNutanixSubnetNames(nics) {
  return [...new Set(nics.map((nic) => nic.subnet_reference?.name ?? nic.subnet_reference?.uuid).filter(Boolean))];
}

function formatNutanixDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
}

function getNestedNutanixValue(object, pathValue) {
  return String(pathValue).split(".").reduce((current, key) => current?.[key], object);
}

function formatNutanixValue(value) {
  if (value == null || value === "") return "";
  if (Array.isArray(value)) return value.map(formatNutanixValue).filter(Boolean).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

async function findJiraObjectByMappedKey({ jira, token, target, keyValue }) {
  const baseUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(jira.cloudId)}/jsm/assets/workspace/${encodeURIComponent(jira.workspaceId)}/v1`;
  const qlQuery = `objectSchemaId = ${Number(target.schema.id)} AND objectTypeId = ${Number(target.objectType.id)} AND "${escapeAqlValue(target.keyAttribute.name)}" = "${escapeAqlValue(keyValue)}"`;
  const result = await fetchJiraJsonWithAuthFallbacks({
    attempts: [
      { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/object/aql?startAt=0&maxResults=25&includeAttributes=true`, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/object/aql?startAt=0&maxResults=25&includeAttributes=true`, auth: "bearer" },
    ],
    email: jira.email,
    token,
    action: "buscar objeto existente en Jira Assets",
    method: "POST",
    body: { qlQuery },
  });
  const matches = extractJiraObjects(result.payload.raw);
  return {
    object: matches[0] ?? null,
    matches,
    duplicates: matches.slice(1),
  };
}

async function buildJiraReferenceIndexes({ mapping, target, jira, token, onProgress }) {
  const referenceFields = (mapping.fields ?? []).filter((field) => (field.kind ?? "attribute") === "jiraObject");
  const groups = new Map();

  for (const field of referenceFields) {
    const reference = resolveJiraReferenceConfig({ target, field });
    const key = getJiraReferenceIndexKey(reference);
    if (!groups.has(key)) groups.set(key, reference);
  }

  const indexes = new Map();
  for (const reference of groups.values()) {
    onProgress?.(`Precargando referencias Jira para ${reference.schema.name}/${reference.objectType.name} por ${reference.matchAttribute.name}.`);
    const objects = await findJiraObjectsBySchemaAndType({
      jira,
      token,
      schemaId: reference.schema.id,
      objectTypeId: reference.objectType.id,
      action: `leer referencias Jira ${reference.schema.name}/${reference.objectType.name}`,
    });
    const byValue = new Map();
    const duplicates = new Set();
    for (const object of objects) {
      const rawValue = getExistingJiraAttributeValue(object, reference.matchAttribute);
      const normalized = normalizeSyncKeyValue(rawValue);
      if (!normalized) continue;
      if (byValue.has(normalized)) {
        duplicates.add(normalized);
        continue;
      }
      byValue.set(normalized, object);
    }
    indexes.set(getJiraReferenceIndexKey(reference), { ...reference, objects, byValue, duplicates });
    onProgress?.(`Referencias Jira precargadas para ${reference.schema.name}/${reference.objectType.name}: ${objects.length} objetos, ${byValue.size} valores indexados, ${duplicates.size} duplicados.`);
  }

  return indexes;
}

function resolveJiraReferenceConfig({ target, field }) {
  const reference = field.reference ?? {};
  const schema = target.allSchemas.find((item) => item.name === reference.schema);
  if (!schema?.id) throw new Error(`No se encontro el esquema de referencia ${reference.schema} para el atributo ${field.jiraAttribute}.`);
  const objectTypes = (schema.objectTypes ?? []).map((objectType) => (typeof objectType === "string" ? { name: objectType, attributes: [] } : objectType));
  const objectType = objectTypes.find((item) => item.name === reference.objectType);
  if (!objectType?.id) throw new Error(`No se encontro el tipo de objeto de referencia ${reference.objectType} en ${reference.schema}.`);
  if (!reference.matchAttribute) throw new Error(`No se configuro el atributo de conexion para la referencia ${field.jiraAttribute}.`);
  const matchAttribute = findJiraAttributeByName(normalizeJiraAttributeDefinitions(objectType.attributes ?? []), reference.matchAttribute);
  if (!matchAttribute?.id) {
    throw new Error(`No se encontro el atributo de conexion ${reference.matchAttribute} en la referencia ${reference.schema}/${reference.objectType}. Ejecuta Probar conexion en Jira Assets para refrescar el catalogo.`);
  }
  return { schema, objectType, matchAttribute };
}

function getJiraReferenceIndexKey(reference) {
  return [reference.schema.id, reference.objectType.id, reference.matchAttribute.id].map(String).join(":");
}

async function resolveJiraReferenceObject({ jira, token, target, field, sourceValue, referenceIndexes }) {
  if (!sourceValue) return { objectKey: "", id: "" };
  const reference = resolveJiraReferenceConfig({ target, field });
  const index = referenceIndexes?.get(getJiraReferenceIndexKey(reference));
  const object = index?.byValue.get(normalizeSyncKeyValue(sourceValue)) ?? await findJiraReferenceObject({
    jira,
    token,
    schemaId: reference.schema.id,
    objectTypeId: reference.objectType.id,
    attributeName: reference.matchAttribute.name,
    value: sourceValue,
  });
  const objectKey = String(object?.objectKey ?? object?.key ?? "");
  if (!objectKey) {
    throw new Error(`No se encontro objeto Jira para la referencia ${field.jiraAttribute}: ${reference.schema.name}/${reference.objectType.name} donde ${reference.matchAttribute.name} = ${sourceValue}.`);
  }
  return {
    objectKey,
    id: getJiraObjectId(object),
    label: getJiraObjectDisplayName(object, objectKey),
  };
}

async function findJiraReferenceObject({ jira, token, schemaId, objectTypeId, attributeName, value }) {
  const baseUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(jira.cloudId)}/jsm/assets/workspace/${encodeURIComponent(jira.workspaceId)}/v1`;
  const qlQuery = `objectSchemaId = ${Number(schemaId)} AND objectTypeId = ${Number(objectTypeId)} AND "${escapeAqlValue(attributeName)}" = "${escapeAqlValue(value)}"`;
  const result = await fetchJiraJsonWithAuthFallbacks({
    attempts: [
      { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/object/aql?startAt=0&maxResults=1&includeAttributes=false`, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/object/aql?startAt=0&maxResults=1&includeAttributes=false`, auth: "bearer" },
    ],
    email: jira.email,
    token,
    action: "buscar objeto de referencia en Jira Assets",
    method: "POST",
    body: { qlQuery },
  });
  return extractJiraObjects(result.payload.raw)[0] ?? null;
}

async function findJiraObjectsForMappingTarget({ jira, token, target, action = "leer objetos existentes en Jira Assets" }) {
  return findJiraObjectsBySchemaAndType({
    jira,
    token,
    schemaId: target.schema.id,
    objectTypeId: target.objectType.id,
    action,
  });
}

async function findJiraObjectsBySchemaAndType({ jira, token, schemaId, objectTypeId, action = "leer objetos existentes en Jira Assets" }) {
  const baseUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(jira.cloudId)}/jsm/assets/workspace/${encodeURIComponent(jira.workspaceId)}/v1`;
  const qlQuery = `objectSchemaId = ${Number(schemaId)} AND objectTypeId = ${Number(objectTypeId)}`;
  const pageSize = 250;
  const objects = [];

  for (let startAt = 0; startAt <= 250000; startAt += pageSize) {
    const result = await fetchJiraJsonWithAuthFallbacks({
      attempts: [
        { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/object/aql?startAt=${startAt}&maxResults=${pageSize}&includeAttributes=true`, auth: "basic" },
        { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/object/aql?startAt=${startAt}&maxResults=${pageSize}&includeAttributes=true`, auth: "bearer" },
      ],
      email: jira.email,
      token,
      action,
      method: "POST",
      body: { qlQuery },
    });
    const pageObjects = extractJiraObjects(result.payload.raw);
    objects.push(...pageObjects);
    if (isLastJiraObjectPage(result.payload.raw, pageObjects.length, pageSize, startAt)) break;
  }

  return objects;
}

function isLastJiraObjectPage(payload, pageLength, pageSize, startAt = 0) {
  if (payload?.isLastPage === true || payload?.lastPage === true) return true;
  const total = Number(payload?.total ?? payload?.totalCount ?? payload?.totalFilterCount ?? payload?.resultCount ?? NaN);
  if (Number.isFinite(total) && startAt + pageLength >= total) return true;
  if (payload?.pageSize && payload?.totalFilterCount && Number(payload.pageNumber ?? payload.page ?? 1) * Number(payload.pageSize) >= Number(payload.totalFilterCount)) return true;
  return pageLength < pageSize;
}

function assertJiraObjectMatchesTarget(object, target) {
  const objectTypeId = String(object.objectTypeId ?? object.objectType?.id ?? "");
  const objectSchemaId = String(object.objectSchemaId ?? object.objectType?.objectSchemaId ?? "");
  if (objectTypeId && objectTypeId !== String(target.objectType.id)) {
    throw new Error(`El objeto encontrado pertenece al tipo ${objectTypeId}, no al tipo seleccionado ${target.objectType.id}. Se cancela la actualizacion.`);
  }
  if (objectSchemaId && objectSchemaId !== String(target.schema.id)) {
    throw new Error(`El objeto encontrado pertenece al esquema ${objectSchemaId}, no al esquema seleccionado ${target.schema.id}. Se cancela la actualizacion.`);
  }
}

function escapeAqlValue(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function extractJiraObjects(payload) {
  if (Array.isArray(payload?.values)) return payload.values;
  if (Array.isArray(payload?.objectEntries)) return payload.objectEntries;
  if (Array.isArray(payload?.results?.objectEntries)) return payload.results.objectEntries;
  if (Array.isArray(payload?.results)) return payload.results;
  return [];
}

async function createJiraObject({ jira, token, objectTypeId, attributes, target }) {
  return writeJiraObject({ jira, token, path: "/object/create", method: "POST", body: { objectTypeId, attributes }, action: "crear objeto en Jira Assets", target });
}

async function updateJiraObject({ jira, token, objectId, objectTypeId, attributes, target }) {
  return writeJiraObject({ jira, token, path: `/object/${encodeURIComponent(objectId)}`, method: "PUT", body: { objectTypeId, attributes }, action: "actualizar objeto en Jira Assets", target });
}

async function writeJiraObject({ jira, token, path, method, body, action, target }) {
  const exBaseUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(jira.cloudId)}/jsm/assets/workspace/${encodeURIComponent(jira.workspaceId)}/v1`;
  const insightBaseUrl = `https://api.atlassian.com/jsm/insight/workspace/${encodeURIComponent(jira.workspaceId)}/v1`;
  return fetchJiraJsonWithAuthFallbacks({
    attempts: [
      { label: "Basic Auth contra api.atlassian.com Assets", url: `${exBaseUrl}${path}`, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com Assets", url: `${exBaseUrl}${path}`, auth: "bearer" },
      { label: "Basic Auth contra api.atlassian.com Insight", url: `${insightBaseUrl}${path}`, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com Insight", url: `${insightBaseUrl}${path}`, auth: "bearer" },
    ],
    email: jira.email,
    token,
    action,
    method,
    body,
    errorDetailDecorator: (detail) => decorateJiraAttributeErrorDetail(detail, target, body?.attributes),
  });
}

function decorateJiraAttributeErrorDetail(detail, target, submittedAttributes = []) {
  if (!detail || !target?.attributes?.length) return detail;
  let decorated = String(detail);
  const attributesById = new Map(target.attributes.map((attribute) => [String(attribute.id), attribute]));
  const submittedById = new Map((submittedAttributes ?? []).map((attribute) => [String(attribute.objectTypeAttributeId), attribute]));
  const referencedIds = new Set([...decorated.matchAll(/rlabs-insight-attribute-(\d+)/g)].map((match) => match[1]));
  for (const id of referencedIds) {
    const attribute = attributesById.get(id);
    if (!attribute) continue;
    const submitted = submittedById.get(id);
    const submittedValues = (submitted?.objectAttributeValues ?? []).map((item) => item?.value).filter((value) => value != null);
    const valueDetail = submittedValues.length ? ` Valor enviado: ${submittedValues.map((value) => JSON.stringify(String(value))).join(", ")}.` : " Valor enviado: vacio.";
    decorated += ` Atributo Jira afectado: ${attribute.name} (ID ${id}${attribute.type ? `, tipo ${attribute.type}` : ""}).${valueDetail}`;
  }
  return decorated;
}

function formatServerDate(date) {
  const pad = (value) => value.toString().padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

async function validateJiraAssetsConnectionInputs({ url, cloudId, workspaceId, email, token }) {
  const discovery = await discoverJiraAssetsWorkspaces({ url, cloudId, email, token });
  const tenantCloudId = discovery.tenantCloudId;
  if (tenantCloudId && tenantCloudId !== cloudId) {
    throw new Error(
      `Cloud ID no coincide con el tenant. Configurado: ${cloudId}. /_edge/tenant_info devuelve: ${tenantCloudId}. Usa ese Cloud ID para este Jira.`
    );
  }

  const workspaces = discovery.workspaces.map((workspace) => workspace.workspaceId).filter(Boolean);
  if (workspaces.length && !workspaces.includes(workspaceId)) {
    throw new Error(
      `Workspace ID no pertenece a este tenant o no es accesible con esta cuenta. Configurado: ${workspaceId}. Workspaces detectados: ${workspaces.join(", ")}.`
    );
  }

  return {
    tenantCloudId: tenantCloudId || cloudId,
    workspaces,
  };
}

async function discoverJiraAssetsWorkspaces({ url, cloudId, email, token }) {
  const siteUrl = normalizeJiraSiteUrl(url);
  const result = await fetchJiraWorkspaces({ siteUrl, cloudId, email, token });

  return {
    tenantCloudId: cloudId,
    workspaces: result.workspaces,
    authMode: result.label,
  };
}

async function fetchJiraWorkspaces({ siteUrl, cloudId, email, token }) {
  const gatewayUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(cloudId)}/rest/servicedeskapi/assets/workspace`;
  const siteWorkspaceUrl = `${siteUrl}/rest/servicedeskapi/assets/workspace`;
  const result = await fetchJiraJsonWithAuthFallbacks({
    attempts: [
      { label: "Basic Auth contra URL del tenant", url: siteWorkspaceUrl, auth: "basic" },
      { label: "Bearer token contra URL del tenant", url: siteWorkspaceUrl, auth: "bearer" },
      { label: "Basic Auth contra api.atlassian.com", url: gatewayUrl, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com", url: gatewayUrl, auth: "bearer" },
    ],
    email,
    token,
    action: "leer workspaces de Assets",
  });
  return {
    label: result.label,
    workspaces: normalizeJiraWorkspaces(result.payload.raw),
  };
}

function normalizeJiraWorkspaces(payload) {
  return extractArray(payload)
    .map((item) => {
      const workspaceId = String(item.workspaceId ?? item.id ?? "");
      return {
        workspaceId,
        name: String(item.name ?? item.workspaceName ?? item.displayName ?? workspaceId),
      };
    })
    .filter((workspace) => workspace.workspaceId);
}

function trimForError(value) {
  return String(value).replace(/\s+/g, " ").slice(0, 700);
}

async function fetchJiraJsonWithAuthFallbacks({ attempts, email, token, action, errorFactory, method = "GET", body, errorDetailDecorator }) {
  const basicAuth = `Basic ${Buffer.from(`${email}:${token}`).toString("base64")}`;
  const failures = [];
  const validationFailures = [];

  for (const attempt of attempts) {
    const response = await fetchJiraResponseWithRetries({
      url: attempt.url,
      method,
      headers: {
        Authorization: attempt.auth === "bearer" ? `Bearer ${token}` : basicAuth,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body,
    });
    const payload = await readJsonResponse(response);
    if (response.ok) {
      return { label: attempt.label, payload };
    }
    const detail = payload.detail ? trimForError(errorDetailDecorator ? errorDetailDecorator(payload.detail) : payload.detail) : "";
    failures.push(`${attempt.label} ${attempt.url}: HTTP ${response.status}${detail ? ` (${detail})` : ""}`);
    if (response.status === 400) {
      validationFailures.push(`${attempt.label}: ${detail || "Jira Assets rechazo los datos enviados."}`);
    }
    if (errorFactory && attempts.length === 1) {
      throw new Error(errorFactory(response.status, payload.detail));
    }
  }

  if (validationFailures.length) {
    throw new Error(`No se pudo ${action} porque Jira Assets rechazo los datos enviados: ${validationFailures[0]}.`);
  }

  throw new Error(
    `No se pudo ${action}. Probados: ${failures.join(" | ")}. Si usas un API token con scopes, Atlassian exige api.atlassian.com/ex/jira/{cloudId}; si usas token sin scopes, suele funcionar contra la URL del tenant. Revisa tambien que la cuenta tenga acceso a Jira Service Management y Assets.`
  );
}

async function fetchJiraResponseWithRetries({ url, method, headers, body }) {
  let response;
  let lastError;
  const externalSignal = syncContextStorage.getStore()?.signal;
  for (let attempt = 1; attempt <= Math.max(1, JIRA_RETRY_ATTEMPTS); attempt += 1) {
    if (externalSignal?.aborted) {
      throw new Error("Operacion cancelada por el usuario antes de llamar a Jira/Atlassian.");
    }
    const controller = new AbortController();
    const abortFromExternalSignal = () => controller.abort();
    externalSignal?.addEventListener("abort", abortFromExternalSignal, { once: true });
    const timeout = setTimeout(() => controller.abort(), JIRA_REQUEST_TIMEOUT_MS);
    try {
      response = await fetch(url, {
        method,
        headers,
        signal: controller.signal,
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch (error) {
      lastError = error;
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abortFromExternalSignal);
      if (externalSignal?.aborted) {
        throw new Error("Operacion cancelada por el usuario durante una llamada a Jira/Atlassian.");
      }
      if (attempt >= JIRA_RETRY_ATTEMPTS) {
        const timeoutDetail = error?.name === "AbortError" ? `timeout de ${JIRA_REQUEST_TIMEOUT_MS} ms` : sanitizeLdapError(error);
        throw new Error(`No se recibio respuesta de Jira/Atlassian (${timeoutDetail}) al llamar ${url}.`);
      }
      await sleep(Math.min(1000 * 2 ** (attempt - 1), 8000));
      continue;
    } finally {
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abortFromExternalSignal);
    }
    if (![429, 502, 503, 504].includes(response.status) || attempt >= JIRA_RETRY_ATTEMPTS) return response;
    await response.arrayBuffer().catch(() => undefined);
    await sleep(getRetryDelayMs(response, attempt));
  }
  if (lastError) throw lastError;
  return response;
}

async function testNutanixConnection({ prismUrl, username, password }) {
  const baseUrl = normalizeNutanixPrismUrl(prismUrl);
  const auth = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
  const attempts = [
    {
      label: "Prism Central v3 clusters/list",
      url: `${baseUrl}/api/nutanix/v3/clusters/list`,
      method: "POST",
      body: { kind: "cluster", length: 100 },
    },
    {
      label: "Prism v2 cluster",
      url: `${baseUrl}/PrismGateway/services/rest/v2.0/cluster`,
      method: "GET",
    },
  ];
  const failures = [];

  for (const attempt of attempts) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(process.env.NUTANIX_REQUEST_TIMEOUT_MS || 15000));
    let response;
    try {
      response = await fetch(attempt.url, {
        method: attempt.method,
        headers: {
          Authorization: auth,
          Accept: "application/json",
          ...(attempt.body ? { "Content-Type": "application/json" } : {}),
        },
        signal: controller.signal,
        ...(attempt.body ? { body: JSON.stringify(attempt.body) } : {}),
      });
    } catch (error) {
      clearTimeout(timeout);
      failures.push(`${attempt.label}: ${explainNutanixNetworkError(error)}`);
      continue;
    } finally {
      clearTimeout(timeout);
    }

    const payload = await readJsonResponse(response);
    if (response.ok) {
      return {
        endpoint: attempt.label,
        clusters: extractNutanixClusterNames(payload.raw),
      };
    }
    failures.push(`${attempt.label}: HTTP ${response.status} (${trimForError(payload.detail || response.statusText)})`);
  }

  throw new Error(`No se pudo validar la conexion con Nutanix Prism Central. Probados: ${failures.join(" | ")}.`);
}

function normalizeNutanixPrismUrl(url) {
  const parsed = new URL(String(url));
  if (!["https:", "http:"].includes(parsed.protocol)) {
    throw new Error("La URL de Nutanix debe usar https://, por ejemplo https://prism.empresa.local:9440.");
  }
  if (parsed.protocol !== "https:" && process.env.ALLOW_INSECURE_NUTANIX_HTTP !== "true") {
    throw new Error("La URL de Nutanix debe usar HTTPS. Define ALLOW_INSECURE_NUTANIX_HTTP=true solo en laboratorio si necesitas HTTP.");
  }
  if (!parsed.hostname) throw new Error("La URL de Nutanix debe incluir host.");
  return `${parsed.protocol}//${parsed.host}`;
}

function explainNutanixNetworkError(error) {
  if (error?.name === "AbortError") return "timeout de conexion";
  const message = sanitizeLdapError(error);
  if (message.includes("self-signed certificate") || message.includes("certificate")) {
    return `${message}. Revisa el certificado TLS de Prism Central o instala una CA valida en el contenedor app.`;
  }
  return message;
}

function extractNutanixClusterNames(payload) {
  const candidates = [
    ...(payload && typeof payload === "object" && !Array.isArray(payload) ? [payload] : []),
    ...(Array.isArray(payload?.entities) ? payload.entities : []),
    ...(Array.isArray(payload?.cluster_uuid) ? payload.cluster_uuid : []),
    ...(Array.isArray(payload) ? payload : []),
  ];
  const names = candidates
    .map((item) => String(item?.spec?.name ?? item?.status?.name ?? item?.name ?? item?.cluster_name ?? ""))
    .filter(Boolean);
  return [...new Set(names)].sort((a, b) => a.localeCompare(b, "es"));
}

function getRetryDelayMs(response, attempt) {
  const retryAfter = Number(response.headers.get("retry-after") ?? response.headers.get("beta-retry-after"));
  const baseDelay = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 1000 * 2 ** (attempt - 1);
  const jitter = 0.7 + Math.random() * 0.6;
  return Math.min(Math.round(baseDelay * jitter), 30000);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function mapWithConcurrency(items, concurrency, mapper) {
  const limit = Math.max(1, Number(concurrency) || 1);
  const results = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

async function fetchJiraAssetsSchemas({ cloudId, workspaceId, email, token }) {
  const baseUrl = `https://api.atlassian.com/ex/jira/${encodeURIComponent(cloudId)}/jsm/assets/workspace/${encodeURIComponent(workspaceId)}/v1`;
  const schemaPayload = await fetchJiraJsonWithAuthFallbacks({
    attempts: [
      { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/objectschema/list`, auth: "basic" },
      { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/objectschema/list`, auth: "bearer" },
    ],
    email,
    token,
    action: "leer esquemas de Assets",
    errorFactory: (status, detail) => explainJiraAssetsSchemaError(status, detail, { cloudId, workspaceId }),
  });

  const schemas = extractArray(schemaPayload.payload.raw)
    .map((schema) => ({
      id: String(schema.id ?? schema.objectSchemaId ?? ""),
      name: String(schema.name ?? schema.objectSchemaKey ?? schema.id ?? "Esquema sin nombre"),
      objectTypes: [],
    }))
    .filter((schema) => schema.id);

  return mapWithConcurrency(
    schemas,
    Number(process.env.JIRA_SCHEMA_CONCURRENCY || 2),
    async (schema) => {
      const typePayload = await fetchJiraJsonWithAuthFallbacks({
        attempts: [
          { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/objectschema/${encodeURIComponent(schema.id)}/objecttypes/flat`, auth: "basic" },
          { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/objectschema/${encodeURIComponent(schema.id)}/objecttypes/flat`, auth: "bearer" },
        ],
        email,
        token,
        action: `leer tipos del esquema ${schema.name}`,
      });
      const objectTypes = extractArray(typePayload.payload.raw)
        .map((type) => ({
          id: String(type.id ?? type.objectTypeId ?? ""),
          name: String(type.name ?? type.label ?? type.id ?? ""),
          attributes: [],
        }))
        .filter((type) => type.id && type.name)
        .sort((a, b) => a.name.localeCompare(b.name, "es"));

      const objectTypesWithAttributes = await mapWithConcurrency(
        objectTypes,
        Number(process.env.JIRA_ATTRIBUTE_CONCURRENCY || 4),
        async (type) => {
          const attributePayload = await fetchJiraJsonWithAuthFallbacks({
            attempts: [
              { label: "Basic Auth contra api.atlassian.com", url: `${baseUrl}/objecttype/${encodeURIComponent(type.id)}/attributes`, auth: "basic" },
              { label: "Bearer token contra api.atlassian.com", url: `${baseUrl}/objecttype/${encodeURIComponent(type.id)}/attributes`, auth: "bearer" },
            ],
            email,
            token,
            action: `leer atributos del tipo ${type.name}`,
          });
          return {
            ...type,
            attributes: extractArray(attributePayload.payload.raw)
              .map((attribute) => ({
                id: String(attribute.id ?? attribute.objectTypeAttributeId ?? ""),
                name: String(attribute.name ?? attribute.label ?? attribute.id ?? ""),
                editable: attribute.editable !== false,
                system: Boolean(attribute.system),
                required: Number(attribute.minimumCardinality ?? attribute.minCardinality ?? 0) > 0,
                label: Boolean(attribute.label === true),
              }))
              .filter((attribute) => attribute.id && attribute.name)
              .sort((a, b) => a.name.localeCompare(b.name, "es")),
          };
        }
      );

      return {
        ...schema,
        objectTypes: objectTypesWithAttributes,
      };
    }
  );
}

async function readJsonResponse(response) {
  const text = await response.text();
  if (!text) return { raw: null, detail: "" };
  try {
    return { raw: JSON.parse(text), detail: text };
  } catch {
    const contentType = response.headers.get("content-type") ?? "";
    const looksHtml = contentType.includes("text/html") || /^\s*</.test(text);
    const detail = looksHtml
      ? `Respuesta no JSON recibida de Jira/Atlassian: HTTP ${response.status} ${response.statusText}. Content-Type: ${contentType || "desconocido"}. Inicio de respuesta: ${trimForError(stripHtmlForError(text))}`
      : `Respuesta no JSON recibida de Jira/Atlassian: HTTP ${response.status} ${response.statusText}. Inicio de respuesta: ${trimForError(text)}`;
    return { raw: null, detail };
  }
}

function stripHtmlForError(value) {
  return String(value).replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ");
}

function extractArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.values)) return payload.values;
  if (Array.isArray(payload?.objectSchemaEntries)) return payload.objectSchemaEntries;
  if (Array.isArray(payload?.objectTypeEntries)) return payload.objectTypeEntries;
  if (Array.isArray(payload?.entries)) return payload.entries;
  return [];
}

function normalizeJiraSiteUrl(url) {
  const parsed = new URL(String(url));
  if (parsed.protocol !== "https:") {
    throw new Error("La URL Jira debe usar HTTPS, por ejemplo https://tenant.atlassian.net.");
  }
  if (!parsed.hostname.endsWith(".atlassian.net")) {
    throw new Error("La URL Jira debe pertenecer a un tenant de Atlassian Cloud (*.atlassian.net).");
  }
  return `${parsed.protocol}//${parsed.hostname}`;
}

function validateLdapConnectionUrl(url) {
  const parsed = new URL(String(url));
  if (!["ldap:", "ldaps:"].includes(parsed.protocol)) {
    throw new Error("La URL de Active Directory debe usar ldap:// o ldaps://.");
  }
  if (!parsed.hostname) {
    throw new Error("La URL de Active Directory debe incluir un host.");
  }
  const port = Number(parsed.port || (parsed.protocol === "ldaps:" ? 636 : 389));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("La URL de Active Directory tiene un puerto no valido.");
  }
}

function explainJiraAssetsSchemaError(status, detail, { cloudId, workspaceId }) {
  if (status === 404 && String(detail).includes("getting tcs sharding record")) {
    return `Jira Assets devolvio 404 al leer esquemas porque Atlassian no encuentra el registro de tenant para el Cloud ID indicado. Revisa el Cloud ID: ${cloudId}. Obtenlo de https://tunombredetenant.atlassian.net/_edge/tenant_info y confirma que el Workspace ID ${workspaceId} pertenece al mismo tenant. Detalle tecnico: ${detail}`;
  }
  return explainJiraHttpError(status, "leer esquemas de Assets", detail);
}

function explainJiraHttpError(status, action, detail) {
  if (status === 401) {
    return `Jira devolvio 401 al ${action}. La autenticacion ha sido rechazada. Si /rest/api/3/myself funciona con el mismo usuario/password, revisa que la cuenta tenga acceso a Jira Service Management/Assets.`;
  }
  if (status === 403) {
    return `Jira devolvio 403 al ${action}. La cuenta/token autentica, pero no tiene permisos o scopes suficientes para Assets. Revisa read:cmdb-schema:jira, read:cmdb-type:jira, read:cmdb-attribute:jira y read:servicedesk-request.`;
  }
  if (status === 404) {
    return `Jira devolvio 404 al ${action}. Revisa que Cloud ID, Workspace ID y URL Jira pertenezcan al mismo tenant. Detalle tecnico: ${detail}`;
  }
  return `Jira devolvio ${status} al ${action}: ${detail}`;
}

function domainToBaseDn(domain) {
  return String(domain)
    .split(".")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => `DC=${part}`)
    .join(",");
}

function encryptSecret(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

function decryptSecret(value) {
  return decryptSecretWithMetadata(value).value;
}

function decryptSecretWithMetadata(value) {
  if (!value || typeof value !== "string") return { value: "", usingCurrentKey: false };
  const [version, iv, tag, encrypted] = value.split(":");
  if (version !== "v1" || !iv || !tag || !encrypted) return { value: "", usingCurrentKey: false };
  const keys = [encryptionKey, ...previousEncryptionKeys];
  for (const [index, key] of keys.entries()) {
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
      decipher.setAuthTag(Buffer.from(tag, "base64"));
      return {
        value: Buffer.concat([decipher.update(Buffer.from(encrypted, "base64")), decipher.final()]).toString("utf8"),
        usingCurrentKey: index === 0,
      };
    } catch {
      // Try next configured key.
    }
  }
  return { value: "", usingCurrentKey: false };
}

function deriveEncryptionKey(secret) {
  return crypto.createHash("sha256").update(String(secret)).digest();
}

function parseLdapUrl(url) {
  const parsed = new URL(url);
  const secure = parsed.protocol === "ldaps:";
  return {
    host: parsed.hostname,
    port: Number(parsed.port || (secure ? 636 : 389)),
    secure,
  };
}

function testTcpConnectivity(url) {
  return new Promise((resolve) => {
    let target;
    try {
      target = parseLdapUrl(url);
    } catch (error) {
      resolve({ ok: false, detail: `URL LDAP no valida: ${sanitizeLdapError(error)}` });
      return;
    }

    const socket = net.createConnection(target.port, target.host);
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({ ok: false, host: target.host, port: target.port, detail: `Timeout TCP contra ${target.host}:${target.port}` });
    }, 7000);

    socket.once("connect", () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve({ ok: true, host: target.host, port: target.port, protocol: target.secure ? "ldaps" : "ldap" });
    });

    socket.once("error", (error) => {
      clearTimeout(timeout);
      resolve({ ok: false, host: target.host, port: target.port, detail: sanitizeLdapError(error) });
    });
  });
}

function chunkArray(items, size) {
  const chunks = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

function buildOuTree(domain, baseDn, ouDns) {
  const root = {
    dn: baseDn,
    name: domain,
    children: [],
  };
  const nodes = new Map([[baseDn.toLowerCase(), root]]);

  ouDns
    .slice()
    .sort((a, b) => dnDepth(a) - dnDepth(b))
    .forEach((dn) => {
      ensureOuNode(dn, baseDn, nodes);
    });

  sortTree(root);
  return [root];
}

function ensureOuNode(dn, baseDn, nodes) {
  const key = dn.toLowerCase();
  if (nodes.has(key)) return nodes.get(key);

  const parentDn = parentDnOf(dn) || baseDn;
  const parent = ensureOuNode(parentDn, baseDn, nodes);
  const node = {
    dn,
    name: rdnValue(dn) || dn,
    children: [],
  };
  parent.children = parent.children || [];
  parent.children.push(node);
  nodes.set(key, node);
  return node;
}

function parentDnOf(dn) {
  const parts = splitDn(dn);
  if (parts.length <= 1) return "";
  return parts.slice(1).join(",");
}

function splitDn(dn) {
  return String(dn).split(/,(?=(?:[^\\]|\\.)*$)/);
}

function rdnValue(dn) {
  const first = splitDn(dn)[0] ?? "";
  const [, value = first] = first.split("=");
  return value.replace(/\\,/g, ",");
}

function dnDepth(dn) {
  return splitDn(dn).length;
}

function sortTree(node) {
  node.children?.sort((a, b) => a.name.localeCompare(b.name, "es"));
  node.children?.forEach(sortTree);
}

function sanitizeLdapError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return redactSecrets(message);
}

function redactSecrets(value) {
  return String(value)
    .replace(/password=[^,\s&]+/gi, "password=***")
    .replace(/token=[^,\s&]+/gi, "token=***")
    .replace(/apiToken["':=\s]+[^"',\s}]+/gi, "apiToken=***")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer ***")
    .replace(/Basic\s+[A-Za-z0-9+/=]+/gi, "Basic ***");
}

function explainLdapError(error, url) {
  const message = sanitizeLdapError(error);
  if (message.includes("ECONNRESET")) {
    const { secure, port } = parseLdapUrl(url);
    const alternative = secure || port === 636 ? "ldap://<dc>:389" : "ldaps://<dc>:636";
    return `${message}. La conexion TCP abre, pero el servidor la resetea durante LDAP/TLS. Revisa si el puerto/protocolo coincide (${url}); prueba ${alternative}, valida firewall y que LDAPS este habilitado en el controlador de dominio.`;
  }
  return message;
}

const distPath = path.resolve(__dirname, "../dist");
app.use((err, _req, res, _next) => {
  console.error("Unhandled request error:", redactSecrets(err instanceof Error ? err.stack || err.message : err));
  if (res.headersSent) return;
  if (err?.type === "entity.too.large") {
    res.status(413).json({ error: "payload_too_large", detail: "La peticion supera el tamano maximo permitido." });
    return;
  }
  if (err instanceof SyntaxError) {
    res.status(400).json({ error: "invalid_json", detail: "El cuerpo JSON no es valido." });
    return;
  }
  res.status(500).json({ error: "internal_error", detail: "Error interno del servidor." });
});
app.use(express.static(distPath, {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith("index.html")) {
      res.setHeader("Cache-Control", "no-store");
      return;
    }
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  },
}));
app.get("*", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(distPath, "index.html"));
});

initDb()
  .then(() => {
    startJiraCatalogRefreshTask();
    startMappingSchedulerTask();
    app.listen(port, "0.0.0.0", () => {
      console.log(`Nexus CMDB listening on ${port}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed", error);
    process.exit(1);
  });
