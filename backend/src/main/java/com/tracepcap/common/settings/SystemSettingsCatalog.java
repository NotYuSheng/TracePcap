package com.tracepcap.common.settings;

import java.util.List;

/**
 * Every deploy-time setting the System settings view lists (#915 phase 1). Generated from
 * {@code application.yml} (property path, environment variable, default) and the descriptions in
 * {@code docs/configuration/environment-variables.rst}. SystemSettingsCatalogTest fails when a
 * {@code ${ENV}} placeholder in application.yml is missing here, so the list can't silently drift.
 */
final class SystemSettingsCatalog {

  private SystemSettingsCatalog() {}

  /** Who may change a setting, and therefore why the UI greys it out. */
  enum Group {
    /** Infrastructure and secrets: set in .env, needs a redeploy. Secrets are never shown. */
    INFRASTRUCTURE,
    /** Tied to memory sizing: set in .env; a wrong value can crash the backend. */
    MEMORY,
    /** Analysis policy: editable in the app in a later phase of #915; .env for now. */
    POLICY
  }

  /**
   * @param env the environment variable
   * @param property the Spring property it binds, or null when only the container entrypoint reads it
   * @param defaultValue the default when the variable isn't set
   * @param secret never return the value, only whether it's set
   */
  record Entry(
      String env,
      String property,
      String defaultValue,
      Group group,
      boolean secret,
      String label,
      String description) {}

  static final List<Entry> ENTRIES =
      List.of(
      new Entry("APP_MEMORY_MB", null, "2048", Group.MEMORY, false, "App memory MB",
          "Memory budget for the backend. The JVM heap, upload cap and JSON size limit are all derived from it."),
      new Entry("SPRING_PROFILES_ACTIVE", "spring.profiles.active", "dev", Group.INFRASTRUCTURE, false, "Spring profiles active",
          "prod enforces strict CORS, disables Swagger + /v3/api-docs, suppresses stacktraces/exception details in error responses, and logs at WARN to a file."),
      new Entry("DATABASE_URL", "spring.datasource.url", "jdbc:postgresql://localhost:5432/tracepcap", Group.INFRASTRUCTURE, false, "Database URL",
          "JDBC URL of the PostgreSQL database."),
      new Entry("DATABASE_USERNAME", "spring.datasource.username", "tracepcap_user", Group.INFRASTRUCTURE, false, "Database username",
          "Database user."),
      new Entry("DATABASE_PASSWORD", "spring.datasource.password", "tracepcap_pass", Group.INFRASTRUCTURE, true, "Database password",
          "Database password."),
      new Entry("DB_POOL_MAX_SIZE", "spring.datasource.hikari.maximum-pool-size", "20", Group.MEMORY, false, "DB pool max size",
          "Maximum database connections. Keep at least 2 × ASYNC_CORE_POOL_SIZE + 5; the backend warns at startup otherwise."),
      new Entry("DB_POOL_MIN_IDLE", "spring.datasource.hikari.minimum-idle", "5", Group.MEMORY, false, "DB pool min idle",
          "Database connections kept open when idle."),
      new Entry("MAX_UPLOAD_SIZE_BYTES", "spring.servlet.multipart.max-file-size", "536870912", Group.MEMORY, false, "Max upload size bytes",
          "Largest capture accepted for upload. Derived from APP_MEMORY_MB by default, so the parser has room to process it."),
      new Entry("MAX_UPLOAD_PACKETS", "app.max-packets", "2000000", Group.MEMORY, false, "Max upload packets",
          "Most packets accepted in a single capture. A provisioning contract, not a hard technical ceiling: packet count is the dominant driver of database row counts, and those drive how much parallel-query shared memory Postgres needs in /dev/shm. Over-limit captures are rejected gracefully at upload (HTTP 413) rather than failing mid-analysis. Set 0 to disable the check. Raise it together with POSTGRES_SHM_SIZE / POSTGRES_WORK_MEM below to support larger captures."),
      new Entry("MAX_UPLOAD_PACKETS_VERIFY_FRACTION", "app.max-packets-verify-fraction", "0.5", Group.MEMORY, false, "Max upload packets verify fraction",
          "Behaviour when capinfos can't produce a packet count (timeout/error). The gate fails closed (rejects) for files at or above this fraction of the max upload size — an unverifiable large capture is exactly the case the gate exists to stop — and fails open (allows) for smaller files, which can't hold a dangerous packet count. Set >= 1.0 for pure fail-open."),
      new Entry("MINIO_ENDPOINT", "minio.endpoint", "http://localhost:9000", Group.INFRASTRUCTURE, false, "MinIO endpoint",
          "Address of the MinIO object store holding captures and extracted files."),
      new Entry("MINIO_ACCESS_KEY", "minio.access-key", "minioadmin", Group.INFRASTRUCTURE, true, "MinIO access key",
          "MinIO access key."),
      new Entry("MINIO_SECRET_KEY", "minio.secret-key", "minioadmin", Group.INFRASTRUCTURE, true, "MinIO secret key",
          "MinIO secret key."),
      new Entry("MINIO_BUCKET", "minio.bucket", "tracepcap-files", Group.INFRASTRUCTURE, false, "MinIO bucket",
          "MinIO bucket for captures and extracted files."),
      new Entry("SERVER_PORT", "server.port", "8080", Group.INFRASTRUCTURE, false, "Server port",
          "Port the backend listens on inside its container."),
      new Entry("ASYNC_CORE_POOL_SIZE", "async.core-pool-size", "5", Group.MEMORY, false, "Async core pool size",
          "Number of threads kept alive to run analyses. These stay up even when idle. This is also how many analyses run at once, because extra threads up to ASYNC_MAX_POOL_SIZE start only once ASYNC_QUEUE_CAPACITY is full. Each running analysis holds two database connections, so keep DB_POOL_MAX_SIZE at least 2 x ASYNC_CORE_POOL_SIZE + 5. The backend logs a warning at startup when it is smaller."),
      new Entry("ASYNC_MAX_POOL_SIZE", "async.max-pool-size", "10", Group.MEMORY, false, "Async max pool size",
          "Maximum analysis threads. Keep at or below the host CPU core count — analysis is CPU-bound (Suricata), so oversubscribing degrades throughput."),
      new Entry("ASYNC_QUEUE_CAPACITY", "async.queue-capacity", "100", Group.MEMORY, false, "Async queue capacity",
          "Files that may wait in the in-memory queue once all threads are busy. Once the queue is also full, uploads apply back-pressure (run analysis inline). This queue is not persisted — pending work is lost on restart and recovered as FAILED by reconciliation."),
      new Entry("CORS_ALLOWED_ORIGINS", "cors.allowed-origins", "http://localhost:3000,http://localhost:3001,http://localhost:5173,http://localhost:8888", Group.INFRASTRUCTURE, false, "CORS allowed origins",
          "Comma-separated allowed browser origins for /api. Under prod it has no localhost defaults; leave it empty for the same-origin shipped stack (nginx proxies /api, so CORS is never exercised). Set it only when the frontend is hosted on a different origin from the API."),
      new Entry("LLM_API_BASE_URL", "llm.api.base-url", "https://api.openai.com/v1", Group.INFRASTRUCTURE, false, "LLM API base URL",
          "Base URL of an OpenAI-compatible inference API. See llm-setup."),
      new Entry("LLM_API_KEY", "llm.api.api-key", "your-api-key-here", Group.INFRASTRUCTURE, true, "LLM API key",
          "API key sent in the Authorization: Bearer header. Leave empty for local servers that don't require authentication."),
      new Entry("LLM_MODEL", "llm.api.model", "gpt-4", Group.INFRASTRUCTURE, false, "LLM model",
          "Model identifier passed in each API request. Must match a model loaded on your inference server."),
      new Entry("LLM_TEMPERATURE", "llm.api.temperature", "0.7", Group.INFRASTRUCTURE, false, "LLM temperature",
          "Sampling temperature (0.0–2.0). Lower values produce more deterministic output; higher values more creative output."),
      new Entry("LLM_MAX_TOKENS", "llm.api.max-tokens", "2000", Group.INFRASTRUCTURE, false, "LLM max tokens",
          "Maximum number of tokens the LLM may generate per response. Controls response length only — not the context window. Increase if stories are cut off; decrease to save compute. Recommended 4000–8000."),
      new Entry("LLM_CONTEXT_LENGTH", "llm.api.context-length", null, Group.INFRASTRUCTURE, false, "LLM context length",
          "The context window size (in tokens) configured on your LLM server. Used to detect prompt-too-large errors early. If unset, auto-detected from the /v1/models endpoint; if that fails, the configured LLM_MAX_TOKENS value remains in effect. Example: 32768 for a 32k model."),
      new Entry("LLM_TIMEOUT", "llm.api.timeout-seconds", "300", Group.INFRASTRUCTURE, false, "LLM timeout",
          "HTTP timeout in seconds for LLM API requests. Local models can be slow — increase if you get timeout errors."),
      new Entry("LLM_TOOL_CALLING", "llm.api.tool-calling", "auto", Group.INFRASTRUCTURE, false, "LLM tool calling",
          "Whether Story mode's investigation phase declares its query as a native tool, so the server constrains generation to the real schema instead of letting the model free-type JSON. auto offers tools once and remembers whether the server accepted them; on always offers them; off never does and uses the free-text JSON path. Support varies by backend — leave on auto unless a server misreports its capabilities."),
      new Entry("TRACEPCAP_AUTH_ENABLED", "tracepcap.auth.enabled", "false", Group.INFRASTRUCTURE, false, "TracePcap auth enabled",
          "Gates the API behind a Keycloak JWT and adds a login flow. Set to true by the production overlays; you rarely set it directly. See authentication."),
      new Entry("KEYCLOAK_ISSUER_URI", "tracepcap.auth.issuer-uri", null, Group.INFRASTRUCTURE, false, "Keycloak issuer URI",
          "OIDC issuer (Keycloak realm) used when login is on."),
      new Entry("KEYCLOAK_JWK_SET_URI", "tracepcap.auth.jwk-set-uri", null, Group.INFRASTRUCTURE, false, "Keycloak JWK set URI",
          "Where the backend fetches the login token signing keys; discovered from the issuer when blank."),
      new Entry("SYSTEM_SETTINGS_EDITABLE", "tracepcap.auth.system-settings-editable", "false", Group.INFRASTRUCTURE, false, "System settings editable",
          "With login off, whether actions marked admin-only are allowed for everyone (true) or no one (false). Ignored with login on, where the Keycloak client role admin decides."),
      new Entry("ANALYSIS_TIMEOUT_SECONDS", "tracepcap.analysis.timeout-seconds", "300", Group.MEMORY, false, "Analysis timeout seconds",
          "How long one analysis may run before it is stopped and marked failed."),
      new Entry("SURICATA_ENABLED", "tracepcap.suricata.enabled", "true", Group.POLICY, false, "Suricata enabled",
          "Deployment-wide switch for intrusion-detection enrichment. false skips it for every capture regardless of the per-upload toggle. Adds ~50 s of fixed rule-loading overhead to each capture it processes, on top of packet scanning that scales with size. The fixed floor makes it the biggest throughput lever, and proportionally heaviest on small captures."),
      new Entry("SURICATA_WARM_ENGINE_ENABLED", "tracepcap.suricata.warm-engine.enabled", "true", Group.MEMORY, false, "Suricata warm engine enabled",
          "Keep a Suricata engine running between analyses, so the ruleset is built once rather than per capture."),
      new Entry("SURICATA_WARM_ENGINE_SOCKET", "tracepcap.suricata.warm-engine.socket", "/tmp/tracepcap-suricata/suricata.sock", Group.INFRASTRUCTURE, false, "Suricata warm engine socket",
          "Unix socket of the warm Suricata engine."),
      new Entry("SURICATA_WARM_ENGINE_STARTUP_TIMEOUT", "tracepcap.suricata.warm-engine.startup-timeout-seconds", "180", Group.MEMORY, false, "Suricata warm engine startup timeout",
          "Seconds to wait for the warm Suricata engine to build its ruleset at startup."),
      new Entry("SURICATA_WARM_ENGINE_RUN_TIMEOUT", "tracepcap.suricata.warm-engine.run-timeout-seconds", "600", Group.MEMORY, false, "Suricata warm engine run timeout",
          "Seconds one capture may take in the warm Suricata engine."),
      new Entry("SURICATA_WARM_ENGINE_LOCK_WAIT", "tracepcap.suricata.warm-engine.lock-wait-seconds", "900", Group.MEMORY, false, "Suricata warm engine lock wait",
          "Seconds an analysis waits for its turn on the shared Suricata engine."),
      new Entry("SURICATA_WARM_ENGINE_COMMAND_TIMEOUT", "tracepcap.suricata.warm-engine.command-timeout-seconds", "30", Group.MEMORY, false, "Suricata warm engine command timeout",
          "Seconds to wait for a reply from the warm Suricata engine."),
      new Entry("FILE_RETENTION_ENABLED", "tracepcap.cleanup.enabled", "true", Group.POLICY, false, "File retention enabled",
          "Master switch for automatic deletion. false keeps captures indefinitely and the clean-up scheduler is never registered, so no other retention setting has any effect. See ../operations/production-hardening."),
      new Entry("FILE_RETENTION_HOURS", "tracepcap.cleanup.retention-hours", "12", Group.POLICY, false, "File retention hours",
          "Number of hours after upload before an analysis file is automatically deleted (only applies when FILE_RETENTION_ENABLED=true). Not zero-guarded — 0 deletes everything immediately.  Monitor Network files are exempt and use MONITOR_FILE_RETENTION_HOURS instead."),
      new Entry("MONITOR_FILE_RETENTION_HOURS", "tracepcap.cleanup.monitor-retention-hours", "0", Group.POLICY, false, "Monitor file retention hours",
          "Number of hours before a monitor-mode snapshot file is deleted; 0 (the default) means never. Monitor networks are a time series, so expiring their snapshots destroys the drift history that makes them useful — which is why they are exempt from FILE_RETENTION_HOURS. Monitor mode is consequently where unbounded growth accumulates on a long-lived deployment."),
      new Entry("PACKET_RETENTION_HOURS", "tracepcap.cleanup.packet-retention-hours", "0", Group.POLICY, false, "Packet retention hours",
          "Number of hours after upload before a file's raw packets are pruned, while the file keeps its conversations and analysis results (0 = packets live as long as the file). Packets dominate database size (~1.5–2M rows per GB of PCAP), so setting this below FILE_RETENTION_HOURS reclaims most of the storage early at the cost of packet-level drill-down. Pruning drops the file's packets partition outright, so it is O(1) regardless of size."),
      new Entry("STUCK_FILE_RECONCILIATION_ENABLED", "tracepcap.reconciliation.enabled", "true", Group.POLICY, false, "Stuck file reconciliation enabled",
          "Scheduled job that flips captures stranded in PROCESSING to FAILED after a timeout. Disabling it leaves crashed or restart-interrupted analyses stuck indefinitely."),
      new Entry("STUCK_FILE_TIMEOUT_MINUTES", "tracepcap.reconciliation.timeout-minutes", "30", Group.POLICY, false, "Stuck file timeout minutes",
          "Minutes a file may stay in PROCESSING before reconciliation marks it FAILED. Must exceed the longest expected analysis time so healthy in-flight jobs are never killed."),
      new Entry("OVERVIEW_APPS_LIMITED", "tracepcap.overview.apps-limited", "true", Group.POLICY, false, "Overview apps limited",
          "Cap the number of detected applications shown in the overview. Set to false to show all detected applications regardless of count."),
      new Entry("OVERVIEW_APPS_MAX", "tracepcap.overview.apps-max", "100", Group.POLICY, false, "Overview apps max",
          "Maximum detected applications shown in the overview when OVERVIEW_APPS_LIMITED=true (ranked alphabetically)."),
      new Entry("EXTRACTION_MAX_MATCHES_PER_STREAM", "tracepcap.extraction.max-matches-per-stream", "20", Group.MEMORY, false, "Extraction max matches per stream",
          "Max files extracted from a single raw TCP/UDP stream. Guards against runaway extraction on streams with many magic-byte sequences."),
      new Entry("EXTRACTION_MAX_STREAM_CONVERSATIONS", "tracepcap.extraction.max-stream-conversations", "50", Group.MEMORY, false, "Extraction max stream conversations",
          "Max number of non-HTTP streams scanned for embedded files per PCAP."),
      new Entry("EXTRACTION_MAX_FILE_SIZE_MB", "tracepcap.extraction.max-file-size-mb", "50", Group.MEMORY, false, "Extraction max file size MB",
          "Max size (MB) of a single extracted file that will be stored. Larger files are detected but skipped (shown with a \"Too large\" badge)."),
      new Entry("GEO_ENRICHMENT_ENABLED", "tracepcap.geo.enabled", "true", Group.POLICY, false, "Geo enrichment enabled",
          "Turns geolocation enrichment off entirely — no lookups, no bundled-database resolution, so captures analyzed while it is off get no geo fields. Distinct from GEO_FORCE_OFFLINE, which keeps enrichment but stops it reaching the network. Not retroactive. See Geolocation."),
      new Entry("GEO_MMDB_PATH", "tracepcap.geo.mmdb-path", null, Group.INFRASTRUCTURE, false, "Geo MMDB path",
          "Override the location of the offline MMDB. Empty (the default) uses the DB-IP Lite database bundled in the backend image at /app/geoip/dbip-city-lite.mmdb. Set it only when mounting a newer or commercial MaxMind-format database."),
      new Entry("GEO_FORCE_OFFLINE", "tracepcap.geo.force-offline", "false", Group.POLICY, false, "Geo force offline",
          "Suppresses the ipinfo.io connectivity probe and lookups, resolving geolocation from the bundled database only. Defaults to false in the base stack and true in the offline stack and both production overlays. This is the one intentional outbound call at runtime. See Geolocation."),
      new Entry("INTELLIGENCE_MAX_CLUSTERS", "tracepcap.intelligence.max-clusters", "60", Group.POLICY, false, "Intelligence max clusters",
          "Most clusters drawn in the Network Intelligence view."),
      new Entry("INTELLIGENCE_MAX_EDGES", "tracepcap.intelligence.max-edges", "200", Group.POLICY, false, "Intelligence max edges",
          "Most edges drawn in the Network Intelligence view."),
      new Entry("DNS_NXDOMAIN_SUSPICIOUS_RATIO", "tracepcap.dns.nxdomain-suspicious-ratio", "0.5", Group.POLICY, false, "DNS NXDOMAIN suspicious ratio",
          "Share of failed (NXDOMAIN) DNS lookups above which a host is flagged as suspicious, e.g. DGA malware."),
      new Entry("DNS_NXDOMAIN_MIN_QUERIES", "tracepcap.dns.nxdomain-min-queries", "20", Group.POLICY, false, "DNS NXDOMAIN min queries",
          "DNS queries a host must make before the NXDOMAIN ratio is judged."),
      new Entry("HTTP_CLIENT_ERROR_SUSPICIOUS_RATIO", "tracepcap.http.client-error-suspicious-ratio", "0.5", Group.POLICY, false, "HTTP client error suspicious ratio",
          "Share of HTTP 4xx responses above which a client is flagged as suspicious, e.g. scanning."),
      new Entry("HTTP_MIN_REQUESTS", "tracepcap.http.min-requests", "20", Group.POLICY, false, "HTTP min requests",
          "HTTP requests a client must make before the error ratio is judged."),
      new Entry("JACKSON_MAX_STRING_LENGTH", "tracepcap.jackson.max-string-length", "53477376", Group.MEMORY, false, "Jackson max string length",
          "Largest single JSON string the API accepts (report diagrams). Derived from APP_MEMORY_MB by default."));
}
