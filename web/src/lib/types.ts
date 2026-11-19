// Shapes of the controller's REST API (crates/df2b-controller/src/api.rs).

export type Role = 'viewer' | 'operator' | 'admin';

export interface Me {
  name: string;
  role: Role;
  auth: 'session' | 'token';
  method: 'password' | 'oidc' | 'token';
  csrf_token: string | null;
  must_change_password: boolean;
}

export interface AuthMethods {
  password: boolean;
  oidc: { name: string } | null;
}

export type Scope =
  | { type: 'global' }
  | { type: 'group'; value: string }
  | { type: 'agents'; value: string[] };

export type Origin = { type: 'agent' | 'user' | 'correlation'; value: string };

export interface Decision {
  seq: number;
  id: string;
  kind: { kind: 'ban' } | { kind: 'unban'; revokes: string } | { kind: string };
  target: string;
  scope: Scope;
  jail: string | null;
  created_at: string;
  expires_at: string | null;
  origin: Origin;
  reason: string;
}

export interface AgentStatus {
  last_seen: string | null;
  agent_version: string;
  active_bans: number;
  clock_skew_ms: number;
  firewall_backend: string;
  firewall_healthy: boolean;
  last_applied_seq: number;
  streams: number;
  allowlist_version: string;
}

export interface Agent {
  id: string;
  hostname: string;
  group: string;
  enrolled_at: string;
  serials: string[];
  cert_not_after: string;
  connected: boolean;
  revoked: boolean;
  status: AgentStatus;
}

export interface Status {
  version: string;
  agents: { total: number; connected: number; revoked: number };
  active_decisions: number;
  last_seq: number;
  propagate: string;
  allowlist: string[];
  allowlist_version: string;
  sessions: number;
  /** configured GeoIP databases */
  geoip: { path: string; database_type: string; build: string | null; error?: string }[];
}

/** ASN/country of an address (GeoIP databases on the controller) */
export interface GeoInfo {
  asn?: number;
  as_org?: string;
  country?: string;
  country_name?: string;
}

export interface Count {
  key: string;
  count: number;
  /** shown instead of the key */
  label?: string;
  title?: string;
}

export interface Stats {
  bans_per_hour: { hour: string; count: number }[];
  active: { total: number; ipv4: number; ipv6: number; permanent: number };
  top_jails: Count[];
  top_prefixes: Count[];
  top_origins: Count[];
  geoip: boolean;
  top_asns: { asn: number; org: string | null; count: number }[];
  top_countries: { country: string; name: string | null; count: number }[];
}

export interface History {
  target: string;
  geo: GeoInfo | null;
  allowlisted: boolean;
  allow_entries: { net: string; expires_at: string | null }[];
  correlation_offenses: number;
  offense_memory: string;
  observations: { jail: string; key: string; agent: string; at: string; failures: number; banned: boolean }[];
  /** log lines agents sent with their reports, newest first */
  samples: { jail: string; key: string; agent: string; at: string; line: string }[];
  active: Decision[];
  history: Decision[];
}

export interface AuditEntry {
  seq: number;
  time: string;
  actor: string;
  remote_addr: string | null;
  action: string;
  details: Record<string, unknown>;
}

export interface SessionInfo {
  id: string;
  user: string;
  method: 'password' | 'oidc';
  role: Role | null;
  created_at: string;
  last_used_at: string;
  expires_at: string;
  remote_addr: string | null;
  user_agent: string | null;
  current: boolean;
}

export interface UserInfo {
  name: string;
  role: Role;
  created_at: string;
  password_changed_at: string;
  must_change_password: boolean;
  sessions: number;
}

export interface TokenInfo {
  name: string;
  role: Role;
  created_at: string;
  created_by: string | null;
  expires_at: string | null;
  expired: boolean;
  last_used_at: string | null;
  current: boolean;
}

export interface AllowEntry {
  net: string;
  source: 'command line' | 'api';
  comment: string;
  created_by: string | null;
  created_at: string | null;
  expires_at: string | null;
  active_bans: number;
}

export type Propagate = 'global' | 'group' | 'off';

export interface JailView {
  name: string;
  filter: string;
  enabled: boolean;
  maxretry: number;
  findtime_secs: number;
  bantime_secs: number;
  bantime_factor: number;
  max_bantime_secs: number;
  overridden: string[];
  active_bans: number;
  origin: 'local' | 'central' | '';
  error: string;
}

export interface JailSettings {
  enabled?: boolean;
  maxretry?: number;
  findtime?: string;
  bantime?: string;
  bantime_factor?: number;
  max_bantime?: string;
}

export interface JailOverride extends JailSettings {
  jail: string;
  group: string | null;
  updated_by: string;
  updated_at: string;
}

export interface JailInfo {
  name: string;
  filters: string[];
  agents: { agent: string; group: string; connected: boolean; jail: JailView }[];
  overrides: JailOverride[];
}

export interface Policies {
  propagate: Propagate;
  jails: JailInfo[];
  groups: string[];
}

export type SourceDef =
  | { type: 'file'; paths: string[]; start_at_end: boolean }
  | { type: 'journald'; matches: string[]; start: string | null };

export interface JailDefinition {
  name: string;
  group: string | null;
  filter: string;
  sources: SourceDef[];
  enabled: boolean;
  maxretry: number;
  findtime: string;
  bantime: string;
  bantime_factor: number;
  max_bantime: string | null;
  updated_by: string;
  updated_at: string;
  filter_is_central: boolean;
}

export interface CentralFilter {
  name: string;
  toml: string;
  updated_by: string;
  updated_at: string;
  used_by: string[];
}

export interface CorrelationRule {
  name: string;
  kind: 'threshold' | 'quorum';
  jail: string | null;
  group: string | null;
  min_agents: number;
  min_failures: number;
  window: string;
  bantime: string;
  bantime_factor: number;
  max_bantime?: string;
  enabled: boolean;
  monitor: boolean;
  updated_by: string;
  updated_at: string;
}

export interface CorrelationHit {
  rule: string;
  jail: string;
  target: string;
  failures: number;
  agents: string[];
  at: string;
}

/** a rule that rewrites sample log lines on the controller */
export interface RedactRule {
  name: string;
  pattern: string;
  replace: string;
  enabled: boolean;
}

export interface RedactPreset {
  name: string;
  description: string;
  pattern: string;
  replace: string;
}
