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
  sessions: number;
}

export interface Count {
  key: string;
  count: number;
}

export interface Stats {
  bans_per_hour: { hour: string; count: number }[];
  active: { total: number; ipv4: number; ipv6: number; permanent: number };
  top_jails: Count[];
  top_prefixes: Count[];
  top_origins: Count[];
}

export interface History {
  target: string;
  allowlisted: boolean;
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
  active_bans: number;
}
