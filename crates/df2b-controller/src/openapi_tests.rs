//! Keeps `openapi.json` (hand-written) in sync with the router in api.rs:
//! every route and method is described and nothing else, with the role its
//! handler requires; plus basic validity of the document.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

const API_SRC: &str = include_str!("api.rs");
const SPEC: &str = include_str!("../openapi.json");

/// Sources of modules whose `&str` constants are used as route paths.
fn module_src(module: &str) -> &'static str {
    match module {
        "oidc" => include_str!("oidc.rs"),
        m => panic!("route path constant in module {m}: add it to module_src"),
    }
}

/// `crate::oidc::BACKCHANNEL_PATH` → its value.
fn resolve_const(path: &str) -> String {
    let parts: Vec<&str> = path.split("::").collect();
    let [.., module, name] = parts[..] else {
        panic!("cannot resolve route path {path}");
    };
    let src = module_src(module);
    let decl = format!("const {name}: &str = \"");
    let start = src
        .find(&decl)
        .unwrap_or_else(|| panic!("no `{decl}` in {module}.rs"))
        + decl.len();
    let len = src[start..].find('"').expect("closing quote");
    src[start..start + len].to_owned()
}

/// The text up to the parenthesis that closes the one before `s`.
fn balanced(s: &str) -> &str {
    let mut depth = 0;
    let mut in_str = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '(' if !in_str => depth += 1,
            ')' if !in_str => {
                if depth == 0 {
                    return &s[..i];
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    panic!("unbalanced parentheses in {s:.80}");
}

/// The first comma outside parentheses.
fn split_args(s: &str) -> (&str, &str) {
    let mut depth = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => return (&s[..i], &s[i + 1..]),
            _ => {}
        }
    }
    panic!("route without a method router: {s}");
}

const METHODS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

/// `get(a).post(b)` or `axum::routing::put(c).delete(d)` → [(get, a), ...].
fn method_router(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut ident = String::new();
    for (i, c) in s.char_indices() {
        match c {
            '(' => {
                if depth == 0 {
                    let method = ident.rsplit("::").next().unwrap_or_default().to_owned();
                    assert!(
                        METHODS.contains(&method.as_str()),
                        "unexpected call {ident:?} in method router {s}"
                    );
                    let inner = balanced(&s[i + 1..]);
                    let handler = inner.split([',', '(']).next().unwrap().trim().to_owned();
                    out.push((method, handler));
                }
                depth += 1;
                ident.clear();
            }
            ')' => depth -= 1,
            c if c.is_alphanumeric() || c == '_' || c == ':' => ident.push(c),
            _ => ident.clear(),
        }
    }
    assert!(!out.is_empty(), "no methods in {s}");
    out
}

/// `/api/v1/agents/:id` → `/api/v1/agents/{id}`.
fn openapi_path(axum: &str) -> String {
    axum.split('/')
        .map(|seg| match seg.strip_prefix(':') {
            Some(p) => format!("{{{p}}}"),
            None => seg.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The role a handler requires, from its source: `none` without a
/// `Caller`, else the first `require(Role::…)`, else `authenticated`.
fn handler_role(handler: &str) -> String {
    let start = API_SRC
        .find(&format!("async fn {handler}("))
        .unwrap_or_else(|| panic!("handler {handler} not found in api.rs"));
    let rest = &API_SRC[start..];
    let body = &rest[..rest.find("\n}\n").expect("end of handler")];
    let sig = &body[..body.find('{').expect("handler body")];
    if !sig.contains("Caller") {
        return "none".into();
    }
    match body.find(".require(Role::") {
        Some(i) => {
            let role = &body[i + ".require(Role::".len()..];
            role[..role.find(')').unwrap()].to_lowercase()
        }
        None => "authenticated".into(),
    }
}

/// (path, method) → handler, from `router_with_limit`.
fn router_routes() -> BTreeMap<(String, String), String> {
    let start = API_SRC
        .find("pub fn router_with_limit(")
        .expect("router_with_limit");
    let src = &API_SRC[start..];
    let src = &src[src.find("Router::new()").expect("Router::new()")..];
    let src = &src[..src.find(".fallback(").expect(".fallback(")];
    let mut out = BTreeMap::new();
    for (i, _) in src.match_indices(".route(") {
        let args = balanced(&src[i + ".route(".len()..]);
        let (path, methods) = split_args(args);
        let path = path.trim();
        let path = match path.strip_prefix('"') {
            Some(p) => p.strip_suffix('"').expect("string literal").to_owned(),
            None => resolve_const(path),
        };
        for (method, handler) in method_router(methods) {
            let key = (openapi_path(&path), method);
            assert!(out.insert(key.clone(), handler).is_none(), "{key:?} twice");
        }
    }
    out
}

fn spec() -> Value {
    serde_json::from_str(SPEC).expect("openapi.json is valid JSON")
}

#[test]
fn parser_understands_the_router() {
    let routes = router_routes();
    assert!(routes.len() > 40, "only {} routes found", routes.len());
    for (key, handler) in [
        (("/api/v1/health", "get"), "health"),
        (("/api/v1/allowlist", "delete"), "remove_allow"),
        (("/api/v1/correlation/{name}", "put"), "set_rule"),
        (("/api/v1/sessions/{id}", "delete"), "end_session"),
        (
            ("/api/v1/oidc/backchannel-logout", "post"),
            "oidc_backchannel_logout",
        ),
    ] {
        let key = (key.0.to_owned(), key.1.to_owned());
        assert_eq!(
            routes.get(&key).map(String::as_str),
            Some(handler),
            "{key:?}"
        );
    }
    assert_eq!(handler_role("health"), "none");
    assert_eq!(handler_role("whoami"), "authenticated");
    assert_eq!(handler_role("ban"), "operator");
    assert_eq!(handler_role("audit"), "admin");
}

#[test]
fn spec_matches_router() {
    let spec = spec();
    let routes = router_routes();
    let mut documented = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().expect("paths") {
        for method in item.as_object().expect("path item").keys() {
            if METHODS.contains(&method.as_str()) {
                documented.insert((path.clone(), method.clone()));
            }
        }
    }
    let served: BTreeSet<_> = routes.keys().cloned().collect();
    let missing: Vec<_> = served.difference(&documented).collect();
    let extra: Vec<_> = documented.difference(&served).collect();
    assert!(
        missing.is_empty(),
        "routes missing in openapi.json: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "openapi.json documents unknown routes: {extra:?}"
    );

    for ((path, method), handler) in &routes {
        let op = &spec["paths"][path][method];
        let want = handler_role(handler);
        assert_eq!(
            op["x-required-role"].as_str(),
            Some(want.as_str()),
            "{method} {path} ({handler}): x-required-role"
        );
        let security = op["security"].as_array().expect("security per operation");
        if want == "none" {
            assert!(security.is_empty(), "{method} {path}: security must be []");
        } else {
            assert!(!security.is_empty(), "{method} {path}: security missing");
            let csrf = security.iter().any(|s| s.get("csrfToken").is_some());
            assert_eq!(
                csrf,
                method != "get",
                "{method} {path}: session cookie needs the CSRF token exactly for unsafe methods"
            );
        }
    }
}

/// Every `{"$ref": "#/..."}` resolves.
fn check_refs(root: &Value, v: &Value, at: &str) {
    match v {
        Value::Object(m) => {
            if let Some(r) = m.get("$ref") {
                let r = r.as_str().expect("$ref is a string");
                let ptr = r.strip_prefix('#').expect("local $ref");
                assert!(root.pointer(ptr).is_some(), "{at}: dangling $ref {r}");
            }
            for (k, v) in m {
                check_refs(root, v, &format!("{at}/{k}"));
            }
        }
        Value::Array(a) => a.iter().for_each(|v| check_refs(root, v, at)),
        _ => {}
    }
}

#[test]
fn spec_is_well_formed() {
    let spec = spec();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1."));
    assert!(!spec["info"]["title"].as_str().unwrap().is_empty());
    assert!(!spec["info"]["version"].as_str().unwrap().is_empty());
    let paths = spec["paths"].as_object().unwrap();
    assert!(!paths.is_empty());
    let mut ids = BTreeSet::new();
    for (path, item) in paths {
        let params: BTreeSet<&str> = path
            .split('/')
            .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
            .collect();
        for (method, op) in item.as_object().unwrap() {
            let id = op["operationId"].as_str().expect("operationId");
            assert!(ids.insert(id.to_owned()), "operationId {id} twice");
            assert!(
                op["summary"].as_str().is_some_and(|s| !s.is_empty()),
                "{method} {path}: summary"
            );
            let responses = op["responses"].as_object().expect("responses");
            assert!(!responses.is_empty(), "{method} {path}: no responses");
            assert!(
                responses
                    .keys()
                    .any(|c| c.starts_with('2') || c.starts_with('3')),
                "{method} {path}: no success response"
            );
            let declared: BTreeSet<&str> = op["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["in"] == "path")
                .map(|p| p["name"].as_str().unwrap())
                .collect();
            assert_eq!(declared, params, "{method} {path}: path parameters");
        }
    }
    for scheme in ["bearerToken", "sessionCookie", "csrfToken"] {
        assert!(spec["components"]["securitySchemes"][scheme].is_object());
    }
    check_refs(&spec, &spec, "#");
}
