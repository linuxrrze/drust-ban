//! The web UI: static files from `web/dist` embedded into the binary, plus
//! security headers for every HTTPS response.
//!
//! Build the UI before the controller (`npm --prefix web ci && npm --prefix
//! web run build`); without it the controller serves a short notice instead.
//! Debug builds read the files from disk at runtime.

use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Assets;

/// The UI loads scripts and styles from its own origin only and talks only
/// to its own API; nothing may frame it.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                   img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                   manifest-src 'self'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

const NOT_BUILT: &str = "<!doctype html><meta charset=utf-8><title>dist-f2b</title>\
<p>The web UI was not built into this controller binary. Build it with \
<code>npm --prefix web ci &amp;&amp; npm --prefix web run build</code> and rebuild \
the controller. The REST API is available under <code>/api/v1</code>.</p>";

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("json" | "webmanifest") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Serves a UI file. The UI routes with `#/...`, so only real files exist.
pub async fn serve(uri: Uri) -> Response {
    let path = match uri.path().trim_start_matches('/') {
        "" => "index.html",
        p => p,
    };
    match Assets::get(path) {
        Some(file) => {
            // file names under assets/ contain a content hash
            let cache = if path.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            (
                [
                    (header::CONTENT_TYPE, content_type(path)),
                    (header::CACHE_CONTROL, cache),
                ],
                file.data,
            )
                .into_response()
        }
        None if path == "index.html" => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            NOT_BUILT,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Headers for every response (API and UI).
pub async fn security_headers(mut r: Response) -> Response {
    let h = r.headers_mut();
    let mut set = |name: &'static str, value: &'static str| {
        h.entry(name).or_insert(HeaderValue::from_static(value));
    };
    set("strict-transport-security", "max-age=31536000");
    set("x-content-type-options", "nosniff");
    set("referrer-policy", "no-referrer");
    set("x-frame-options", "DENY");
    set("cross-origin-opener-policy", "same-origin");
    set("cross-origin-resource-policy", "same-origin");
    set("content-security-policy", CSP);
    // API responses carry ban lists and tokens: never cache them
    set("cache-control", "no-store");
    r
}
