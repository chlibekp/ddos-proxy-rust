use std::sync::Arc;

use http::{Response, StatusCode};

use crate::body::{full, BoxedBody};
use crate::metrics;
use crate::proxy::Proxy;

/// Handles the configured health check path (default `/healthz`).
///
/// Probes the backend with a HEAD request to `backend_path`. Responds with:
///   - `200 {"status":"ok","backend":"reachable"}` on a 2xx/3xx backend response
///   - `503 {"status":"degraded","backend":"unreachable","error":"..."}` on failure
///
/// This endpoint bypasses the WAF and requires no authentication, making it
/// safe for use by Kubernetes liveness/readiness probes and load-balancer checks.
pub async fn handle(proxy: Arc<Proxy>, backend_path: &str) -> Response<BoxedBody> {
    match proxy.health_check(backend_path).await {
        Ok(status) if status.is_success() || status.is_redirection() => {
            metrics::HEALTHZ_CHECKS.with_label_values(&["ok"]).inc();
            json_response(StatusCode::OK, r#"{"status":"ok","backend":"reachable"}"#)
        }
        Ok(status) => {
            metrics::HEALTHZ_CHECKS.with_label_values(&["error"]).inc();
            let body = format!(
                r#"{{"status":"degraded","backend":"unreachable","error":"backend returned {}"}}"#,
                status.as_u16()
            );
            json_response(StatusCode::SERVICE_UNAVAILABLE, &body)
        }
        Err(e) => {
            metrics::HEALTHZ_CHECKS.with_label_values(&["error"]).inc();
            let msg = e.to_string().replace('"', "\\\"");
            let body = format!(
                r#"{{"status":"degraded","backend":"unreachable","error":"{}"}}"#,
                msg
            );
            json_response(StatusCode::SERVICE_UNAVAILABLE, &body)
        }
    }
}

fn json_response(status: StatusCode, body: &str) -> Response<BoxedBody> {
    let mut resp = Response::new(full(body.to_owned()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_response_sets_status_and_content_type() {
        let resp = json_response(StatusCode::OK, r#"{"status":"ok"}"#);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn json_response_503_for_unavailable() {
        let resp = json_response(StatusCode::SERVICE_UNAVAILABLE, r#"{"status":"degraded"}"#);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
