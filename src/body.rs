use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};

/// Unified boxed body type used across the proxy/WAF response path.
pub type BoxedBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

pub fn empty() -> BoxedBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full<T: Into<Bytes>>(chunk: T) -> BoxedBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
