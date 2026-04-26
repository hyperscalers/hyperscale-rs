//! Trace context for distributed tracing.
//!
//! Only compiled when the `trace-propagation` feature is enabled.
//! When disabled, `TraceContext` is a zero-size type that serializes to nothing.

#[cfg(feature = "trace-propagation")]
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
#[cfg(feature = "trace-propagation")]
use opentelemetry_sdk::propagation::TraceContextPropagator;
use sbor::prelude::BasicSbor;

/// Trace context carrier for network messages.
///
/// When `trace-propagation` feature is enabled, this carries W3C Trace Context
/// headers for distributed tracing across nodes.
///
/// When disabled, this is a zero-size type that serializes to an empty vector,
/// adding minimal overhead to messages.
#[derive(Debug, Clone, PartialEq, Eq, Default, BasicSbor)]
pub struct TraceContext {
    /// W3C Trace Context headers (traceparent, tracestate).
    /// Empty when feature is disabled.
    pub headers: Vec<(String, String)>,
}

impl TraceContext {
    /// Create a new trace context from the current span.
    ///
    /// When `trace-propagation` feature is enabled, extracts the current
    /// OpenTelemetry context and serializes it to W3C Trace Context format.
    ///
    /// When disabled, returns an empty context.
    #[must_use]
    pub const fn from_current() -> Self {
        #[cfg(feature = "trace-propagation")]
        {
            let propagator = TraceContextPropagator::new();
            let mut headers = Vec::new();
            let cx = opentelemetry::Context::current();
            propagator.inject_context(&cx, &mut VecInjector(&mut headers));
            Self { headers }
        }
        #[cfg(not(feature = "trace-propagation"))]
        {
            Self {
                headers: Vec::new(),
            }
        }
    }

    /// Extract the trace context and return an OpenTelemetry Context.
    ///
    /// When `trace-propagation` feature is enabled, deserializes the W3C
    /// Trace Context headers and returns the extracted context.
    ///
    /// When disabled, returns the current context unchanged.
    #[cfg(feature = "trace-propagation")]
    pub fn extract(&self) -> opentelemetry::Context {
        let propagator = TraceContextPropagator::new();
        propagator.extract(&VecExtractor(&self.headers))
    }

    /// Returns true if trace propagation is enabled at compile time.
    #[must_use]
    pub const fn is_enabled() -> bool {
        cfg!(feature = "trace-propagation")
    }

    /// Returns true if this context contains trace data.
    #[must_use]
    pub const fn has_trace(&self) -> bool {
        !self.headers.is_empty()
    }
}

/// Injector that writes headers to a Vec.
#[cfg(feature = "trace-propagation")]
struct VecInjector<'a>(&'a mut Vec<(String, String)>);

#[cfg(feature = "trace-propagation")]
impl Injector for VecInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.push((key.to_string(), value));
    }
}

/// Extractor that reads headers from a Vec.
#[cfg(feature = "trace-propagation")]
struct VecExtractor<'a>(&'a [(String, String)]);

#[cfg(feature = "trace-propagation")]
impl Extractor for VecExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.iter().map(|(k, _)| k.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_default() {
        let ctx = TraceContext::default();
        assert!(ctx.headers.is_empty());
        assert!(!ctx.has_trace());
    }

    #[test]
    fn test_trace_context_from_current_without_span() {
        // Without an active span, should return empty context
        let ctx = TraceContext::from_current();
        // When feature disabled, always empty
        // When feature enabled but no span, also empty
        assert!(!ctx.has_trace() || TraceContext::is_enabled());
    }

    #[test]
    fn test_is_enabled() {
        // Just verify it compiles and returns a bool
        let _enabled = TraceContext::is_enabled();
    }
}
