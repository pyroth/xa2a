//! Utility functions and helpers for the A2A SDK.

#![allow(dead_code)]

pub mod signing;

use std::collections::HashMap;
use uuid::Uuid;

use crate::types::{
    Artifact, Message, MessageSendParams, Part, Task, TaskArtifactUpdateEvent, TaskState,
    TaskStatus,
};

/// Generates a new UUID v4 string.
pub fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a current timestamp in ISO 8601 format.
pub fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Encodes bytes to base64.
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decodes base64 string to bytes.
pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(data)
}

/// Constant-time comparison to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Extracts query parameters from a URL (simple implementation).
pub fn parse_query_params(url: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(key.to_string(), value.to_string());
            }
        }
    }
    params
}

/// Builds a URL with query parameters.
pub fn build_url_with_params(base: &str, params: &HashMap<String, String>) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let query: Vec<String> = params.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    format!("{}?{}", base.trim_end_matches('?'), query.join("&"))
}

/// Creates a new task object from message send params.
///
/// Generates UUIDs for task and context IDs if they are not already present.
pub fn create_task_obj(params: &MessageSendParams) -> Task {
    let context_id = params
        .message
        .context_id
        .clone()
        .unwrap_or_else(generate_id);

    Task {
        id: generate_id(),
        context_id,
        status: TaskStatus::new(TaskState::Submitted),
        kind: "task".to_string(),
        history: Some(vec![params.message.clone()]),
        artifacts: None,
        metadata: None,
    }
}

/// Appends artifact data from an event to a task.
///
/// Handles creating the artifacts list if it doesn't exist, adding new artifacts,
/// and appending parts to existing artifacts based on the `append` flag.
pub fn append_artifact_to_task(task: &mut Task, event: &TaskArtifactUpdateEvent) {
    let artifacts = task.artifacts.get_or_insert_with(Vec::new);
    let artifact_id = &event.artifact.artifact_id;
    let append_parts = event.append.unwrap_or(false);

    let existing_idx = artifacts.iter().position(|a| &a.artifact_id == artifact_id);

    if !append_parts {
        // Replace or add new artifact
        if let Some(idx) = existing_idx {
            artifacts[idx] = event.artifact.clone();
        } else {
            artifacts.push(event.artifact.clone());
        }
    } else if let Some(idx) = existing_idx {
        // Append parts to existing artifact
        artifacts[idx].parts.extend(event.artifact.parts.clone());
    }
    // If append=true but artifact doesn't exist, we ignore (matching Python behavior)
}

/// Creates a text artifact with the given content.
pub fn build_text_artifact(text: impl Into<String>, artifact_id: impl Into<String>) -> Artifact {
    Artifact::new(artifact_id, vec![Part::text(text)])
}

/// Checks if server and client output modalities are compatible.
///
/// Returns true if:
/// - Client specifies no preferred output modes
/// - Server specifies no supported output modes
/// - There is at least one common modality
pub fn are_modalities_compatible(
    server_output_modes: Option<&[String]>,
    client_output_modes: Option<&[String]>,
) -> bool {
    match (client_output_modes, server_output_modes) {
        (None, _) | (Some(&[]), _) => true,
        (_, None) | (_, Some(&[])) => true,
        (Some(client), Some(server)) => client.iter().any(|c| server.contains(c)),
    }
}

/// Applies history length limit to a task.
///
/// If `history_length` is specified and the task has history,
/// truncates the history to the specified length from the end.
pub fn apply_history_length(mut task: Task, history_length: Option<i32>) -> Task {
    if let (Some(length), Some(history)) = (history_length, task.history.as_mut()) {
        let length = length.max(0) as usize;
        if history.len() > length {
            let start = history.len() - length;
            *history = history.split_off(start);
        }
    }
    task
}

/// Extracts text content from a message.
///
/// Joins all text parts with the specified delimiter.
pub fn get_message_text(message: &Message, delimiter: &str) -> String {
    message
        .parts
        .iter()
        .filter_map(|p| p.as_text())
        .collect::<Vec<_>>()
        .join(delimiter)
}

/// Extension header name for A2A protocol.
pub const HTTP_EXTENSION_HEADER: &str = "A2A-Extensions";

/// Updates extension header value by adding new extensions.
pub fn update_extension_header(existing: Option<&str>, new_extensions: &[String]) -> String {
    let mut extensions: Vec<&str> = existing
        .map(|e| e.split(',').map(str::trim).collect())
        .unwrap_or_default();

    for ext in new_extensions {
        if !extensions.contains(&ext.as_str()) {
            extensions.push(ext);
        }
    }

    extensions.join(", ")
}

/// Tracing span helper for A2A operations.
#[cfg(feature = "telemetry")]
pub mod telemetry {
    use tracing::{Span, info_span};

    /// Creates a span for a send_message operation.
    pub fn send_message_span(task_id: &str, context_id: &str) -> Span {
        info_span!(
            "a2a.send_message",
            task_id = %task_id,
            context_id = %context_id,
            otel.kind = "client"
        )
    }

    /// Creates a span for a get_task operation.
    pub fn get_task_span(task_id: &str) -> Span {
        info_span!(
            "a2a.get_task",
            task_id = %task_id,
            otel.kind = "client"
        )
    }

    /// Creates a span for agent execution.
    pub fn execute_span(task_id: &str, context_id: &str) -> Span {
        info_span!(
            "a2a.execute",
            task_id = %task_id,
            context_id = %context_id,
            otel.kind = "server"
        )
    }

    /// Creates a span for handling a request.
    pub fn handle_request_span(method: &str) -> Span {
        info_span!(
            "a2a.handle_request",
            method = %method,
            otel.kind = "server"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // UUID v4 format
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }
}
