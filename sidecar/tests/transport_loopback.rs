//! RED tests for the Iroh transport core: real endpoint pair over loopback.
//!
//! Contract (plan §5/§6 Phase 1):
//! - Two endpoints bind with persistent keys and the Hermes ALPN.
//! - The dialer connects to the acceptor by EndpointAddr and exchanges
//!   hello + one bounded task.request/task.result frame pair.
//! - Oversized and malformed frames fail closed (connection rejected).

use std::collections::BTreeSet;

use hermes_iroh_sidecar::protocol;
use hermes_iroh_sidecar::transport::{self, TransportConfig};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, SecretKey, TransportAddr};

const ALPN: &[u8] = b"/hermes/interconnect/1";

fn task_request(text: &str) -> Vec<u8> {
    protocol::encode_frame(
        format!(
            r#"{{"protocol":"hermes-interconnect","version":1,"type":"task.request","requestId":"req-1","payload":{{"text":"{text}"}}}}"#
        )
        .as_bytes(),
    )
}

/// Spawns a minimal acceptor endpoint that echoes task.request as task.result.
/// This is the in-process model of what the sidecar binary does; the
/// library function `run_accept_loop` is the same code the binary uses.
async fn spawn_acceptor(secret: SecretKey) -> anyhow::Result<(Endpoint, EndpointAddr)> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let addr = EndpointAddr {
        id: endpoint.id(),
        addrs: endpoint
            .bound_sockets()
            .into_iter()
            .map(TransportAddr::Ip)
            .collect::<BTreeSet<_>>(),
    };

    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(ALPN, hermes_iroh_sidecar::transport::HermesHandler::default())
        .spawn();
    std::mem::forget(router); // keep alive for the test process lifetime

    Ok((endpoint, addr))
}

#[tokio::test]
async fn hello_and_task_round_trip_over_loopback() -> anyhow::Result<()> {
    let (_server, addr) = spawn_acceptor(SecretKey::generate()).await?;
    let client = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]).bind().await?;

    let result = transport::call_peer(
        &client,
        addr,
        task_request("What is 2+2?"),
    )
    .await?;

    assert_eq!(result.status, "completed");
    assert!(!result.text.is_empty());
    Ok(())
}

#[tokio::test]
async fn oversized_frame_is_rejected_without_exchange() -> anyhow::Result<()> {
    let (_server, addr) = spawn_acceptor(SecretKey::generate()).await?;
    let client = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]).bind().await?;

    // Build a frame claiming a length above MAX_FRAME_BYTES.
    let mut bad = Vec::new();
    bad.extend_from_slice(&(0xFFFF_FFFFu32).to_be_bytes());
    let err = transport::call_peer(&client, addr, bad)
        .await
        .expect_err("oversized frame must fail");
    assert!(
        err.to_string().contains("too large") || err.to_string().contains("frame"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_envelope_yields_task_error() -> anyhow::Result<()> {
    let (_server, addr) = spawn_acceptor(SecretKey::generate()).await?;
    let client = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]).bind().await?;

    let bad_frame = protocol::encode_frame(
        br#"{"protocol":"wrong","version":1,"type":"task.request","requestId":"x"}"#,
    );
    let result = transport::call_peer(&client, addr, bad_frame).await?;
    assert_eq!(result.status, "failed");
    Ok(())
}

#[tokio::test]
async fn unused_config_defaults_are_safe() {
    let cfg = TransportConfig::default();
    assert!(cfg.max_frame_bytes > 0);
    assert!(cfg.request_timeout_secs >= 1);
}
