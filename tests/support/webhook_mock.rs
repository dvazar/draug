//! Shared integration-test webhook mock.
//!
//! Integration tests compile against `draug` as an external crate user, so the
//! `#[cfg(test)]` mock/reader helpers inside `src/alert.rs` are NOT visible
//! here — only the crate's `pub` API is. To avoid a third drifting copy of the
//! HTTP request-reader/reply logic (the src unit tests own one private copy of
//! their own; see `read_http_request`/`write_200_close` in `src/alert.rs`), the
//! integration `WebhookMock` is single-sourced in this module and shared by the
//! lifecycle suite via `#[path = "support/webhook_mock.rs"] mod`.
//!
//! Like the src unit mocks, every reply carries `Connection: close` so the
//! client (`ureq`, which pools/reuses TCP connections by default) opens a fresh
//! connection per POST. Without it, ureq can send alert #2 on the same pooled
//! socket while the mock is blocked awaiting a NEW connection, leaving alert #2
//! unread until ureq times out -> dropped, which both flakes multi-alert tests
//! and can MASK a double-send regression.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A webhook mock that records every POST body it receives. It reads each
/// connection until the full HTTP request (headers + JSON body) has arrived,
/// because TCP may split the request across segments and a single `read` can
/// miss the body (which carries `severity`/`reason`/`restart_count`).
pub struct WebhookMock {
    pub url: String,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl WebhookMock {
    /// Bind an ephemeral port and serve forever on a background thread. Each
    /// accepted connection is read to a full request, recorded, then answered
    /// with a `Connection: close` reply so ureq does not pool the socket.
    pub fn start() -> WebhookMock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let recorded = bodies.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                if let Some(raw) = read_http_request(&mut stream) {
                    recorded.lock().unwrap().push(raw);
                }
                write_200_close(&mut stream);
            }
        });
        WebhookMock { url, bodies }
    }

    /// Count recorded requests whose JSON body, once parsed, satisfies `pred`.
    /// Bodies that fail to frame/parse as JSON are skipped. This is the precise
    /// alternative to substring matching on the raw text, which would let
    /// `"restart_count":1` also match `:10`, `:11`, `:100`, etc.
    pub fn count_where(&self, pred: impl Fn(&serde_json::Value) -> bool) -> usize {
        self.bodies
            .lock()
            .unwrap()
            .iter()
            .filter_map(|raw| parse_body_json(raw))
            .filter(|json| pred(json))
            .count()
    }

    /// Count recorded requests whose parsed JSON field `key` equals `value`.
    /// Numeric-typed comparison, so `restart_count == 1` never collides with
    /// `10`/`11`/`100` the way a raw substring match would.
    pub fn count_field_eq(&self, key: &str, value: serde_json::Value) -> usize {
        self.count_where(|json| json.get(key) == Some(&value))
    }
}

/// Extract and parse the JSON body from a raw HTTP request string. The body is
/// everything after the `\r\n\r\n` header/body separator. Returns `None` if the
/// separator is missing or the body is not valid JSON.
fn parse_body_json(raw: &str) -> Option<serde_json::Value> {
    let idx = raw.find("\r\n\r\n")?;
    let body = &raw[idx + 4..];
    serde_json::from_str(body).ok()
}

/// Read one full HTTP request (headers + JSON body) from `stream` and return
/// the raw request text — or `None` once the peer closes with no request. Stops
/// a read once the header/body separator AND the JSON body terminator have
/// arrived, so it never returns a partial request split across TCP segments.
fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                return if data.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&data).to_string())
                };
            }
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data);
                if let Some(idx) = text.find("\r\n\r\n")
                    && text[idx + 4..].contains('}')
                {
                    break;
                }
            }
            Err(_) => {
                if data.is_empty() {
                    return None;
                }
                break; // partial request — record it and let asserts report
            }
        }
    }
    Some(String::from_utf8_lossy(&data).to_string())
}

/// Reply `200 OK` with an empty body and `Connection: close` so the client
/// (ureq) does NOT pool/reuse the socket; every POST then arrives on a
/// connection the mock fully owns end-to-end. `Content-Length: 0` lets the
/// client see a complete response.
fn write_200_close(stream: &mut TcpStream) {
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
