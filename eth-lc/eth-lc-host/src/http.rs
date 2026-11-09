//! Minimal Beacon API and JSON-RPC client.

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// GET `base + path`, parsed as JSON.
pub fn get_json(base: &str, path: &str) -> Result<Value> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let mut resp = ureq::get(&url)
        .header("Accept", "application/json")
        .call()
        .with_context(|| format!("GET {url}"))?;
    resp.body_mut()
        .read_json::<Value>()
        .with_context(|| format!("JSON from {url}"))
}

/// JSON-RPC call; returns `result`.
pub fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let req = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut resp = ureq::post(url)
        .send_json(&req)
        .with_context(|| format!("{method} at {url}"))?;
    let v: Value = resp.body_mut().read_json()?;
    if let Some(e) = v.get("error") {
        bail!("{method}: {e}");
    }
    Ok(v["result"].clone())
}
