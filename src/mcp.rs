//! `agent mcp`: an MCP server (JSON-RPC over stdio) that an agent runs
//! inside its sandbox. Its tools let the agent see what it was granted and
//! ask you, with a reason, for a folder or a host; the supervisor does the
//! work through the control socket (see `control.rs`).

use crate::control::{self, Call, Reply};
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;

/// Protocol versions we speak; tools work the same in all of them.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "You run inside an agentos sandbox: you see only the folders you were granted, \
your file changes and git pushes are held for the user's review, and the network is an allowlist. \
When you need a folder or a host you don't have, ask for it with these tools and a one-sentence reason \
instead of working around the restriction. The user decides.";

fn tools() -> Value {
    json!([
        {
            "name": "sandbox_info",
            "description": "What this agentos sandbox gives you: the folders you can read and change, \
the hosts you can reach, your budget, and where your changes and git pushes go. \
Call it when something is denied or unreachable, before asking for more.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "request_path_access",
            "description": "Ask the user for a folder (or file) you can't see, or can't change, in this sandbox. \
The user decides; the answer comes when they do, which can take a minute. Write access is transactional: \
your changes there are held for the user's review like the rest of your work.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute, ~/…, or relative to the task's folder" },
                    "access": { "type": "string", "enum": ["read", "write"] },
                    "reason": { "type": "string", "description": "One sentence, shown to the user" }
                },
                "required": ["path", "access", "reason"]
            }
        },
        {
            "name": "request_network_access",
            "description": "Ask the user to let you reach a host that this sandbox blocks (connections to it are refused). \
The user decides; the answer comes when they do. Only HTTPS goes through.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "A host name, like pypi.org" },
                    "port": { "type": "integer", "description": "Defaults to 443" },
                    "reason": { "type": "string", "description": "One sentence, shown to the user" }
                },
                "required": ["host", "reason"]
            }
        }
    ])
}

/// The tool call, as a call to agentos.
fn to_call(name: &str, args: &Value) -> std::result::Result<Call, String> {
    let text = |key: &str| args[key].as_str().map(str::to_string).filter(|s| !s.trim().is_empty());
    let reason = || text("reason").ok_or_else(|| "give a reason: one sentence the user will read".to_string());
    match name {
        "sandbox_info" => Ok(Call::Info),
        "request_path_access" => {
            let path = text("path").ok_or("path is required")?;
            let write = match args["access"].as_str() {
                Some("read") | None => false,
                Some("write") => true,
                Some(other) => return Err(format!("access must be \"read\" or \"write\", not {other:?}")),
            };
            Ok(Call::Path { path, write, reason: reason()? })
        }
        "request_network_access" => {
            let host = text("host").ok_or("host is required")?;
            let port = match &args["port"] {
                Value::Null => None,
                v => Some(v.as_u64().and_then(|p| u16::try_from(p).ok()).ok_or("port must be a number from 1 to 65535")?),
            };
            Ok(Call::Network { host, port, reason: reason()? })
        }
        other => Err(format!("unknown tool {other}")),
    }
}

/// The answer to one JSON-RPC message, if it needs one.
pub fn handle(msg: &Value, ask: &dyn Fn(&Call) -> Result<Reply>) -> Option<Value> {
    // Notifications (no id) and the client's own responses get no reply.
    let id = msg.get("id")?.clone();
    let method = msg.get("method")?.as_str().unwrap_or("");
    let params = &msg["params"];
    let result = match method {
        "initialize" => {
            let wanted = params["protocolVersion"].as_str().unwrap_or("");
            let version = VERSIONS.iter().find(|v| **v == wanted).unwrap_or(&VERSIONS[1]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "agentos", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let reply = to_call(name, &params["arguments"])
                .map_err(Reply::error)
                .and_then(|c| ask(&c).map_err(|e| Reply::error(format!("{e:#}"))))
                .unwrap_or_else(|r| r);
            Ok(json!({ "content": [{ "type": "text", "text": reply.text }], "isError": !reply.ok }))
        }
        _ => Err(json!({ "code": -32601, "message": format!("method not found: {method}") })),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
    })
}

/// Serves MCP on stdin/stdout until the agent closes it.
pub fn serve_stdio(socket: &Path) -> Result<()> {
    let ask = |c: &Call| control::call(socket, c);
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg, &ask),
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("parse error: {e}") } })),
        };
        if let Some(r) = reply {
            writeln!(out, "{r}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params })
    }

    #[test]
    fn speaks_mcp() {
        let calls = std::sync::Mutex::new(Vec::new());
        let ask = |c: &Call| {
            calls.lock().unwrap().push(c.clone());
            Ok(Reply::answer("granted"))
        };
        let init = handle(&rpc("initialize", json!({ "protocolVersion": "2025-03-26" })), &ask).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["id"], 7);
        let unknown = handle(&rpc("initialize", json!({ "protocolVersion": "1999-01-01" })), &ask).unwrap();
        assert_eq!(unknown["result"]["protocolVersion"], "2025-06-18");
        assert!(handle(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }), &ask).is_none());

        let list = handle(&rpc("tools/list", json!({})), &ask).unwrap();
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["sandbox_info", "request_path_access", "request_network_access"]);

        let args = json!({ "path": "~/code/lib", "access": "write", "reason": "fix the bug there" });
        let r = handle(&rpc("tools/call", json!({ "name": "request_path_access", "arguments": args })), &ask).unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "granted");
        assert_eq!(r["result"]["isError"], false);
        let r = handle(&rpc("tools/call", json!({ "name": "request_network_access", "arguments": { "host": "pypi.org", "port": 8443, "reason": "deps" } })), &ask).unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(
            *calls.lock().unwrap(),
            [
                Call::Path { path: "~/code/lib".into(), write: true, reason: "fix the bug there".into() },
                Call::Network { host: "pypi.org".into(), port: Some(8443), reason: "deps".into() }
            ]
        );

        // Bad arguments come back as tool errors, without bothering anyone.
        let r = handle(&rpc("tools/call", json!({ "name": "request_network_access", "arguments": { "host": "pypi.org" } })), &ask).unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("reason"));
        assert_eq!(calls.lock().unwrap().len(), 2);
        let r = handle(&rpc("resources/list", json!({})), &ask).unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }
}
