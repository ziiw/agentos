//! System services as MCP tools: a D-Bus bus, seen through an MCP server
//! that agentos runs outside the sandbox.
//!
//! ```toml
//! [mcp.desktop]
//! dbus = "session"                              # or "system"
//! services = ["org.freedesktop.Notifications"]  # the only names it can reach
//! ```
//!
//! A bus is a lot of power: the session bus has your password manager, your
//! shell and your media players; the system bus has `systemd` and the power
//! button. So a server like this reaches **only the services you list**
//! (`org.mpris.MediaPlayer2.*` lists a family), whatever the agent asks for,
//! and everything it does goes through the gateway's usual questions, rules
//! and journal. Four tools, which the agent can use without knowing D-Bus:
//!
//! - `dbus_services`: which of your services are there;
//! - `dbus_introspect`: an object's methods, properties and signals, typed;
//! - `dbus_get`: one property (read-only, like the two above);
//! - `dbus_call`: a method, with its arguments as JSON. The method's
//!   signature comes from introspection, so `["hi", 3]` is enough.
//!
//! The bus is spoken to by `busctl` (part of systemd); this module turns
//! JSON into the words `busctl call` wants, and its JSON back into text.
//! `agent dbus-bridge` is the program `[mcp.NAME] dbus = …` starts.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long one `busctl` may take (a D-Bus call times out at 25 s itself).
const TIMEOUT: Duration = Duration::from_secs(30);
/// What an answer may weigh before it's cut.
const MAX_OUTPUT: usize = 64 * 1024;
/// More values than this in one call is a mistake.
const MAX_WORDS: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    Session,
    System,
}

impl Bus {
    pub fn parse(s: &str) -> Option<Bus> {
        match s {
            "session" => Some(Bus::Session),
            "system" => Some(Bus::System),
            _ => None,
        }
    }

    fn flag(self) -> &'static str {
        match self {
            Bus::Session => "--user",
            Bus::System => "--system",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Bus::Session => "session",
            Bus::System => "system",
        }
    }
}

// ---- names ----

/// A well-known bus name: dotted elements of letters, digits, `_` and `-`
/// (none starting with a digit). Never a unique name (`:1.42`).
fn valid_service(name: &str) -> bool {
    name.len() <= 255
        && name.contains('.')
        && !name.starts_with('-')
        && name.split('.').all(|e| !e.is_empty() && !e.starts_with(|c: char| c.is_ascii_digit()) && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
}

/// What `services` may hold: a name, or a family (`org.mpris.MediaPlayer2.*`).
pub fn valid_pattern(p: &str) -> bool {
    valid_service(p.strip_suffix(".*").unwrap_or(p))
}

/// Whether `name` is one the list lets through.
pub fn allows(patterns: &[String], name: &str) -> bool {
    valid_service(name)
        && patterns.iter().any(|p| match p.strip_suffix(".*") {
            Some(family) => name.len() > family.len() + 1 && name.starts_with(family) && name.as_bytes()[family.len()] == b'.',
            None => p == name,
        })
}

fn valid_path(p: &str) -> bool {
    p == "/" || (p.len() <= 1024 && p.starts_with('/') && p[1..].split('/').all(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')))
}

fn valid_interface(n: &str) -> bool {
    n.len() <= 255 && n.contains('.') && n.split('.').all(|e| !e.is_empty() && !e.starts_with(|c: char| c.is_ascii_digit()) && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

fn valid_member(n: &str) -> bool {
    n.len() <= 255 && !n.is_empty() && !n.starts_with(|c: char| c.is_ascii_digit()) && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---- types ----

/// A D-Bus type, from a signature.
#[derive(Debug, Clone, PartialEq)]
enum Ty {
    Basic(char),
    Variant,
    Array(Box<Ty>),
    Struct(Vec<Ty>),
    /// `{kv}`, only ever inside an array.
    Entry(Box<Ty>, Box<Ty>),
}

/// The complete types a signature holds, in order.
fn parse_signature(sig: &str) -> Result<Vec<Ty>, String> {
    let chars: Vec<char> = sig.chars().collect();
    let (mut i, mut out) = (0, Vec::new());
    while i < chars.len() {
        out.push(parse_type(&chars, &mut i, 0).map_err(|e| format!("signature {sig:?}: {e}"))?);
    }
    Ok(out)
}

fn parse_type(c: &[char], i: &mut usize, depth: usize) -> Result<Ty, String> {
    if depth > 16 {
        return Err("nested too deeply".into());
    }
    let ch = *c.get(*i).ok_or("it ends in the middle of a type")?;
    *i += 1;
    match ch {
        'y' | 'b' | 'n' | 'q' | 'i' | 'u' | 'x' | 't' | 'd' | 's' | 'o' | 'g' | 'h' => Ok(Ty::Basic(ch)),
        'v' => Ok(Ty::Variant),
        'a' if c.get(*i) == Some(&'{') => {
            *i += 1;
            let key = parse_type(c, i, depth + 1)?;
            if !matches!(key, Ty::Basic(_)) {
                return Err("a dict's keys are plain values".into());
            }
            let value = parse_type(c, i, depth + 1)?;
            if c.get(*i) != Some(&'}') {
                return Err("a dict entry is a key and a value".into());
            }
            *i += 1;
            Ok(Ty::Array(Box::new(Ty::Entry(Box::new(key), Box::new(value)))))
        }
        'a' => Ok(Ty::Array(Box::new(parse_type(c, i, depth + 1)?))),
        '(' => {
            let mut fields = Vec::new();
            loop {
                match c.get(*i) {
                    Some(')') => {
                        *i += 1;
                        break;
                    }
                    None => return Err("a struct is never closed".into()),
                    _ => fields.push(parse_type(c, i, depth + 1)?),
                }
            }
            if fields.is_empty() {
                return Err("a struct with nothing in it".into());
            }
            Ok(Ty::Struct(fields))
        }
        other => Err(format!("{other:?} isn't a D-Bus type")),
    }
}

// ---- JSON to what `busctl call` wants ----

/// `value` as the words `busctl call` takes for type `ty`: a plain value is
/// itself, an array is its length and then its items, a dict is its length
/// and then key and value of each entry, a struct is its fields, and a
/// variant is its signature and then its value.
fn words(ty: &Ty, value: &Value, at: &str, out: &mut Vec<String>) -> Result<(), String> {
    if out.len() > MAX_WORDS {
        return Err("that's too many values for one call".into());
    }
    let wrong = |what: &str| format!("{at}: expected {what}, got {}", crate::approvals::sanitize(&value.to_string(), 60));
    match ty {
        Ty::Basic(t @ ('y' | 'n' | 'q' | 'i' | 'u' | 'x' | 't')) => {
            let (lo, hi): (i128, i128) = match t {
                'y' => (0, u8::MAX as i128),
                'n' => (i16::MIN as i128, i16::MAX as i128),
                'q' => (0, u16::MAX as i128),
                'i' => (i32::MIN as i128, i32::MAX as i128),
                'u' => (0, u32::MAX as i128),
                'x' => (i64::MIN as i128, i64::MAX as i128),
                _ => (0, u64::MAX as i128),
            };
            let n = match value {
                Value::Number(n) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)),
                Value::String(s) => s.trim().parse::<i128>().ok(),
                _ => None,
            };
            match n {
                Some(n) if (lo..=hi).contains(&n) => out.push(n.to_string()),
                Some(_) => return Err(format!("{at}: {value} doesn't fit type {t} ({lo} to {hi})")),
                None => return Err(wrong(&format!("an integer (type {t})"))),
            }
        }
        Ty::Basic('b') => match value {
            Value::Bool(b) => out.push(b.to_string()),
            Value::String(s) if s == "true" || s == "false" => out.push(s.clone()),
            _ => return Err(wrong("true or false (type b)")),
        },
        Ty::Basic('d') => match value {
            Value::Number(n) => out.push(n.as_f64().unwrap_or_default().to_string()),
            Value::String(s) if s.trim().parse::<f64>().is_ok() => out.push(s.trim().to_string()),
            _ => return Err(wrong("a number (type d)")),
        },
        Ty::Basic(t @ ('s' | 'o' | 'g')) => match value {
            Value::String(s) if s.contains('\0') => return Err(format!("{at}: a string can't hold a NUL")),
            Value::String(s) if *t == 'o' && !valid_path(s) => return Err(format!("{at}: {s:?} isn't an object path (type o)")),
            Value::String(s) if *t == 'g' && parse_signature(s).is_err() => return Err(format!("{at}: {s:?} isn't a signature (type g)")),
            Value::String(s) => out.push(s.clone()),
            _ => return Err(wrong(&format!("a string (type {t})"))),
        },
        Ty::Basic(_) => return Err(format!("{at}: file descriptors can't be passed")),
        Ty::Variant => {
            // {"type": "as", "data": ["a"]} says what it is; a bare value is guessed.
            if let (Some(Value::String(sig)), Some(data), 2) = (value.get("type"), value.get("data"), value.as_object().map_or(0, |o| o.len())) {
                let types = parse_signature(sig)?;
                let [inner] = types.as_slice() else { return Err(format!("{at}: a variant holds one value, not {sig:?}")) };
                out.push(sig.clone());
                return words(inner, data, &format!("{at}.data"), out);
            }
            let sig = match value {
                Value::String(_) => "s".to_string(),
                Value::Bool(_) => "b".to_string(),
                Value::Number(n) if n.is_f64() => "d".to_string(),
                Value::Number(n) if n.as_i64().is_some_and(|n| i32::try_from(n).is_ok()) => "i".to_string(),
                Value::Number(n) if n.as_i64().is_some() => "x".to_string(),
                Value::Number(_) => "t".to_string(),
                Value::Array(items) if !items.is_empty() && items.iter().all(Value::is_string) => "as".to_string(),
                Value::Array(items) if !items.is_empty() && items.iter().all(|v| v.as_i64().is_some_and(|n| i32::try_from(n).is_ok())) => "ai".to_string(),
                _ => return Err(format!("{at}: say what type that variant is: {{\"type\": \"a{{sv}}\", \"data\": …}}")),
            };
            let types = parse_signature(&sig)?;
            out.push(sig);
            return words(&types[0], value, at, out);
        }
        Ty::Array(element) => match element.as_ref() {
            Ty::Entry(key, val) => {
                // A JSON object, or a list of [key, value] pairs (for keys that aren't strings).
                let entries: Vec<(Value, &Value)> = match value {
                    Value::Object(map) => map.iter().map(|(k, v)| (Value::String(k.clone()), v)).collect(),
                    Value::Array(pairs) => pairs
                        .iter()
                        .map(|p| match p.as_array().map(Vec::as_slice) {
                            Some([k, v]) => Ok((k.clone(), v)),
                            _ => Err(format!("{at}: a dict is an object, or a list of [key, value] pairs")),
                        })
                        .collect::<Result<_, _>>()?,
                    _ => return Err(wrong("an object (a dict)")),
                };
                out.push(entries.len().to_string());
                for (k, v) in entries {
                    words(key, &k, &format!("{at} key"), out)?;
                    words(val, v, &format!("{at}.{}", k.as_str().unwrap_or("…")), out)?;
                }
            }
            _ => {
                let Value::Array(items) = value else { return Err(wrong("a list")) };
                out.push(items.len().to_string());
                for (n, item) in items.iter().enumerate() {
                    words(element, item, &format!("{at}[{n}]"), out)?;
                }
            }
        },
        Ty::Struct(fields) => {
            let Value::Array(items) = value else { return Err(wrong(&format!("a list of {} values (a struct)", fields.len()))) };
            if items.len() != fields.len() {
                return Err(format!("{at}: a struct of {} values, got {}", fields.len(), items.len()));
            }
            for (n, (field, item)) in fields.iter().zip(items).enumerate() {
                words(field, item, &format!("{at}[{n}]"), out)?;
            }
        }
        Ty::Entry(..) => return Err(format!("{at}: a dict entry outside a dict")),
    }
    Ok(())
}

// ---- introspection ----

#[derive(Debug, Default, PartialEq)]
struct Node {
    interfaces: Vec<Interface>,
    /// Objects below this one, by their last path element.
    children: Vec<String>,
}

#[derive(Debug, Default, PartialEq)]
struct Interface {
    name: String,
    members: Vec<Member>,
}

#[derive(Debug, Default, PartialEq)]
struct Member {
    /// "method", "signal" or "property".
    kind: &'static str,
    name: String,
    /// Arguments: (name, type, going out).
    args: Vec<(String, String, bool)>,
    /// For a property: its type and access.
    ty: String,
    access: String,
}

impl Interface {
    /// What a call to `method` takes: the types of its `in` arguments.
    fn method_signature(&self, method: &str) -> Option<String> {
        let m = self.members.iter().find(|m| m.kind == "method" && m.name == method)?;
        Some(m.args.iter().filter(|(_, _, out)| !out).map(|(_, ty, _)| ty.as_str()).collect())
    }
}

/// The attributes of a tag's text (`interface name="a.b" x='y'`), after its name.
fn attributes(tag: &str) -> (String, BTreeMap<String, String>) {
    let tag = tag.trim();
    let name_end = tag.find(char::is_whitespace).unwrap_or(tag.len());
    let (name, mut rest) = (tag[..name_end].to_string(), tag[name_end..].trim_start());
    let mut attrs = BTreeMap::new();
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
        let Some(close) = after[1..].find(quote) else { break };
        let value = after[1..1 + close].replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
        attrs.insert(key, value);
        rest = after[close + 2..].trim_start();
    }
    (name, attrs)
}

/// Reads what `org.freedesktop.DBus.Introspectable.Introspect` answers.
fn parse_introspection(xml: &str) -> Result<Node, String> {
    let (mut node, mut depth) = (Node::default(), 0usize);
    let (mut interface, mut member): (Option<Interface>, Option<Member>) = (None, None);
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        if let Some(after) = rest.strip_prefix("!--") {
            rest = after.split_once("-->").map_or("", |(_, r)| r);
            continue;
        }
        if rest.starts_with('?') || rest.starts_with('!') {
            rest = rest.split_once('>').map_or("", |(_, r)| r);
            continue;
        }
        // The end of the tag: a '>' that isn't inside quotes.
        let (mut quote, mut end) = (None, None);
        for (i, ch) in rest.char_indices() {
            match (quote, ch) {
                (None, '"' | '\'') => quote = Some(ch),
                (Some(q), c) if c == q => quote = None,
                (None, '>') => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let end = end.ok_or("the introspection data ends inside a tag")?;
        let (tag, after) = (&rest[..end], &rest[end + 1..]);
        rest = after;
        let (closing, tag) = tag.strip_prefix('/').map_or((false, tag), |t| (true, t));
        let (self_closing, tag) = tag.strip_suffix('/').map_or((false, tag), |t| (true, t));
        let (name, attrs) = attributes(tag);
        let attr = |k: &str| attrs.get(k).cloned().unwrap_or_default();
        match (closing, name.as_str()) {
            (false, "node") => {
                if depth == 1 && !attr("name").is_empty() {
                    node.children.push(attr("name"));
                }
                if !self_closing {
                    depth += 1;
                }
            }
            (true, "node") => depth = depth.saturating_sub(1),
            (false, "interface") => {
                interface = Some(Interface { name: attr("name"), members: Vec::new() });
                if self_closing {
                    node.interfaces.extend(interface.take());
                }
            }
            (true, "interface") => node.interfaces.extend(interface.take()),
            (false, kind @ ("method" | "signal" | "property")) => {
                let kind = match kind {
                    "method" => "method",
                    "signal" => "signal",
                    _ => "property",
                };
                member = Some(Member { kind, name: attr("name"), ty: attr("type"), access: attr("access"), args: Vec::new() });
                if self_closing {
                    if let (Some(i), Some(m)) = (interface.as_mut(), member.take()) {
                        i.members.push(m);
                    }
                }
            }
            (true, "method" | "signal" | "property") => {
                if let (Some(i), Some(m)) = (interface.as_mut(), member.take()) {
                    i.members.push(m);
                }
            }
            (false, "arg") => {
                if let Some(m) = member.as_mut() {
                    // Methods take their arguments in unless it says out; signals send them.
                    let out = match attrs.get("direction").map(String::as_str) {
                        Some("out") => true,
                        Some(_) => false,
                        None => m.kind == "signal",
                    };
                    m.args.push((attr("name"), attr("type"), out));
                }
            }
            _ => {}
        }
    }
    Ok(node)
}

/// An object for reading: its interfaces and what's in them, then its children.
fn render(service: &str, path: &str, node: &Node) -> String {
    let arg = |(name, ty, _): &(String, String, bool)| if name.is_empty() { ty.clone() } else { format!("{ty} {name}") };
    let mut text = format!("{service} {path}\n");
    for interface in &node.interfaces {
        // Every object has these; they only add noise.
        if interface.name == "org.freedesktop.DBus.Peer" || interface.name == "org.freedesktop.DBus.Introspectable" {
            continue;
        }
        text += &format!("  interface {}\n", interface.name);
        for m in &interface.members {
            match m.kind {
                "method" => {
                    let (ins, outs): (Vec<_>, Vec<_>) = m.args.iter().partition(|a| !a.2);
                    let ins: Vec<String> = ins.into_iter().map(arg).collect();
                    let outs: Vec<String> = outs.into_iter().map(arg).collect();
                    let result = if outs.is_empty() { String::new() } else { format!(" -> {}", outs.join(", ")) };
                    text += &format!("    method {}({}){result}\n", m.name, ins.join(", "));
                }
                "signal" => text += &format!("    signal {}({})\n", m.name, m.args.iter().map(arg).collect::<Vec<_>>().join(", ")),
                _ => text += &format!("    property {}: {} ({})\n", m.name, m.ty, m.access),
            }
        }
    }
    if !node.children.is_empty() {
        let base = path.trim_end_matches('/');
        text += &format!("  objects below: {}\n", node.children.iter().map(|c| format!("{base}/{c}")).collect::<Vec<_>>().join(", "));
    }
    text
}

// ---- the bus ----

/// What turns words into answers: `busctl`, or a stand-in in tests.
pub trait Runner {
    /// Runs `busctl` with these arguments after the bus and output flags;
    /// its output, or what it said when it failed.
    fn run(&self, args: &[String]) -> Result<String, String>;
}

/// `busctl`, for one bus.
pub struct Busctl(pub Bus);

impl Busctl {
    /// What `busctl` is given. The `--` matters: busctl reads options anywhere
    /// among its arguments, so without it a string the agent passes, like
    /// `--address=…` or `-H host`, would be taken as an option of busctl's own.
    fn argv(bus: Bus, args: &[String]) -> Vec<String> {
        let mut argv = words_of([bus.flag(), "--json=short", "--no-pager", "--"]);
        argv.extend(args.iter().cloned());
        argv
    }
}

impl Runner for Busctl {
    fn run(&self, args: &[String]) -> Result<String, String> {
        let mut child = Command::new("busctl")
            .args(Busctl::argv(self.0, args))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => "busctl isn't installed (it comes with systemd)".to_string(),
                _ => format!("couldn't start busctl: {e}"),
            })?;
        // Read both as they come so a full pipe can't stall it.
        let read = |mut pipe: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = (&mut pipe).take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf);
                buf
            })
        };
        let (out, err) = (read(Box::new(child.stdout.take().unwrap())), read(Box::new(child.stderr.take().unwrap())));
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("no answer from the bus in {} seconds", TIMEOUT.as_secs()));
                }
                Err(e) => return Err(format!("busctl: {e}")),
            }
        };
        let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        if status.success() {
            let mut text = String::from_utf8_lossy(&out[..out.len().min(MAX_OUTPUT)]).trim().to_string();
            if out.len() > MAX_OUTPUT {
                text += "\n…(cut: the answer was longer than 64 KiB)";
            }
            Ok(text)
        } else {
            let said = String::from_utf8_lossy(&err).trim().to_string();
            Err(if said.is_empty() { format!("busctl failed ({status})") } else { crate::approvals::sanitize(&said, 600) })
        }
    }
}

/// The server: one bus, and the services it may touch.
pub struct Bridge {
    bus: Bus,
    services: Vec<String>,
    runner: Box<dyn Runner>,
}

fn words_of<const N: usize>(parts: [&str; N]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// A required string argument.
fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    match args.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s),
        Some(Value::String(_) | Value::Null) | None => Err(format!("{key} is required")),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

impl Bridge {
    pub fn new(bus: Bus, services: Vec<String>, runner: Box<dyn Runner>) -> Bridge {
        Bridge { bus, services, runner }
    }

    fn service<'a>(&self, args: &'a Value) -> Result<&'a str, String> {
        let name = text(args, "service")?;
        if allows(&self.services, name) {
            Ok(name)
        } else {
            Err(format!("{name:?} isn't a service this server may use. It can reach: {}", self.services.join(", ")))
        }
    }

    fn path<'a>(&self, args: &'a Value, default: Option<&'a str>) -> Result<&'a str, String> {
        let path = match (args.get("path"), default) {
            (None | Some(Value::Null), Some(d)) => d,
            _ => text(args, "path")?,
        };
        if valid_path(path) { Ok(path) } else { Err(format!("{path:?} isn't an object path (like /org/freedesktop/Notifications)")) }
    }

    fn interface<'a>(&self, args: &'a Value) -> Result<&'a str, String> {
        let name = text(args, "interface")?;
        if valid_interface(name) { Ok(name) } else { Err(format!("{name:?} isn't an interface name (like org.freedesktop.Notifications)")) }
    }

    fn member<'a>(&self, args: &'a Value, key: &str) -> Result<&'a str, String> {
        let name = text(args, key)?;
        if valid_member(name) { Ok(name) } else { Err(format!("{name:?} isn't a valid {key} name")) }
    }

    /// The names on the bus that `method` (ListNames, ListActivatableNames) lists.
    fn names(&self, method: &str) -> Result<Vec<String>, String> {
        let out = self.runner.run(&words_of(["call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", method]))?;
        let reply: Value = serde_json::from_str(&out).map_err(|_| "the bus answered something that isn't JSON".to_string())?;
        Ok(reply["data"][0].as_array().map(|a| a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect()).unwrap_or_default())
    }

    fn introspect(&self, service: &str, path: &str) -> Result<Node, String> {
        let out = self.runner.run(&words_of(["call", service, path, "org.freedesktop.DBus.Introspectable", "Introspect"]))?;
        let reply: Value = serde_json::from_str(&out).map_err(|_| "the bus answered something that isn't JSON".to_string())?;
        parse_introspection(reply["data"][0].as_str().ok_or("that object has no introspection data")?)
    }

    /// Runs one tool: its answer, or what went wrong.
    pub fn call(&self, tool: &str, args: &Value) -> Result<String, String> {
        match tool {
            "dbus_services" => {
                let mut found = BTreeMap::new();
                // Not everything is running: some services start when first called.
                for name in self.names("ListActivatableNames").unwrap_or_default() {
                    if allows(&self.services, &name) {
                        found.insert(name, false);
                    }
                }
                for name in self.names("ListNames")? {
                    if allows(&self.services, &name) {
                        found.insert(name, true);
                    }
                }
                let listed: Vec<Value> = found.into_iter().map(|(name, running)| json!({ "name": name, "running": running })).collect();
                Ok(json!({ "bus": self.bus.name(), "allowed": self.services, "services": listed }).to_string())
            }
            "dbus_introspect" => {
                let (service, path) = (self.service(args)?, self.path(args, Some("/"))?);
                Ok(render(service, path, &self.introspect(service, path)?))
            }
            "dbus_get" => {
                let (service, path) = (self.service(args)?, self.path(args, None)?);
                let (interface, property) = (self.interface(args)?, self.member(args, "property")?);
                self.runner.run(&words_of(["get-property", service, path, interface, property]))
            }
            "dbus_call" => {
                let (service, path) = (self.service(args)?, self.path(args, None)?);
                let (interface, method) = (self.interface(args)?, self.member(args, "method")?);
                let given: &[Value] = match args.get("args") {
                    None | Some(Value::Null) => &[],
                    Some(Value::Array(list)) => list,
                    Some(_) => return Err("args is a list: one value for each argument of the method".into()),
                };
                // What the method takes: as given, or as the object says.
                let signature = match args.get("signature") {
                    Some(Value::String(s)) if !s.is_empty() => s.clone(),
                    None | Some(Value::Null) | Some(Value::String(_)) => match self.introspect(service, path) {
                        Ok(node) => match node.interfaces.iter().find(|i| i.name == interface).and_then(|i| i.method_signature(method)) {
                            Some(sig) => sig,
                            None => return Err(format!("{service} has no method {interface}.{method} at {path}; dbus_introspect lists what it has")),
                        },
                        Err(_) if given.is_empty() => String::new(),
                        Err(why) => return Err(format!("couldn't look up what {method} takes ({why}); pass its signature too")),
                    },
                    Some(_) => return Err("signature is a string, like \"su\"".into()),
                };
                let types = parse_signature(&signature)?;
                if types.len() != given.len() {
                    return Err(format!(
                        "{method} takes {} argument{} ({}), and args has {}",
                        types.len(),
                        if types.len() == 1 { "" } else { "s" },
                        if signature.is_empty() { "none".to_string() } else { signature.clone() },
                        given.len()
                    ));
                }
                let mut line = words_of(["call", service, path, interface, method]);
                if !types.is_empty() {
                    line.push(signature);
                    for (n, (ty, value)) in types.iter().zip(given).enumerate() {
                        words(ty, value, &format!("args[{n}]"), &mut line)?;
                    }
                }
                let answer = self.runner.run(&line)?;
                Ok(if answer.is_empty() { "(it returned nothing)".to_string() } else { answer })
            }
            other => Err(format!("unknown tool {other}")),
        }
    }

    pub fn tools(&self) -> Value {
        let service = json!({ "type": "string", "description": format!("One of: {}", self.services.join(", ")) });
        let path = json!({ "type": "string", "description": "An object path, like /org/freedesktop/Notifications" });
        json!([
            {
                "name": "dbus_services",
                "description": format!("The services on the {} bus that you can use here, and whether each is running (a service that isn't starts when you call it, if it can). Start here.", self.bus.name()),
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": { "readOnlyHint": true }
            },
            {
                "name": "dbus_introspect",
                "description": "What an object offers: its interfaces with their methods (and the types they take and return), properties and signals, and the objects below it. Start at path / and follow \"objects below\".",
                "inputSchema": { "type": "object", "properties": { "service": service, "path": { "type": "string", "description": "Defaults to /" } }, "required": ["service"] },
                "annotations": { "readOnlyHint": true }
            },
            {
                "name": "dbus_get",
                "description": "Reads one property of an object, as {\"type\": signature, \"data\": value}.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "service": service, "path": path, "interface": { "type": "string" }, "property": { "type": "string" } },
                    "required": ["service", "path", "interface", "property"]
                },
                "annotations": { "readOnlyHint": true }
            },
            {
                "name": "dbus_call",
                "description": "Calls a method, with its arguments as a JSON list in the order dbus_introspect shows (strings, numbers, booleans; a list for an array; an object for a dict, like a{sv}; a list for a struct). \
A variant (type v) is a plain value, or {\"type\": \"u\", \"data\": 5} to say which type. Answers {\"type\": signature, \"data\": [return values]}. This can change things, so you may be asked first.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "service": service,
                        "path": path,
                        "interface": { "type": "string" },
                        "method": { "type": "string" },
                        "args": { "type": "array", "description": "One value for each argument the method takes", "items": {} },
                        "signature": { "type": "string", "description": "Only if introspection can't tell: the method's input types, like \"su\"" }
                    },
                    "required": ["service", "path", "interface", "method"]
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": false }
            }
        ])
    }

    /// The answer to one JSON-RPC message, if it needs one.
    pub fn handle(&self, msg: &Value) -> Option<Value> {
        // Notifications (no id) get no reply.
        let id = msg.get("id")?.clone();
        let params = &msg["params"];
        let result = match msg.get("method").and_then(Value::as_str).unwrap_or("") {
            "initialize" => {
                let wanted = params["protocolVersion"].as_str().unwrap_or("");
                let version = crate::mcp::VERSIONS.iter().find(|v| **v == wanted).unwrap_or(&crate::mcp::VERSIONS[1]);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "agentos-dbus", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": format!(
                        "A bridge to the user's {} D-Bus bus, limited to: {}. Use dbus_services, then dbus_introspect to see what an object offers, then dbus_get or dbus_call.",
                        self.bus.name(),
                        self.services.join(", ")
                    ),
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tools() })),
            "tools/call" => {
                let (text, failed) = match self.call(params["name"].as_str().unwrap_or(""), &params["arguments"]) {
                    Ok(text) => (text, false),
                    Err(text) => (text, true),
                };
                Ok(json!({ "content": [{ "type": "text", "text": text }], "isError": failed }))
            }
            other => Err(json!({ "code": -32601, "message": format!("method not found: {other}") })),
        };
        Some(match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
        })
    }
}

/// `agent dbus-bridge`: serves MCP on stdin/stdout until it closes.
pub fn serve_stdio(bus: &str, services: Vec<String>) -> Result<()> {
    let Some(bus) = Bus::parse(bus) else { bail!("--bus is session or system, not {bus:?}") };
    if services.is_empty() {
        bail!("name the services this bridge may reach, with --service NAME");
    }
    if let Some(bad) = services.iter().find(|s| !valid_pattern(s)) {
        bail!("{bad:?} isn't a service name (like org.freedesktop.Notifications, or a family: org.mpris.MediaPlayer2.*)");
    }
    let bridge = Bridge::new(bus, services, Box::new(Busctl(bus)));
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => bridge.handle(&msg),
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
    use std::cell::RefCell;
    use std::rc::Rc;

    fn types(sig: &str) -> Vec<Ty> {
        parse_signature(sig).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The words for `values` against `sig`, or the complaint.
    fn flat(sig: &str, values: Value) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for (n, (ty, value)) in types(sig).iter().zip(values.as_array().unwrap()).enumerate() {
            words(ty, value, &format!("args[{n}]"), &mut out)?;
        }
        Ok(out)
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn signatures_are_read() {
        assert_eq!(types(""), []);
        assert_eq!(types("su"), [Ty::Basic('s'), Ty::Basic('u')]);
        assert_eq!(types("a{sv}"), [Ty::Array(Box::new(Ty::Entry(Box::new(Ty::Basic('s')), Box::new(Ty::Variant))))]);
        assert_eq!(types("(is)"), [Ty::Struct(vec![Ty::Basic('i'), Ty::Basic('s')])]);
        assert_eq!(types("aas").len(), 1);
        assert_eq!(types("a(sa{sv})").len(), 1);
        for bad in ["a", "(", "()", "{ss}", "a{s}", "a{(s)s}", "a{ss", "z", "(ii", "a{sss}", &"a".repeat(40)] {
            assert!(parse_signature(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn arguments_become_the_words_busctl_takes() {
        let cases: Vec<(&str, Value, &[&str])> = vec![
            ("su", json!(["x", 3]), &["x", "3"]),
            ("as", json!([["a", "b"]]), &["2", "a", "b"]),
            ("as", json!([[]]), &["0"]),
            ("a{ss}", json!([{ "k": "v" }]), &["1", "k", "v"]),
            ("a{ss}", json!([[["k", "v"], ["l", "w"]]]), &["2", "k", "v", "l", "w"]),
            ("a{iu}", json!([[[1, 2]]]), &["1", "1", "2"]),
            ("a{sv}", json!([{ "name": "x", "urgency": { "type": "y", "data": 1 } }]), &["2", "name", "s", "x", "urgency", "y", "1"]),
            ("a{sv}", json!([{}]), &["0"]),
            ("(si)", json!([["a", -1]]), &["a", "-1"]),
            ("a(si)", json!([[["a", 1], ["b", 2]]]), &["2", "a", "1", "b", "2"]),
            ("aas", json!([[["a"], ["b", "c"]]]), &["2", "1", "a", "2", "b", "c"]),
            ("ay", json!([[1, 2, 255]]), &["3", "1", "2", "255"]),
            ("v", json!(["hi"]), &["s", "hi"]),
            ("v", json!([5]), &["i", "5"]),
            ("v", json!([5_000_000_000i64]), &["x", "5000000000"]),
            ("v", json!([true]), &["b", "true"]),
            ("v", json!([1.5]), &["d", "1.5"]),
            ("v", json!([["a", "b"]]), &["as", "2", "a", "b"]),
            ("v", json!([{ "type": "as", "data": ["a"] }]), &["as", "1", "a"]),
            ("v", json!([{ "type": "v", "data": { "type": "u", "data": 7 } }]), &["v", "u", "7"]),
            ("b", json!([true]), &["true"]),
            ("b", json!(["false"]), &["false"]),
            ("d", json!([0.25]), &["0.25"]),
            ("i", json!(["-5"]), &["-5"]),
            ("t", json!([18446744073709551615u64]), &["18446744073709551615"]),
            ("oi", json!(["/org/x", 1]), &["/org/x", "1"]),
            ("g", json!(["a{sv}"]), &["a{sv}"]),
            ("ss", json!(["", "with space and \"quotes\""]), &["", "with space and \"quotes\""]),
        ];
        for (sig, values, want) in cases {
            assert_eq!(flat(sig, values.clone()), Ok(strings(want)), "{sig} {values}");
        }
        let refused: Vec<(&str, Value, &str)> = vec![
            ("s", json!([5]), "expected a string"),
            ("i", json!(["five"]), "expected an integer"),
            ("i", json!([2147483648i64]), "doesn't fit type i"),
            ("u", json!([-1]), "doesn't fit type u"),
            ("y", json!([256]), "doesn't fit type y"),
            ("n", json!([-32769]), "doesn't fit type n"),
            ("b", json!([1]), "expected true or false"),
            ("d", json!([true]), "expected a number"),
            ("as", json!(["x"]), "expected a list"),
            ("as", json!([[1]]), "args[0][0]: expected a string"),
            ("a{ss}", json!(["text"]), "expected an object"),
            ("a{ss}", json!([[["only one"]]]), "list of [key, value] pairs"),
            ("a{ss}", json!([{ "k": 1 }]), "args[0].k: expected a string"),
            ("(ii)", json!([[1]]), "a struct of 2 values, got 1"),
            ("(ii)", json!([5]), "expected a list of 2 values"),
            ("o", json!(["not a path"]), "isn't an object path"),
            ("g", json!(["(("]), "isn't a signature"),
            ("h", json!([3]), "file descriptors"),
            ("s", json!(["a\0b"]), "NUL"),
            ("v", json!([{}]), "say what type that variant is"),
            ("v", json!([[]]), "say what type that variant is"),
            ("v", json!([{ "type": "si", "data": 1 }]), "holds one value"),
            ("v", json!([{ "type": "q", "data": 70000 }]), "doesn't fit type q"),
        ];
        for (sig, values, why) in refused {
            let err = flat(sig, values.clone()).unwrap_err();
            assert!(err.contains(why), "{sig} {values}: {err}");
        }
        // Not a gigabyte of argv.
        let big = json!([vec![1; MAX_WORDS + 10]]);
        assert!(flat("ai", big).unwrap_err().contains("too many"));
    }

    const NOTIFICATIONS: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<!-- generated: a comment with <tags> in it -->
<node>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect"><arg name="xml_data" type="s" direction="out"/></method>
  </interface>
  <interface name="org.freedesktop.Notifications">
    <method name="Notify">
      <arg type="s" name="app_name" direction="in"/>
      <arg type="u" name="replaces_id" direction="in"/>
      <arg type="s" name="app_icon" direction="in"/>
      <arg type="s" name="summary" direction="in"/>
      <arg type="s" name="body" direction="in"/>
      <arg type="as" name="actions" direction="in"/>
      <arg type="a{sv}" name="hints" direction="in"/>
      <arg type="i" name="expire_timeout" direction="in"/>
      <arg type="u" name="id" direction="out"/>
      <annotation name="org.qtproject.QtDBus.QtTypeName.In6" value="QVariantMap"/>
    </method>
    <method name="GetServerInformation">
      <arg type="s" name="name" direction="out"/>
      <arg type="s" name="vendor" direction="out"/>
    </method>
    <method name="CloseNotification"><arg type="u"/></method>
    <signal name="NotificationClosed">
      <arg type="u" name="id"/>
      <arg type="u" name="reason"/>
    </signal>
    <property name="Version" type="s" access="read"/>
  </interface>
  <node name="inbox"/>
  <node name="archive"><node name="deeper"/></node>
</node>"#;

    #[test]
    fn introspection_is_read_and_shown() {
        let node = parse_introspection(NOTIFICATIONS).unwrap();
        assert_eq!(node.children, ["inbox", "archive"], "only the objects directly below");
        let interface = node.interfaces.iter().find(|i| i.name == "org.freedesktop.Notifications").unwrap();
        assert_eq!(interface.method_signature("Notify"), Some("susssasa{sv}i".to_string()));
        assert_eq!(interface.method_signature("GetServerInformation"), Some(String::new()), "outputs aren't inputs");
        assert_eq!(interface.method_signature("CloseNotification"), Some("u".to_string()), "no direction means in, for a method");
        assert_eq!(interface.method_signature("Nope"), None);
        let shown = render("org.freedesktop.Notifications", "/org/freedesktop/Notifications", &node);
        assert!(shown.contains("method Notify(s app_name, u replaces_id, s app_icon, s summary, s body, as actions, a{sv} hints, i expire_timeout) -> u id\n"), "{shown}");
        assert!(shown.contains("method GetServerInformation() -> s name, s vendor\n"), "{shown}");
        assert!(shown.contains("signal NotificationClosed(u id, u reason)\n"), "{shown}");
        assert!(shown.contains("property Version: s (read)\n"), "{shown}");
        assert!(shown.contains("objects below: /org/freedesktop/Notifications/inbox, /org/freedesktop/Notifications/archive\n"), "{shown}");
        assert!(!shown.contains("Introspectable"), "what every object has is left out");
        assert!(render("a.b", "/", &node).contains("objects below: /inbox, /archive"));
        assert!(parse_introspection("<node><interface name=\"a.b\"").is_err());
        assert_eq!(parse_introspection("").unwrap(), Node::default());
    }

    #[test]
    fn only_the_services_you_name_are_reachable() {
        let list = strings(&["org.freedesktop.Notifications", "org.mpris.MediaPlayer2.*"]);
        for yes in ["org.freedesktop.Notifications", "org.mpris.MediaPlayer2.vlc", "org.mpris.MediaPlayer2.firefox.instance_1234"] {
            assert!(allows(&list, yes), "{yes}");
        }
        for no in [
            "org.freedesktop.secrets",
            "org.freedesktop.Notifications.extra",
            "org.mpris.MediaPlayer2",
            "org.mpris.MediaPlayer2.",
            "org.mpris.MediaPlayer20.x",
            "org.mpris.MediaPlayer2x.y",
            ":1.42",
            "",
            "*",
            "org.freedesktop.Notifications ",
        ] {
            assert!(!allows(&list, no), "{no:?}");
        }
        assert!(!allows(&[], "org.freedesktop.Notifications"));
        for ok in ["org.freedesktop.Notifications", "org.mpris.MediaPlayer2.*", "com.example.App-1"] {
            assert!(valid_pattern(ok), "{ok}");
        }
        for bad in ["*", ".*", "org.*.x", "org.*", "nodots", ":1.5", "org..x", "org.1x", "a b.c", "org.freedesktop.*.*", ""] {
            assert!(!valid_pattern(bad), "{bad}");
        }
        assert!(valid_path("/") && valid_path("/org/freedesktop/Notifications") && valid_path("/a_1"));
        for bad in ["", "org", "/org/", "//", "/org//x", "/org/x y", "/org/x-y", "/org/../x"] {
            assert!(!valid_path(bad), "{bad:?}");
        }
        assert!(valid_interface("org.freedesktop.DBus.Properties") && !valid_interface("nodots") && !valid_interface("org.free-desktop.x"));
        assert!(valid_member("Notify") && !valid_member("") && !valid_member("a.b") && !valid_member("1a"));
    }

    /// A bus for tests: answers each `busctl` line from a table, and remembers the lines.
    struct Stand {
        seen: Rc<RefCell<Vec<Vec<String>>>>,
        answer: Box<dyn Fn(&[String]) -> Result<String, String>>,
    }

    impl Runner for Stand {
        fn run(&self, args: &[String]) -> Result<String, String> {
            self.seen.borrow_mut().push(args.to_vec());
            (self.answer)(args)
        }
    }

    fn bridge(services: &[&str], answer: impl Fn(&[String]) -> Result<String, String> + 'static) -> (Bridge, Rc<RefCell<Vec<Vec<String>>>>) {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let stand = Stand { seen: seen.clone(), answer: Box::new(answer) };
        (Bridge::new(Bus::Session, strings(services), Box::new(stand)), seen)
    }

    fn typed(sig: &str, data: Value) -> String {
        json!({ "type": sig, "data": data }).to_string()
    }

    #[test]
    fn a_call_is_typed_by_the_object_and_sent_as_words() {
        let (b, seen) = bridge(&["org.freedesktop.Notifications"], |a| match a[0].as_str() {
            "call" if a[4] == "Introspect" => Ok(typed("s", json!([NOTIFICATIONS]))),
            "call" if a[4] == "Notify" => Ok(typed("u", json!([42]))),
            "call" if a[4] == "CloseNotification" => Ok(String::new()),
            _ => Err(format!("unexpected {a:?}")),
        });
        let notify = json!({
            "service": "org.freedesktop.Notifications", "path": "/org/freedesktop/Notifications",
            "interface": "org.freedesktop.Notifications", "method": "Notify",
            "args": ["agent", 0, "", "Done", "The tests pass", [], { "urgency": { "type": "y", "data": 1 } }, 5000]
        });
        assert_eq!(b.call("dbus_call", &notify), Ok(typed("u", json!([42]))));
        let sent = seen.borrow().last().unwrap().clone();
        assert_eq!(
            sent,
            strings(&[
                "call", "org.freedesktop.Notifications", "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "Notify", "susssasa{sv}i", "agent", "0", "", "Done",
                "The tests pass", "0", "1", "urgency", "y", "1", "5000"
            ])
        );
        // Nothing to return is said so.
        let close = json!({ "service": "org.freedesktop.Notifications", "path": "/org/freedesktop/Notifications", "interface": "org.freedesktop.Notifications", "method": "CloseNotification", "args": [7] });
        assert_eq!(b.call("dbus_call", &close), Ok("(it returned nothing)".to_string()));
        // The wrong number of arguments, or the wrong sort, never reaches the bus.
        let before = seen.borrow().len();
        for (args, why) in [(json!([]), "takes 1 argument (u), and args has 0"), (json!([1, 2]), "and args has 2"), (json!(["seven"]), "expected an integer")] {
            let mut call = close.clone();
            call["args"] = args;
            assert!(b.call("dbus_call", &call).unwrap_err().contains(why), "{why}");
        }
        assert!(seen.borrow()[before..].iter().all(|line| line[4] == "Introspect"), "only the lookup was sent: {:?}", seen.borrow());
        // A method the object doesn't list.
        let mut missing = close.clone();
        missing["method"] = json!("Explode");
        assert!(b.call("dbus_call", &missing).unwrap_err().contains("has no method org.freedesktop.Notifications.Explode"));
        // An explicit signature skips the lookup.
        let (b, seen) = bridge(&["org.example.App"], |_| Ok(typed("s", json!(["ok"]))));
        let direct = json!({ "service": "org.example.App", "path": "/", "interface": "org.example.App", "method": "Say", "signature": "sb", "args": ["hi", true] });
        assert_eq!(b.call("dbus_call", &direct), Ok(typed("s", json!(["ok"]))));
        assert_eq!(seen.borrow().len(), 1);
        assert_eq!(seen.borrow()[0][5..], strings(&["sb", "hi", "true"])[..]);
        // No arguments, and an object that can't be introspected: still callable.
        let (b, seen) = bridge(&["org.example.App"], |a| if a[4] == "Introspect" { Err("no such object".into()) } else { Ok("{}".into()) });
        let plain = json!({ "service": "org.example.App", "path": "/", "interface": "org.example.App", "method": "Ping" });
        assert_eq!(b.call("dbus_call", &plain), Ok("{}".to_string()));
        assert_eq!(seen.borrow().last().unwrap().len(), 5);
        let with_args = json!({ "service": "org.example.App", "path": "/", "interface": "org.example.App", "method": "Ping", "args": [1] });
        assert!(b.call("dbus_call", &with_args).unwrap_err().contains("pass its signature too"));
    }

    #[test]
    fn nothing_outside_your_list_is_sent_to_the_bus() {
        let (b, seen) = bridge(&["org.freedesktop.Notifications"], |_| panic!("the bus must not be asked"));
        let call = |tool: &str, args: Value| b.call(tool, &args);
        for service in ["org.freedesktop.secrets", ":1.5", "org.freedesktop.Notifications.x", "", "org.freedesktop.Notifications\n"] {
            for (tool, extra) in [
                ("dbus_introspect", json!({})),
                ("dbus_get", json!({ "path": "/", "interface": "a.b", "property": "P" })),
                ("dbus_call", json!({ "path": "/", "interface": "a.b", "method": "M" })),
            ] {
                let mut args = extra;
                args["service"] = json!(service);
                let err = call(tool, args).unwrap_err();
                assert!(err.contains("isn't a service this server may use") || err.contains("service is required"), "{tool} {service:?}: {err}");
            }
        }
        // And what is allowed has to be well formed, too.
        let ok = "org.freedesktop.Notifications";
        for (tool, args, why) in [
            ("dbus_introspect", json!({ "service": ok, "path": "relative" }), "isn't an object path"),
            ("dbus_introspect", json!({ "service": ok, "path": 5 }), "path must be a string"),
            ("dbus_get", json!({ "service": ok, "interface": "a.b", "property": "P" }), "path is required"),
            ("dbus_get", json!({ "service": ok, "path": "/", "interface": "nodots", "property": "P" }), "isn't an interface name"),
            ("dbus_get", json!({ "service": ok, "path": "/", "interface": "a.b", "property": "P;rm" }), "isn't a valid property name"),
            ("dbus_call", json!({ "service": ok, "path": "/", "interface": "a.b", "method": "M N" }), "isn't a valid method name"),
            ("dbus_call", json!({ "service": ok, "path": "/", "interface": "a.b", "method": "M", "args": "x" }), "args is a list"),
            ("dbus_call", json!({ "service": ok, "path": "/", "interface": "a.b", "method": "M", "signature": 5 }), "signature is a string"),
            ("dbus_call", json!({ "service": ok, "path": "/", "interface": "a.b", "method": "M", "signature": "((", "args": [] }), "signature"),
            ("dbus_nope", json!({}), "unknown tool"),
        ] {
            let err = call(tool, args.clone()).unwrap_err();
            assert!(err.contains(why), "{tool} {args}: {err}");
        }
        assert!(seen.borrow().is_empty());
    }

    #[test]
    fn services_says_which_of_yours_are_there() {
        let (b, _) = bridge(&["org.freedesktop.Notifications", "org.mpris.MediaPlayer2.*", "org.example.Away"], |a| match a[4].as_str() {
            "ListNames" => Ok(typed("as", json!([["org.freedesktop.DBus", ":1.3", "org.freedesktop.secrets", "org.mpris.MediaPlayer2.vlc", "org.freedesktop.Notifications"]]))),
            "ListActivatableNames" => Ok(typed("as", json!([["org.example.Away", "org.freedesktop.Notifications", "org.gnome.Shell"]]))),
            _ => Err("no".into()),
        });
        let listed: Value = serde_json::from_str(&b.call("dbus_services", &json!({})).unwrap()).unwrap();
        assert_eq!(listed["bus"], "session");
        assert_eq!(
            listed["services"],
            json!([
                { "name": "org.example.Away", "running": false },
                { "name": "org.freedesktop.Notifications", "running": true },
                { "name": "org.mpris.MediaPlayer2.vlc", "running": true },
            ])
        );
        assert_eq!(listed["allowed"].as_array().unwrap().len(), 3);
        assert!(!listed.to_string().contains("secrets"), "other services aren't even named");
    }

    #[test]
    fn properties_and_errors_pass_through() {
        let (b, seen) = bridge(&["org.mpris.MediaPlayer2.*"], |a| match a[0].as_str() {
            "get-property" if a[4] == "PlaybackStatus" => Ok(typed("s", json!("Playing"))),
            _ => Err("Call failed: The name org.mpris.MediaPlayer2.vlc was not provided by any .service files".into()),
        });
        let get = json!({ "service": "org.mpris.MediaPlayer2.vlc", "path": "/org/mpris/MediaPlayer2", "interface": "org.mpris.MediaPlayer2.Player", "property": "PlaybackStatus" });
        assert_eq!(b.call("dbus_get", &get), Ok(typed("s", json!("Playing"))));
        assert_eq!(seen.borrow()[0], strings(&["get-property", "org.mpris.MediaPlayer2.vlc", "/org/mpris/MediaPlayer2", "org.mpris.MediaPlayer2.Player", "PlaybackStatus"]));
        let mut other = get.clone();
        other["property"] = json!("Volume");
        assert!(b.call("dbus_get", &other).unwrap_err().contains("was not provided by any .service files"));
    }

    #[test]
    fn busctl_is_told_where_the_options_end() {
        let argv = Busctl::argv(Bus::Session, &strings(&["call", "org.a.b", "/", "a.b", "M", "s", "--address=unix:path=/tmp/x"]));
        assert_eq!(argv[..5], strings(&["--user", "--json=short", "--no-pager", "--", "call"])[..], "nothing the agent says comes before the `--`");
        assert_eq!(Busctl::argv(Bus::System, &[])[0], "--system");
        assert!(!allows(&strings(&["-H.example"]), "-H.example"), "a name that looks like an option isn't one");
        assert!(!valid_pattern("-H.example"));
    }

    #[test]
    fn it_speaks_mcp() {
        let (b, _) = bridge(&["org.freedesktop.Notifications"], |_| Ok(typed("s", json!(["x"]))));
        let ask = |method: &str, params: Value| b.handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })).unwrap();
        let init = ask("initialize", json!({ "protocolVersion": "2025-06-18" }));
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(init["result"]["serverInfo"]["name"], "agentos-dbus");
        assert!(init["result"]["instructions"].as_str().unwrap().contains("org.freedesktop.Notifications"));
        let list = ask("tools/list", json!({}));
        let tools: Vec<(&str, bool)> = list["result"]["tools"].as_array().unwrap().iter().map(|t| (t["name"].as_str().unwrap(), t["annotations"]["readOnlyHint"].as_bool().unwrap())).collect();
        assert_eq!(tools, [("dbus_services", true), ("dbus_introspect", true), ("dbus_get", true), ("dbus_call", false)], "only calls can change things");
        for tool in list["result"]["tools"].as_array().unwrap() {
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
        let denied = ask("tools/call", json!({ "name": "dbus_get", "arguments": { "service": "org.freedesktop.secrets", "path": "/", "interface": "a.b", "property": "P" } }));
        assert_eq!(denied["result"]["isError"], true);
        assert!(denied["result"]["content"][0]["text"].as_str().unwrap().contains("isn't a service this server may use"));
        assert!(ask("resources/list", json!({})).get("error").is_some());
        assert!(b.handle(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).is_none());
        assert_eq!(ask("ping", json!({}))["result"], json!({}));
    }
}
