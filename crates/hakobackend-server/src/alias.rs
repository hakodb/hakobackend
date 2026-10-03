//! Path aliases: owner-declared rewrites for regular endpoints
//! (`/api/alias/...` -> a target path + query, issue #5).
//!
//! Pure syntax sugar (htaccess-RewriteRule spirit, not a script engine):
//! the rewritten request flows through the SAME router, auth, policy,
//! rate-limit and wstats as a direct call — downstream cannot tell the
//! difference. Policy applies to the TARGET (one rule surface).
//!
//! Match engine: exact segments + `:param` captures only (no regex —
//! regex on the hot path is a ReDoS budget nobody asked for). Query
//! templates substitute `{name}` captures; the request's own query
//! string MERGES (request wins on collision — explicit caller intent
//! beats the alias default).
//!
//! Load-time guards (fail-closed): pattern must start with `/`,
//! target must NOT start with `/api/alias/` (loop-safe: aliases never
//! chain), every `{name}` in target/query must have a `:name` capture
//! (typos refuse to boot, not silent empty strings), duplicate patterns
//! refused.

use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Alias {
    pub pattern: String,
    pub target_path: String,
    pub target_query: String,
    segs: Vec<Seg>,
    params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Exact(String),
    Param(String),
}

fn parse_pattern(pattern: &str) -> Result<(Vec<Seg>, Vec<String>), String> {
    if !pattern.starts_with('/') {
        return Err(format!("alias pattern must start with `/`: {pattern}"));
    }
    let mut segs = Vec::new();
    let mut params = Vec::new();
    for part in pattern.split('/').filter(|s| !s.is_empty()) {
        if let Some(name) = part.strip_prefix(':') {
            if name.is_empty() {
                return Err(format!("empty :param in {pattern}"));
            }
            params.push(name.to_string());
            segs.push(Seg::Param(name.to_string()));
        } else {
            segs.push(Seg::Exact(part.to_string()));
        }
    }
    if segs.is_empty() {
        return Err(format!("alias pattern has no segments: {pattern}"));
    }
    Ok((segs, params))
}

fn check_template(text: &str, params: &[String], what: &str) -> Result<(), String> {
    // Canonical alias shape is `name=<json>` (options={...}): split off
    // the envelope key and validate the JSON value's string-literal slots
    // only (structural braces are not typos there). Bare templates keep
    // the strict rule (every {name} must resolve).
    if let Some((_, value)) = text.split_once('=') {
        let value = value.trim();
        if value.starts_with('{') && value.ends_with('}') && balanced_braces(value) {
            return check_json_slots(value, params, what);
        }
    }
    check_bare_slots(text, params, what)
}

/// Balanced `{...}` ignoring `"..."` strings (escapes honored).
fn balanced_braces(s: &str) -> bool {
    let mut depth = 0i32;
    let mut instr = false;
    let mut esc = false;
    for c in s.chars() {
        if instr {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                instr = false;
            }
            continue;
        }
        match c {
            '"' => instr = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    !instr && depth == 0
}

/// Validate only the `{name}` slots that sit inside `"..."` string
/// values (the only place a capture can legally appear in JSON).
/// A `{...}` outside strings (object keys, structure) is skipped —
/// it is JSON, not a slot. Slot names must be captures.
fn check_json_slots(json: &str, params: &[String], what: &str) -> Result<(), String> {
    let bytes = json.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        // One string literal (escapes honored).
        i += 1;
        let start = i;
        let mut esc = false;
        while i < bytes.len() {
            match (bytes[i], esc) {
                (_, true) => esc = false,
                (b'\\', false) => esc = true,
                (b'"', false) => break,
                _ => {}
            }
            i += 1;
        }
        if i >= bytes.len() {
            return Err(format!("unclosed string in {what}"));
        }
        let lit = &json[start..i];
        i += 1;
        // Slots inside this literal.
        let mut j = 0;
        while let Some(open) = lit[j..].find('{') {
            let open = j + open;
            let Some(rel) = lit[open..].find('}') else {
                return Err(format!("unclosed {{ in {what}"));
            };
            let name = &lit[open + 1..open + rel];
            if !params.iter().any(|p| p == name) {
                return Err(format!("unknown {{{name}}} in {what} (captures: {params:?})"));
            }
            j = open + rel + 1;
        }
    }
    Ok(())
}

fn check_bare_slots(text: &str, params: &[String], what: &str) -> Result<(), String> {
    // Every {name} must resolve; stray braces are typos (fail closed).
    let mut i = 0;
    while let Some(open) = text[i..].find('{') {
        let open = i + open;
        let Some(close) = text[open..].find('}') else {
            return Err(format!("unclosed {{ in {what}: {text}"));
        };
        let close = open + close;
        let name = &text[open + 1..close];
        if !params.iter().any(|p| p == name) {
            return Err(format!("unknown {{{name}}} in {what} (captures: {params:?})"));
        }
        i = close + 1;
    }
    Ok(())
}

/// Validate + compile one alias declaration. Patterns are stored
/// WITHOUT the `/api/alias/` prefix (the middleware strips it before
/// matching): `/api/alias/students/:sid` compiles to `students/:sid`,
/// so a pattern can never accidentally match outside the alias router.
pub fn compile(pattern: &str, target_path: &str, target_query: &str) -> Result<Alias, String> {
    let stripped = pattern.strip_prefix("/api/alias/").ok_or_else(|| {
        format!("alias pattern must start with `/api/alias/`: {pattern}")
    })?;
    let (segs, params) = parse_pattern(&format!("/{stripped}"))?;
    if target_path.starts_with("/api/alias/") {
        return Err(format!("alias target must not chain into /api/alias/: {target_path}"));
    }
    if !target_path.starts_with("/api/") {
        return Err(format!("alias target must stay under /api/: {target_path}"));
    }
    check_template(target_path, &params, "target_path")?;
    check_template(target_query, &params, "target_query")?;
    Ok(Alias {
        pattern: pattern.into(),
        target_path: target_path.into(),
        target_query: target_query.into(),
        segs,
        params,
    })
}

/// Validate a whole table (duplicates refused). Order = declaration
/// order (first match wins — deterministic, documented).
pub fn compile_all(decls: &[(String, String, String)]) -> Result<Vec<Alias>, String> {
    let mut out = Vec::with_capacity(decls.len());
    for (p, tp, tq) in decls {
        if out.iter().any(|a: &Alias| a.pattern == *p) {
            return Err(format!("duplicate alias pattern: {p}"));
        }
        out.push(compile(p, tp, tq)?);
    }
    Ok(out)
}

fn substitute(template: &str, caps: &HashMap<&str, &str>) -> String {
    // Mirror of check_template: `name=<json>` templates substitute only
    // inside "..." string literals (structure byte-faithful); bare
    // templates substitute every {name}.
    if let Some((head, value)) = template.split_once('=') {
        if value.trim().starts_with('{')
            && value.trim().ends_with('}')
            && balanced_braces(value.trim())
            && !head.contains('{')
        {
            let mut out = String::with_capacity(template.len() + 16);
            out.push_str(head);
            out.push('=');
            out.push_str(&substitute_json(value, caps));
            return out;
        }
    }
    substitute_bare(template, caps)
}

/// Substitute `{name}` slots inside string literals of a JSON template
/// (byte-faithful elsewhere: structure, spacing, key order untouched).
fn substitute_json(template: &str, caps: &HashMap<&str, &str>) -> String {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len() + 16);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        out.push('"');
        i += 1;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i] as char);
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                out.push('"');
                i += 1;
                break;
            }
            if bytes[i] == b'{' {
                if let Some(rel) = template[i..].find('}') {
                    let name = &template[i + 1..i + rel];
                    if caps.contains_key(name) {
                        encode_into(&mut out, caps[name]);
                        i += rel + 1;
                        continue;
                    }
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn encode_into(out: &mut String, value: &str) {
    // Percent-encode the capture for its new home (path or query):
    // alphanumerics + -_.~ pass, the rest %XX (UTF-8 bytes). Captures
    // come from URL segments (already decoded once); without this a
    // `/` or `&` inside a value would break out of its slot.
    for b in value.as_bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
}

fn substitute_bare(template: &str, caps: &HashMap<&str, &str>) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut i = 0;
    while let Some(open) = template[i..].find('{') {
        let open = i + open;
        let close = open + template[open..].find('}').expect("checked at load");
        out.push_str(&template[i..open]);
        let name = &template[open + 1..close];
        encode_into(&mut out, caps.get(name).copied().unwrap_or(""));
        i = close + 1;
    }
    out.push_str(&template[i..]);
    out
}

/// Try one alias against a request path. Returns (target_path,
/// target_query) on segment-count + exact match.
fn try_match(alias: &Alias, path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() != alias.segs.len() {
        return None;
    }
    let mut caps: HashMap<&str, &str> = HashMap::with_capacity(alias.params.len());
    for (seg, part) in alias.segs.iter().zip(parts) {
        match seg {
            Seg::Exact(e) if e == part => {}
            Seg::Exact(_) => return None,
            Seg::Param(name) => {
                caps.insert(name, part);
            }
        }
    }
    Some((substitute(&alias.target_path, &caps), substitute(&alias.target_query, &caps)))
}

#[derive(Debug, Clone, Default)]
pub struct AliasTable {
    aliases: Arc<Vec<Alias>>,
}

impl AliasTable {
    pub fn new(aliases: Vec<Alias>) -> Self {
        Self {
            aliases: Arc::new(aliases),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty()
    }

    /// First-match rewrite (None = no alias; the router handles directly).
    pub fn rewrite(&self, path: &str) -> Option<(String, String)> {
        if self.aliases.is_empty() {
            return None;
        }
        self.aliases.iter().find_map(|a| try_match(a, path))
    }
}

/// Merge alias query (defaults) with the request query (wins).
/// Both are raw `k=v&...` strings; request keys shadow alias keys
/// (exact key match). Order: surviving alias pairs first, then the
/// request pairs verbatim.
pub fn merge_query(alias_q: &str, req_q: Option<&str>) -> String {
    let req_q = req_q.unwrap_or("");
    if alias_q.is_empty() {
        return req_q.to_string();
    }
    if req_q.is_empty() {
        return alias_q.to_string();
    }
    let req_keys: std::collections::HashSet<&str> = req_q
        .split('&')
        .map(|p| p.split('=').next().unwrap_or(""))
        .collect();
    let mut parts: Vec<&str> = alias_q
        .split('&')
        .filter(|p| !req_keys.contains(p.split('=').next().unwrap_or("")))
        .collect();
    parts.extend(req_q.split('&'));
    parts.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> AliasTable {
        match compile_all(&[(
            "/api/alias/students/:sid/:pin".into(),
            "/api/collections/students".into(),
            "options={\"filters\":[{\"field\":\"sid\",\"op\":\"==\",\"value\":\"{sid}\"},{\"field\":\"pin\",\"op\":\"==\",\"value\":\"{pin}\"}],\"limit\":1}".into(),
        )]) {
            Ok(v) => AliasTable::new(v),
            Err(e) => panic!("test table must compile: {e}"),
        }
    }

    /// Test helper: rewrite through the middleware's eyes (prefix strip).
    fn via_mw(t: &AliasTable, full_path: &str) -> Option<(String, String)> {
        let sub = full_path.strip_prefix("/api/alias").unwrap_or(full_path);
        t.rewrite(sub)
    }

    #[test]
    fn template_json_shape() {
        // options={...} is the canonical shape: structural braces are NOT
        // slots; unknown names INSIDE strings still refuse.
        assert!(compile(
            "/api/alias/a/:x",
            "/api/collections/c",
            "options={\"limit\":1,\"q\":\"{x}\"}",
        )
        .is_ok());
        assert!(compile(
            "/api/alias/a/:x",
            "/api/collections/c",
            "options={\"q\":\"{y}\"}",
        )
        .is_err());
        // Non-JSON templates keep the strict rule everywhere.
        assert!(compile("/api/alias/a/:x", "/api/c/{x}/tail", "").is_ok());
        assert!(compile("/api/alias/a/:x", "/api/c/{y}/tail", "").is_err());
    }

    #[test]
    fn rewrite_substitutes_and_merges() {
        let t = table();
        let (p, q) = via_mw(&t, "/api/alias/students/S1/987").expect("match");
        assert_eq!(p, "/api/collections/students");
        assert!(q.contains("\"S1\"") && q.contains("\"987\""));
        // Request query wins on collision, merges otherwise.
        let m = merge_query("a=1&b=2", Some("b=9&c=3"));
        assert_eq!(m, "a=1&b=9&c=3");
        assert_eq!(merge_query("", Some("x=1")), "x=1");
        assert_eq!(merge_query("a=1", None), "a=1");
    }

    #[test]
    fn no_match_and_encoding() {
        let t = table();
        assert!(via_mw(&t, "/api/alias/students/only-one").is_none());
        assert!(via_mw(&t, "/api/alias/other/S1/987").is_none());
        assert!(via_mw(&t, "/api/collections/students").is_none());
        // Captures encode for their slot: / & space cannot break out.
        let (p, q) = via_mw(&t, "/api/alias/students/a%2Fb/c%20d").unwrap();
        assert!(q.contains("a%2Fb") || q.contains("a%252Fb"));
        let _ = p;
    }

    #[test]
    fn load_guards() {
        assert!(compile("/nope", "/api/x", "").is_err());
        assert!(compile("/api/other", "/api/x", "").is_err());
        assert!(compile("/api/alias/a/:x", "/api/alias/b", "").is_err());
        assert!(compile("/api/alias/a/:x", "/other", "").is_err());
        assert!(compile("/api/alias/a/:x", "/api/x/{y}", "").is_err());
        assert!(compile("/api/alias/a/:x", "/api/x", "{unclosed").is_err());
        assert!(compile_all(&[
            ("/api/alias/a/:x".into(), "/api/x".into(), "".into()),
            ("/api/alias/a/:x".into(), "/api/y".into(), "".into()),
        ])
        .is_err());
        assert!(AliasTable::default().rewrite("/api/alias/a/b").is_none());
    }
}
