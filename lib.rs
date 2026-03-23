// Optional strict canonicalizer:
// cargo add jcs
// https://crates.io/crates/jcs
//
// HTTP fetch dependency used here:
// cargo add ureq
//
// Base64:
// cargo add base64
//
// JSON:
// cargo add serde_json
//
// P-256 + PKCS#8/SPKI DER support:
// cargo add p256 --features ecdsa,pkcs8
//
// SHA-256:
// cargo add sha2

use serde_json::{Map, Value};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct OpenClaim;

type OpenClaimResult<T> = Result<T, String>;

#[derive(Clone, Debug)]
struct KeyObj {
	fmt: String,
	value: KeyValue
}

#[derive(Clone, Debug)]
enum KeyValue {
	String(String),
	Bytes(Vec<u8>)
}

#[derive(Clone, Debug)]
enum ResolvedKey {
	One(KeyObj),
	Many(Vec<String>)
}

#[derive(Clone)]
struct TtlEntry<T: Clone> {
	val: T,
	exp: u64
}

impl OpenClaim {

	// ---------- CACHE ----------

	fn cache_ttl() -> u64 {
		60 // seconds, matching JS 60_000 ms
	}

	fn url_cache() -> &'static Mutex<HashMap<String, TtlEntry<Option<Value>>>> {
		static CACHE: OnceLock<Mutex<HashMap<String, TtlEntry<Option<Value>>>>> = OnceLock::new();
		CACHE.get_or_init(|| Mutex::new(HashMap::new()))
	}

	fn key_cache() -> &'static Mutex<HashMap<String, TtlEntry<Option<ResolvedKey>>>> {
		static CACHE: OnceLock<Mutex<HashMap<String, TtlEntry<Option<ResolvedKey>>>>> = OnceLock::new();
		CACHE.get_or_init(|| Mutex::new(HashMap::new()))
	}

	fn pubkey_cache() -> &'static Mutex<HashMap<String, TtlEntry<VerifyingKey>>> {
		static CACHE: OnceLock<Mutex<HashMap<String, TtlEntry<VerifyingKey>>>> = OnceLock::new();
		CACHE.get_or_init(|| Mutex::new(HashMap::new()))
	}

	fn now() -> u64 {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs()
	}

	fn get_cache<T: Clone>(
		cache: &Mutex<HashMap<String, TtlEntry<T>>>,
		key: &str
	) -> Option<T> {
		let now = Self::now();
		let mut cache = cache.lock().map_err(|_| ()).ok()?;

		if let Some(entry) = cache.get(key) {
			if now <= entry.exp {
				return Some(entry.val.clone());
			}
		}

		cache.remove(key);
		None
	}

	fn set_cache<T: Clone>(
		cache: &Mutex<HashMap<String, TtlEntry<T>>>,
		key: &str,
		val: T
	) {
		let mut cache = cache.lock().unwrap();
		cache.insert(
			key.to_string(),
			TtlEntry {
				val,
				exp: Self::now() + Self::cache_ttl()
			}
		);
	}

	pub fn clear_fetch_cache(url: Option<&str>) {
		let mut cache = Self::url_cache().lock().unwrap();

		if let Some(u) = url {
			cache.remove(u);
		} else {
			cache.clear();
		}
	}

	// ---------- EXISTING ----------

	fn normalize(v: Value) -> Value {
		match v {
			Value::Array(a) => Value::Array(a.into_iter().map(Self::normalize).collect()),

			Value::Object(m) => {
				let mut keys: Vec<_> = m.keys().cloned().collect();
				keys.sort();

				let mut out = Map::new();

				for k in keys {
					out.insert(k.clone(), Self::normalize(m.get(&k).cloned().unwrap_or(Value::Null)));
				}

				Value::Object(out)
			}

			Value::Number(n) => Value::String(n.to_string()),

			_ => v
		}
	}

	fn fallback_canonicalize(mut claim: Value) -> Vec<u8> {

		if let Some(o) = claim.as_object_mut() {
			o.remove("sig");
		}

		let sorted = Self::normalize(claim);

		serde_json::to_vec(&sorted)
			.map_err(|e| format!("OpenClaim: failed to serialize canonical JSON: {}", e))
			.unwrap()
	}

	pub fn canonicalize(claim: Value) -> Vec<u8> {

		let mut obj = claim.clone();

		if let Some(o) = obj.as_object_mut() {
			o.remove("sig");
		}

		match jcs::to_vec(&obj) {
			Ok(v) => v,
			Err(_) => Self::fallback_canonicalize(claim)
		}
	}

	// ---------- NEW HELPERS ----------

	fn to_array(v: Option<&Value>) -> Vec<Value> {
		match v {
			None => vec![],
			Some(Value::Array(a)) => a.clone(),
			Some(x) => vec![x.clone()]
		}
	}

	fn normalize_signatures(v: Option<&Value>) -> Vec<Option<String>> {
		Self::to_array(v)
			.into_iter()
			.map(|x| match x {
				Value::Null => None,
				Value::String(s) => Some(s),
				other => Some(match other {
					Value::Bool(b) => b.to_string(),
					Value::Number(n) => n.to_string(),
					Value::String(s) => s,
					_ => other.to_string()
				})
			})
			.collect()
	}

	fn ensure_string_keys(keys: &[String]) -> OpenClaimResult<()> {
		for _k in keys {
			// Rust type already guarantees String here.
		}
		Ok(())
	}

	fn ensure_unique_keys(keys: &[String]) -> OpenClaimResult<()> {
		let mut seen = HashSet::new();

		for k in keys {
			if !seen.insert(k.clone()) {
				return Err("OpenClaim: duplicate keys are not allowed".to_string());
			}
		}

		Ok(())
	}

	fn ensure_sorted_keys(keys: &[String]) -> OpenClaimResult<()> {
		let mut sorted = keys.to_vec();
		sorted.sort();

		if keys != sorted.as_slice() {
			return Err("OpenClaim: key array must be lexicographically sorted".to_string());
		}

		Ok(())
	}

	fn strip_pem_headers(pem: &str) -> String {
		pem
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")
			.replace(char::is_whitespace, "")
	}

	fn der_to_pem(base64_der: &str) -> String {
		let body = base64_der.trim();
		let mut lines = Vec::new();

		let mut i = 0usize;
		while i < body.len() {
			let end = std::cmp::min(i + 64, body.len());
			lines.push(body[i..end].to_string());
			i = end;
		}

		let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
		out.push_str(&lines.join("\n"));
		out.push_str("\n-----END PUBLIC KEY-----");
		out
	}

	fn pem_to_der(pem: &str) -> String {
		Self::strip_pem_headers(pem)
	}

	fn is_pem_public_key(v: &str) -> bool {
		v.contains("BEGIN PUBLIC KEY")
	}

	fn public_key_to_der_b64(pubkey: &VerifyingKey) -> OpenClaimResult<String> {
		let der = pubkey
			.to_public_key_der()
			.map_err(|e| format!("OpenClaim: failed to export public key DER: {}", e))?;

		Ok(general_purpose::STANDARD.encode(der.as_ref()))
	}

	fn to_es256_key_string_from_public_key(pubkey: &VerifyingKey) -> OpenClaimResult<String> {
		Ok(format!(
			"data:key/es256;base64,{}",
			Self::public_key_to_der_b64(pubkey)?
		))
	}

	fn to_base64_der_string(value: &KeyValue) -> String {
		match value {
			KeyValue::Bytes(bytes) => general_purpose::STANDARD.encode(bytes),
			KeyValue::String(s) => s.clone()
		}
	}

	fn sha256(data: &[u8]) -> Vec<u8> {
		let mut hasher = Sha256::new();
		hasher.update(data);
		hasher.finalize().to_vec()
	}

	fn value_to_sig_array(sigs: &[Option<String>]) -> Value {
		Value::Array(
			sigs
				.iter()
				.map(|s| match s {
					Some(v) => Value::String(v.clone()),
					None => Value::Null
				})
				.collect()
		)
	}

	fn value_to_key_array(keys: &[String]) -> Value {
		Value::Array(keys.iter().map(|k| Value::String(k.clone())).collect())
	}

	fn value_to_existing_keys(existing: &Value, claim: &Value) -> Vec<String> {
		if existing.get("keys").is_some() {
			Self::to_array(existing.get("keys"))
				.into_iter()
				.filter_map(|v| v.as_str().map(|s| s.to_string()))
				.collect()
		} else {
			Self::to_array(claim.get("key"))
				.into_iter()
				.filter_map(|v| v.as_str().map(|s| s.to_string()))
				.collect()
		}
	}

	fn value_to_existing_signatures(existing: &Value, claim: &Value) -> Vec<Option<String>> {
		if existing.get("signatures").is_some() {
			Self::normalize_signatures(existing.get("signatures"))
		} else {
			Self::normalize_signatures(claim.get("sig"))
		}
	}

	fn get_cached_public_key(base64_der: &str) -> OpenClaimResult<VerifyingKey> {

		if let Some(k) = Self::get_cache(Self::pubkey_cache(), base64_der) {
			return Ok(k);
		}

		let bytes = general_purpose::STANDARD
			.decode(base64_der)
			.map_err(|e| format!("OpenClaim: invalid base64 public key DER: {}", e))?;

		let key = VerifyingKey::from_public_key_der(&bytes)
			.map_err(|e| format!("OpenClaim: failed to parse public key DER: {}", e))?;

		Self::set_cache(Self::pubkey_cache(), base64_der, key.clone());

		Ok(key)
	}

	// ---------- NEW: DATA KEY PARSER ----------

	fn parse_data_key(key_str: &str) -> Option<KeyObj> {

		if !key_str.starts_with("data:key/") {
			return None;
		}

		let idx = key_str.find(',')?;
		let meta = &key_str[5..idx];
		let data = &key_str[idx + 1..];

		let mut parts = meta.split(';');
		let type_part = parts.next()?;
		let fmt = type_part.replace("key/", "").to_uppercase();

		let mut encoding = "raw";

		for p in parts {
			if p == "base64" {
				encoding = "base64";
			}
			if p == "base64url" {
				encoding = "base64url";
			}
		}

		let value = match encoding {
			"base64" => {
				let bytes = general_purpose::STANDARD.decode(data).ok()?;
				KeyValue::Bytes(bytes)
			}
			"base64url" => {
				let mut s = data.replace('-', "+").replace('_', "/");
				let rem = s.len() % 4;
				if rem != 0 {
					s.push_str(&"=".repeat(4 - rem));
				}
				let bytes = general_purpose::STANDARD.decode(s).ok()?;
				KeyValue::Bytes(bytes)
			}
			_ => KeyValue::String(data.to_string())
		};

		Some(KeyObj {
			fmt,
			value
		})
	}

	// ---------- FETCH ----------

	fn fetch_json(url: &str) -> Option<Value> {

		if let Some(cached) = Self::get_cache(Self::url_cache(), url) {
			return cached;
		}

		let json = match ureq::get(url).call() {
			Ok(mut res) => match res.body_mut().read_to_string() {
				Ok(body) => serde_json::from_str::<Value>(&body).ok(),
				Err(_) => None
			},
			Err(_) => None
		};

		Self::set_cache(Self::url_cache(), url, json.clone());

		json
	}

	// ---------- KEY RESOLUTION ----------

	fn resolve_key(key: &str) -> OpenClaimResult<Option<ResolvedKey>> {
		let seen = HashSet::new();
		Self::resolve_key_inner(key, &seen)
	}

	fn resolve_key_inner(
		key: &str,
		seen: &HashSet<String>
	) -> OpenClaimResult<Option<ResolvedKey>> {

		if seen.contains(key) {
			return Err("OpenClaim: cyclic key reference detected".to_string());
		}

		if let Some(cached) = Self::get_cache(Self::key_cache(), key) {
			return Ok(cached);
		}

		if key.is_empty() {
			return Ok(None);
		}

		let mut next_seen = seen.clone();
		next_seen.insert(key.to_string());

		// --- DATA URL ---
		if key.starts_with("data:key/") {
			if let Some(parsed) = Self::parse_data_key(key) {
				let out = Some(ResolvedKey::One(parsed));
				Self::set_cache(Self::key_cache(), key, out.clone());
				return Ok(out);
			}
		}

		// --- URL ---
		if key.starts_with("http://") || key.starts_with("https://") {
			let segments: Vec<&str> = key.split('#').collect();
			let url = segments[0];

			let json = Self::fetch_json(url);

			if json.is_none() {
				Self::set_cache(Self::key_cache(), key, None);
				return Ok(None);
			}

			let mut current = json.unwrap();

			for seg in segments.iter().skip(1) {
				if seg.is_empty() {
					continue;
				}

				current = match current.get(*seg) {
					Some(v) => v.clone(),
					None => {
						Self::set_cache(Self::key_cache(), key, None);
						return Ok(None);
					}
				};
			}

			if let Value::Array(arr) = current {
				let out: Vec<String> = arr
					.into_iter()
					.filter_map(|v| v.as_str().map(|s| s.to_string()))
					.collect();

				let resolved = Some(ResolvedKey::Many(out));
				Self::set_cache(Self::key_cache(), key, resolved.clone());
				return Ok(resolved);
			}

			if let Some(s) = current.as_str() {
				let resolved = Self::resolve_key_inner(s, &next_seen)?;
				Self::set_cache(Self::key_cache(), key, resolved.clone());
				return Ok(resolved);
			}

			Self::set_cache(Self::key_cache(), key, None);
			return Ok(None);
		}

		// --- LEGACY ---
		let parts: Vec<&str> = key.splitn(2, ':').collect();
		if parts.len() < 2 {
			return Ok(None);
		}

		let fmt = parts[0].to_uppercase();
		let rest = parts[1].to_string();

		let out = Some(ResolvedKey::One(KeyObj {
			fmt,
			value: KeyValue::String(rest)
		}));

		Self::set_cache(Self::key_cache(), key, out.clone());

		Ok(out)
	}

	// ---------- EXISTING ----------

	fn build_sorted_key_state(
		keys_input: Vec<String>,
		signatures_input: Vec<Option<String>>
	) -> OpenClaimResult<(Vec<String>, Vec<Option<String>>)> {

		let keys = keys_input;
		let signatures = signatures_input;

		Self::ensure_string_keys(&keys)?;
		Self::ensure_unique_keys(&keys)?;

		if signatures.len() > keys.len() {
			return Err("OpenClaim: signature array cannot be longer than key array".to_string());
		}

		let mut pairs: Vec<(String, Option<String>)> = keys
			.into_iter()
			.enumerate()
			.map(|(i, key)| {
				let sig = if i < signatures.len() {
					signatures[i].clone()
				} else {
					None
				};

				(key, sig)
			})
			.collect();

		pairs.sort_by(|a, b| a.0.cmp(&b.0));

		let sorted_keys: Vec<String> = pairs.iter().map(|p| p.0.clone()).collect();
		let sorted_sigs: Vec<Option<String>> = pairs.into_iter().map(|p| p.1).collect();

		Self::ensure_sorted_keys(&sorted_keys)?;

		Ok((sorted_keys, sorted_sigs))
	}

	fn parse_verify_policy(policy: &Value, total_keys: usize) -> usize {
		if policy.is_null() {
			return 1;
		}

		if let Some(n) = policy.as_u64() {
			return n as usize;
		}

		if policy.get("mode") == Some(&Value::String("all".into())) {
			return total_keys;
		}

		if let Some(n) = policy.get("minValid").and_then(|v| v.as_u64()) {
			return n as usize;
		}

		1
	}

	// ---------- SIGN ----------

	pub fn sign(claim: Value, key: &SigningKey) -> OpenClaimResult<Value> {
		Self::sign_with_existing(claim, key, Value::Null)
	}

	pub fn sign_with_existing(mut claim: Value, key: &SigningKey, existing: Value) -> OpenClaimResult<Value> {

		let mut keys = Self::value_to_existing_keys(&existing, &claim);
		let sigs = Self::value_to_existing_signatures(&existing, &claim);

		let pubkey = VerifyingKey::from(key);
		let signer_key = Self::to_es256_key_string_from_public_key(&pubkey)?;

		if keys.is_empty() {
			keys = vec![signer_key.clone()];
		} else if !keys.contains(&signer_key) {
			keys.push(signer_key.clone());
		}

		let (sorted_keys, mut sorted_sigs) = Self::build_sorted_key_state(keys, sigs)?;
		let signer_index = sorted_keys
			.iter()
			.position(|k| k == &signer_key)
			.ok_or_else(|| "OpenClaim: signer key missing after key-state build".to_string())?;

		let mut tmp = claim.clone();
		tmp["key"] = Self::value_to_key_array(&sorted_keys);
		tmp["sig"] = Self::value_to_sig_array(&sorted_sigs);

		let canon = Self::canonicalize(tmp);
		let hash = Self::sha256(&canon);

		let sig: Signature = key
			.sign_prehash(&hash)
			.map_err(|e| format!("OpenClaim: failed to sign claim: {}", e))?;

		sorted_sigs[signer_index] = Some(
			general_purpose::STANDARD.encode(sig.to_der().as_bytes())
		);

		claim["key"] = Self::value_to_key_array(&sorted_keys);
		claim["sig"] = Self::value_to_sig_array(&sorted_sigs);

		Ok(claim)
	}

	// ---------- VERIFY ----------

	pub fn verify(claim: Value) -> OpenClaimResult<bool> {
		Self::verify_with_policy(claim, Value::Null)
	}

	pub fn verify_with_policy(mut claim: Value, policy: Value) -> OpenClaimResult<bool> {

		let keys: Vec<String> =
			Self::to_array(claim.get("key"))
				.into_iter()
				.filter_map(|v| v.as_str().map(|s| s.to_string()))
				.collect();

		let sigs = Self::normalize_signatures(claim.get("sig"));

		if keys.is_empty() {
			return Err("OpenClaim: missing public keys".to_string());
		}

		let (sorted_keys, sorted_sigs) = Self::build_sorted_key_state(keys, sigs)?;

		tmp_claim_set(&mut claim, &sorted_keys, &sorted_sigs);

		let canon = Self::canonicalize(claim.clone());
		let hash = Self::sha256(&canon);

		let mut valid = 0usize;

		for i in 0..sorted_keys.len() {

			let sig_b64 = match &sorted_sigs[i] {
				Some(s) => s,
				None => continue
			};

			let resolved = match Self::resolve_key(&sorted_keys[i])? {
				Some(v) => v,
				None => continue
			};

			let mut key_objs: Vec<KeyObj> = Vec::new();

			match resolved {
				ResolvedKey::One(obj) => {
					key_objs.push(obj);
				}
				ResolvedKey::Many(arr) => {
					for item in arr {
						match Self::resolve_key(&item)? {
							Some(ResolvedKey::One(obj)) => key_objs.push(obj),
							_ => {}
						}
					}
				}
			}

			for ko in key_objs {

				if ko.fmt == "ES256" {
					let der_b64 = Self::to_base64_der_string(&ko.value);

					let pubkey = match Self::get_cached_public_key(&der_b64) {
						Ok(k) => k,
						Err(_) => continue
					};

					let sig_bytes = match general_purpose::STANDARD.decode(sig_b64) {
						Ok(v) => v,
						Err(_) => continue
					};

					let sig = match Signature::from_der(&sig_bytes) {
						Ok(s) => s,
						Err(_) => continue
					};

					if pubkey.verify_prehash(&hash, &sig).is_ok() {
						valid += 1;
						break;
					}
				}

				if ko.fmt == "EIP712" {
					// punt
					continue;
				}
			}
		}

		Ok(valid >= Self::parse_verify_policy(&policy, sorted_keys.len()))
	}
}

fn tmp_claim_set(claim: &mut Value, keys: &[String], sigs: &[Option<String>]) {
	claim["key"] = Value::Array(keys.iter().map(|k| Value::String(k.clone())).collect());
	claim["sig"] = Value::Array(
		sigs.iter().map(|s| match s {
			Some(v) => Value::String(v.clone()),
			None => Value::Null
		}).collect()
	);
}