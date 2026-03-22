use serde_json::{Value,Map};
use p256::ecdsa::{SigningKey,VerifyingKey,Signature};
use p256::ecdsa::signature::{Signer,Verifier};
use base64::{engine::general_purpose,Engine as _};

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct OpenClaim;

impl OpenClaim {

	// ---------- CACHE ----------

	fn cache() -> &'static Mutex<HashMap<String,(u64,String)>> {
		use std::sync::OnceLock;
		static CACHE: OnceLock<Mutex<HashMap<String,(u64,String)>>> = OnceLock::new();
		CACHE.get_or_init(|| Mutex::new(HashMap::new()))
	}

	fn now() -> u64 {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_secs()
	}

	fn fetch_cached(url: &str) -> Option<String> {

		let ttl = 300; // seconds
		let now = Self::now();

		{
			let cache = Self::cache().lock().unwrap();

			if let Some((t,val)) = cache.get(url) {
				if now - *t < ttl {
					return Some(val.clone());
				}
			}
		}

		// lazy dependency: only if used
		let body = match ureq::get(url).call() {
			Ok(res) => res.into_string().ok(),
			Err(_) => None
		};

		let mut cache = Self::cache().lock().unwrap();

		cache.insert(
			url.to_string(),
			(now, body.clone().unwrap_or_default())
		);

		body
	}

	pub fn clear_fetch_cache(url: Option<&str>) {

		let mut cache = Self::cache().lock().unwrap();

		if let Some(u) = url {
			cache.remove(u);
		} else {
			cache.clear();
		}
	}

	fn normalize(v: Value) -> Value {
		match v {

			Value::Array(a) =>
				Value::Array(a.into_iter().map(Self::normalize).collect()),

			Value::Object(m) => {
				let mut keys: Vec<_> = m.keys().cloned().collect();
				keys.sort();

				let mut out = Map::new();

				for k in keys {
					out.insert(k.clone(),Self::normalize(m[&k].clone()));
				}

				Value::Object(out)
			}

			_ => v
		}
	}

	fn fallback(mut claim: Value) -> String {

		if let Some(o) = claim.as_object_mut() {
			o.remove("sig");
		}

		let sorted = Self::normalize(claim);

		serde_json::to_string(&sorted).unwrap()
	}

	pub fn canonicalize(claim: Value) -> String {

		let mut obj = claim.clone();

		if let Some(o) = obj.as_object_mut() {
			o.remove("sig");
		}

		if let Ok(s) = jcs::to_string(&obj) {
			return s
		}

		Self::fallback(claim)
	}

	// ---------- NEW HELPERS ----------

	fn to_array(v: Option<&Value>) -> Vec<Value> {
		match v {
			None => vec![],
			Some(Value::Array(a)) => a.clone(),
			Some(x) => vec![x.clone()]
		}
	}

	fn to_string_vec(v: Option<&Value>) -> Vec<Option<String>> {
		Self::to_array(v)
			.into_iter()
			.map(|x| match x {
				Value::Null => None,
				Value::String(s) => Some(s),
				_ => None
			})
			.collect()
	}

	fn ensure_sorted(keys: &Vec<String>) {
		let mut sorted = keys.clone();
		sorted.sort();
		if *keys != sorted {
			panic!("keys must be lexicographically sorted");
		}
	}

	fn pem_to_der(pem: &str) -> String {
		pem
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")
			.replace("\n", "")
			.trim()
			.to_string()
	}

	fn der_to_key(base64_der: &str) -> VerifyingKey {
		let bytes = general_purpose::STANDARD.decode(base64_der).unwrap();
		VerifyingKey::from_sec1_bytes(&bytes).unwrap()
	}

	fn resolve_key(key: &str) -> Option<(String,String)> {

		let parts: Vec<&str> = key.splitn(2, ':').collect();
		if parts.len() < 2 { return None }

		let typ = parts[0].to_uppercase();
		let rest = parts[1];

		if rest.starts_with("http://") || rest.starts_with("https://") {

			let segments: Vec<&str> = rest.split('#').collect();
			let url = segments[0];

			let raw = Self::fetch_cached(url)?;
			let json: Value = serde_json::from_str(&raw).ok()?;

			let mut current = json;

			for seg in segments.iter().skip(1) {
				if seg.is_empty() { continue }
				current = current.get(*seg)?.clone();
			}

			let val = current.as_str()?.to_string();

			return Some((typ,val));
		}

		Some((typ,rest.to_string()))
	}

	// ---------- SIGN ----------

	pub fn sign(claim: Value,key:&SigningKey) -> Value {
		Self::sign_with_existing(claim,key,Value::Null)
	}

	pub fn sign_with_existing(mut claim: Value,key:&SigningKey,existing: Value) -> Value {

		let mut keys: Vec<String> =
			Self::to_array(existing.get("keys"))
				.into_iter()
				.filter_map(|v| v.as_str().map(|s| s.to_string()))
				.collect();

		let mut sigs = Self::to_string_vec(existing.get("signatures"));

		let pubkey = VerifyingKey::from(key);
		let der = pubkey.to_encoded_point(false).as_bytes().to_vec();

		let key_str = format!(
			"es256:{}",
			general_purpose::STANDARD.encode(der)
		);

		if !keys.contains(&key_str) {
			keys.push(key_str.clone());
		}

		keys.sort();
		Self::ensure_sorted(&keys);

		while sigs.len() < keys.len() {
			sigs.push(None);
		}

		let index = keys.iter().position(|k| k == &key_str).unwrap();

		let mut tmp = claim.clone();
		tmp["key"] = Value::Array(keys.iter().map(|k| Value::String(k.clone())).collect());
		tmp["sig"] = Value::Array(
			sigs.iter().map(|s| match s {
				Some(v)=>Value::String(v.clone()),
				None=>Value::Null
			}).collect()
		);

		let canon = Self::canonicalize(tmp);

		let sig: Signature = key.sign(canon.as_bytes());

		sigs[index] = Some(
			general_purpose::STANDARD.encode(sig.to_bytes())
		);

		claim["key"] = Value::Array(keys.iter().map(|k| Value::String(k.clone())).collect());

		claim["sig"] = Value::Array(
			sigs.iter().map(|s| match s {
				Some(v)=>Value::String(v.clone()),
				None=>Value::Null
			}).collect()
		);

		claim
	}

	// ---------- VERIFY ----------

	pub fn verify(claim: Value,key:&VerifyingKey) -> bool {
		Self::verify_with_policy(claim,key,Value::Null)
	}

	pub fn verify_with_policy(mut claim: Value,_:&VerifyingKey,policy: Value) -> bool {

		let keys: Vec<String> =
			Self::to_array(claim.get("key"))
				.into_iter()
				.filter_map(|v| v.as_str().map(|s| s.to_string()))
				.collect();

		let sigs = Self::to_string_vec(claim.get("sig"));

		if keys.is_empty() || sigs.is_empty() {
			return false
		}

		if keys.len() != sigs.len() {
			return false
		}

		Self::ensure_sorted(&keys);

		let mut tmp = claim.clone();

		tmp["key"] = Value::Array(keys.iter().map(|k| Value::String(k.clone())).collect());

		tmp["sig"] = Value::Array(
			sigs.iter().map(|s| match s {
				Some(v)=>Value::String(v.clone()),
				None=>Value::Null
			}).collect()
		);

		let canon = Self::canonicalize(tmp);

		let mut valid = 0;

		for i in 0..keys.len() {

			let sig_b64 = match &sigs[i] {
				Some(s)=>s,
				None=>continue
			};

			let (typ,val) = match Self::resolve_key(&keys[i]) {
				Some(v)=>v,
				None=>continue
			};

			if typ == "EIP712" { continue }
			if typ != "ES256" { continue }

			let key = match VerifyingKey::from_sec1_bytes(
				&general_purpose::STANDARD.decode(val).unwrap()
			) {
				Ok(k)=>k,
				Err(_)=>continue
			};

			let sig_bytes = match general_purpose::STANDARD.decode(sig_b64) {
				Ok(v)=>v,
				Err(_)=>continue
			};

			let sig = match Signature::from_bytes(&sig_bytes) {
				Ok(s)=>s,
				Err(_)=>continue
			};

			if key.verify(canon.as_bytes(),&sig).is_ok() {
				valid += 1;
			}
		}

		let mut min_valid = 1;

		if let Some(m) = policy.get("minValid") {
			if let Some(v) = m.as_u64() {
				min_valid = v as usize;
			}
		}

		if policy.get("mode") == Some(&Value::String("all".into())) {
			min_valid = keys.len();
		}

		valid >= min_valid
	}
}