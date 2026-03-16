use serde_json::Value;

pub struct OpenClaim;

impl OpenClaim {

	pub fn canonicalize(mut claim: Value) -> String {
		claim.as_object_mut().unwrap().remove("sig");
		serde_json::to_string(&claim).unwrap()
	}

}