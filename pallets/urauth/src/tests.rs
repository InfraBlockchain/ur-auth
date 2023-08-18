#[test]
fn json_parse_works() {
    use lite_json::{json_parser::parse_json, JsonValue};

    let json_string = r#"
        {
            "domain" : "website1.com",
            "adminDID" : "did:infra:ua:i3jr3...qW3dt",
            "challenge" : "__random_challenge_value__",
            "timestamp": "2023-07-28T10:17:21Z",
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-07-28T17:29:31Z",
                "verificationMethod": "did:infra:ua:i3jr3...qW3dt#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "gweEDz58DAdFfa9.....CrfFPP2oumHKtz"
            }
        } 
	"#;
    let json_data = parse_json(json_string).expect("Invalid!");
    let mut domain: String = "".into();
    let mut admin_did: String = "".into();
    let mut challenge: String = "".into();
    let mut timestamp: String = "".into();
    let mut proof: String = "".into();
    match json_data {
        JsonValue::Object(obj_value) => {
            domain = find_json_value(obj_value.clone(), "domain".into()).unwrap();
            admin_did = find_json_value(obj_value.clone(), "adminDID".into()).unwrap();
            challenge = find_json_value(obj_value.clone(), "challenge".into()).unwrap();
            timestamp = find_json_value(obj_value.clone(), "timestamp".into()).unwrap();
            proof = find_json_value(obj_value.clone(), "proof".into()).unwrap();
        }
        _ => {}
    }
    let did_clone = admin_did.clone();
    let pk = did_clone.split(':').collect::<Vec<&str>>();
    println!(
        "도메인 => {:?}, 어드민 => {:?}, 퍼블릭키 => {:?}, 챌린지 => {:?}, 타임스탬프 => {:?}, 프루프 => {:?}",
        domain, admin_did, pk.last().unwrap(), challenge, timestamp, proof
    );
}

fn find_json_value(json_object: lite_json::JsonObject, field_name: String) -> Option<String> {
    let (_, json_value) = json_object
        .iter()
        .find(|(field, _)| field.iter().copied().eq(field_name.chars()))
        .unwrap();
    match json_value {
        lite_json::JsonValue::String(v) => Some(v.iter().collect::<String>()),
        lite_json::JsonValue::Object(v) => find_json_value(v.clone(), "proofValue".into()),
        _ => None,
    }
}
