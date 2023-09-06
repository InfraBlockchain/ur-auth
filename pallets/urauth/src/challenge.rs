
pub use super::*;

pub type AccountIdFor<T> = <T as frame_system::Config>::AccountId; 
pub trait ChallengeValueInterface<T: Config> {

    type Account;
    type ChallengeValue;

    fn handle_challenge_json(raw_json: &Vec<u8>) -> Result<Self::ChallengeValue, DispatchError>;

    fn challenge_value(
        json_object: &lite_json::JsonObject,
        field_name: &str,
        sub_field: Option<&str>
    ) -> Result<Option<Vec<u8>>, DispatchError>;

    fn verify_challenge_value() -> Option<Self::Account>;
}

pub struct ChallengeValueFieldsV1;

impl<T: Config> ChallengeValueInterface<T> for ChallengeValueFieldsV1 {
    type Account = AccountIdFor<T>;
    type ChallengeValue = (Vec<u8>, Vec<u8>, Vec<u8>, URI, Vec<u8>, Vec<u8>);

    fn handle_challenge_json(raw_json: &Vec<u8>) -> Result<Self::ChallengeValue, DispatchError> {

        let json = sp_std::str::from_utf8(raw_json)
            .map_err(|_| Error::<T>::ErrorConvertToString)?;

        match lite_json::parse_json(json) {
            Ok(obj) => match obj {
                // ToDo: Check domain, admin_did, challenge
                lite_json::JsonValue::Object(obj) => {
                    let uri = <Self as ChallengeValueInterface<T>>::challenge_value(&obj, "domain", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let owner_did = <Self as ChallengeValueInterface<T>>::challenge_value(&obj, "adminDID", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let challenge = <Self as ChallengeValueInterface<T>>::challenge_value(&obj, "challenge", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let timestamp = <Self as ChallengeValueInterface<T>>::challenge_value(&obj, "timestamp", None)?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let proof_type = <Self as ChallengeValueInterface<T>>::challenge_value(&obj, "proof", Some("type"))?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let hex_proof = <Self as ChallengeValueInterface<T>>::challenge_value(&obj, "proof", Some("proofValue"))?
                        .ok_or(Error::<T>::BadChallengeValue)?;
                    let mut proof = [0u8; 64];
                    hex::decode_to_slice(hex_proof, &mut proof as &mut [u8])
                        .map_err(|_| Error::<T>::ErrorDecodeHex)?;
                    let mut raw_payload: Vec<u8> = Default::default();
                    let raw_owner_did = owner_did.clone();
                    URAuthSignedPayload::<T::AccountId>::Challenge {
                        uri: URI::new(uri.clone()),
                        owner_did,
                        challenge: challenge.clone(),
                        timestamp,
                    }
                    .using_encoded(|m| raw_payload = m.to_vec());

                    return Ok((
                        proof.to_vec(),
                        proof_type,
                        raw_payload,
                        URI::new(uri),
                        raw_owner_did,
                        challenge,
                    ));
                }
                _ => return Err(Error::<T>::BadChallengeValue.into()),
            },
            Err(_) => return Err(Error::<T>::BadChallengeValue.into()),
        }
    }

    fn challenge_value(
        json_object: &lite_json::JsonObject,
        field_name: &str,
        sub_field: Option<&str>
    ) -> Result<Option<Vec<u8>>, DispatchError> {

        Ok(None)
    }

    fn verify_challenge_value() -> Option<Self::Account> {
        None
    }
}