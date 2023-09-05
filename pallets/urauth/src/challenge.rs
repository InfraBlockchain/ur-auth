
pub use super::*;

pub type AccountIdFor<T> = <T as frame_system::Config>::AccountId; 
pub trait ChallengeValueInterface<T: Config> {

    type Account;
    type ChallengeValue;

    fn handle_challenge_json() -> Self::ChallengeValue;

    fn verify_challenge_value() -> Option<Self::Account>;
}

pub struct ChallengeValueFieldsV1;

impl<T: Config> ChallengeValueInterface<T> for ChallengeValueFieldsV1 {
    type Account = AccountIdFor<T>;
    type ChallengeValue = (Vec<u8>, Vec<u8>, Vec<u8>, URI, Vec<u8>, Vec<u8>);

    fn handle_challenge_json() -> Self::ChallengeValue {
        (Default::default(), Default::default(), Default::default(), URI::new("".into()), Default::default(), Default::default())
    }

    fn verify_challenge_value() -> Option<Self::Account> {
        None
    }
}