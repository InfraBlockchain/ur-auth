#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;

use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_std::vec::Vec;

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

type AssetId = u32;
type DataSetId = u32;
#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq, TypeInfo, MaxEncodedLen)]
pub struct DataSetMetadata<BoundedString> {
    dataset_id: DataSetId,
    asset_id: Option<AssetId>,
    name: BoundedString,
    description: BoundedString,
}

impl<BoundedString> DataSetMetadata<BoundedString> {
    pub fn new(id: DataSetId, name: BoundedString, description: BoundedString) -> Self {
        Self {
            dataset_id: id,
            asset_id: None,
            name,
            description
        }
    }
}

#[frame_support::pallet]
pub mod pallet {

    use super::*;
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The maximum length of a name or symbol stored on-chain.
		#[pallet::constant]
		type StringLimit: Get<u32>;
    }

    #[pallet::storage]
    pub type DataSet<T: Config> = StorageMap<_, Blake2_128Concat, DataSetId, DataSetMetadata<BoundedVec<u8, T::StringLimit>>>;

    #[pallet::storage]
    pub type DataSetCounter<T: Config> = StorageValue<_, DataSetId, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DataSetRegistered { producer: T::AccountId, dataset_id: DataSetId }
    }

    #[pallet::error]
    pub enum Error<T> {
        BadMetadata,
        Overflow,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(1_000)]
        pub fn register_dataset(origin: OriginFor<T>, name: Vec<u8>, description: Vec<u8>) -> DispatchResult {
            let producer = ensure_signed(origin)?;

            let bounded_name: BoundedVec<u8, T::StringLimit> = name.try_into().map_err(|_| Error::<T>::BadMetadata)?;
            let bounded_description: BoundedVec<u8, T::StringLimit> = description.try_into().map_err(|_| Error::<T>::BadMetadata)?;
            let dataset_id = Self::dataset_id()?;
            let dataset_metadata = DataSetMetadata::<BoundedVec<u8, T::StringLimit>>::new(dataset_id, bounded_name, bounded_description);
            DataSet::<T>::insert(dataset_id, dataset_metadata);
            Self::deposit_event(Event::<T>::DataSetRegistered { producer, dataset_id });

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn dataset_id() -> Result<DataSetId, DispatchError> {
        let dataset_id = DataSetCounter::<T>::get();
        DataSetCounter::<T>::try_mutate(|c| -> DispatchResult {
            *c = c.checked_add(1).ok_or(Error::<T>::Overflow)?;
            Ok(())
        })?;
        Ok(dataset_id)
    }
}

