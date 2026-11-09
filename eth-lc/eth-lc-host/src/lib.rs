//! Host-side support for `eth-lc-core`: Beacon API and SSZ decoding per fork,
//! recorded chain directories, key hints, checkpoint checks for new
//! instances, execution evidence, and synthetic test data.

pub mod chain_dir;
pub mod checkpoint;
pub mod evidence;
pub mod forks;
pub mod hints;
pub mod http;
pub mod synthetic;

pub use chain_dir::ChainDir;
pub use hints::key_hints;
