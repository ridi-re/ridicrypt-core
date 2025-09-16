type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod datastores;
pub mod decrypt;
pub mod exts;
pub mod prelude;
pub mod utils;
