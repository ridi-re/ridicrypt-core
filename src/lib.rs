type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod decrypt;
pub mod exts;
pub mod global_key;
pub mod prelude;
pub mod settings;
mod utils;
