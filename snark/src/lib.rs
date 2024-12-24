pub type Error = Box<dyn ark_std::error::Error>;

pub mod gadget;

#[cfg(feature = "registerdata")]
pub mod registerdata;

// circuits
#[cfg(feature = "accepttrade")]
pub mod accepttrade;

#[cfg(feature = "generatetrade")]
pub mod generatetrade;

#[cfg(feature = "cc-snark")]
pub mod cc_snark;

// API
#[cfg(feature = "api")]
pub mod api;
