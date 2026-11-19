//! Generated gRPC types for the agent <-> controller protocol.

#[allow(clippy::result_large_err)] // tonic's Status is large; generated code
pub mod v1 {
    tonic::include_proto!("df2b.v1");
}

mod convert;

pub use convert::{from_unix_ms, origin_string, to_unix_ms};
