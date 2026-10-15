#[cfg(target_arch = "aarch64")]
mod aarch64_sha2;
mod batch_agnostic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_sha2;

use super::constants;
use crate::sha2::{Sha2, Strategy};
pub struct Sha512Core {
    hash: [u64; 8],
}

impl Sha2 for Sha512Core {
    type State = [u64; 8];
    type Output = [u8; 64];
    type Block = [u8; 128];

    const BLOCK_SIZE: usize = 128;
    const LENGTH_BYTES: usize = 16;

    fn initial_state() -> Self::State {
        constants::SHA512_INITIAL
    }

    fn compress(state: &mut Self::State, block: &Self::Block, strategy: Strategy) {
        process(state, block, strategy);
    }

    fn output(state: Self::State) -> Self::Output {
        state
            .into_iter()
            .flat_map(u64::to_be_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .expect("SHA-512 output is always 64 bytes")
    }
}

pub(crate) fn process(hash: &mut [u64; 8], content: &[u8; 128], stat: Strategy) {
    match stat {
        Strategy::SimdBatch => {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                x86_sha2::process(hash, content);
            };

            #[cfg(target_arch = "aarch64")]
            {
                aarch64_sha2::process(hash, content);
            }
        }
        Strategy::Batch => {
            batch_agnostic::process(hash, content);
        }
    }
}
