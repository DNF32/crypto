#[cfg(target_arch = "aarch64")]
mod aarch64_sha2;
mod batch_agnostic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_sha2;

use super::constants;
use crate::sha2::{Sha2, Strategy, constants::SHA256_INITIAL};
pub struct Sha256Core {
    hash: [u32; 8],
}

impl Sha2 for Sha256Core {
    type State = [u32; 8];
    type Output = [u8; 32];
    type Block = [u8; 64];

    const BLOCK_SIZE: usize = 64;
    const LENGTH_BYTES: usize = 8;

    fn initial_state() -> Self::State {
        constants::SHA256_INITIAL
    }

    fn compress(state: &mut Self::State, block: &Self::Block, strategy: Strategy) {
        process(state, block, strategy);
    }

    fn output(state: Self::State) -> Self::Output {
        state
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .expect("SHA-256 output is always 32 bytes")
    }
}

pub(crate) fn process(hash: &mut [u32; 8], content: &[u8; 64], stat: Strategy) {
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

//use crate::HasherAlg;
//use crate::sha2::constants;
//
//pub use crate::sha2::backend::Strategy;
//// Sha-256/224
//
//// Init structure
//impl CCSha256 {
//    pub) fn new(strategy: Strategy) -> Self {
//        CCSha256 {
//            hash: constants::SHA256_INITIAL,
//            strategy: strategy,
//            buffer: Vec::with_capacity(64),
//            message_len: 0,
//        }
//    }
//}
//impl HasherAlg for CCSha256 {
//    type Output = [u32; 8];
//    fn update(&mut self, input: impl AsRef<[u8]>) {
//        let input = input.as_ref();
//        self.message_len += input.len() as u64;
//
//        let buffer_size = self.buffer.len();
//
//        if buffer_size + input.len() < 64 {
//            self.buffer.extend_from_slice(input);
//            return;
//        }
//
//        let take = 64 - buffer_size;
//        let mut offset = take;
//
//        self.buffer.extend_from_slice(&input[0..offset]);
//        //assert!(self.buffer.len() == 64);
//
//        let mut buffer = std::mem::take(&mut self.buffer);
//        let base_block = buffer.as_slice().try_into().unwrap();
//        unsafe {
//            process(self.strategy.clone(), &mut self.hash, base_block);
//        }
//
//        while input.len() - offset >= 64 {
//            let block = &input[offset..(offset + 64)];
//            unsafe {
//                process(
//                    self.strategy.clone(),
//                    &mut self.hash,
//                    block.try_into().unwrap(),
//                );
//            }
//            offset += 64;
//        }
//
//        buffer.clear();
//        buffer.extend_from_slice(&input[offset..]);
//        self.buffer = buffer;
//    }
//
//    fn finalize(&mut self) -> [u32; 8] {
//        let bit_len = self.message_len * 8;
//
//        self.buffer.push(0x80);
//
//        while self.buffer.len() % 64 != 56 {
//            self.buffer.push(0);
//        }
//
//        self.buffer.extend_from_slice(&bit_len.to_be_bytes());
//
//        let final_blocks = std::mem::take(&mut self.buffer);
//        for block in final_blocks.chunks_exact(64) {
//            process(
//                self.strategy.clone(),
//                &mut self.hash,
//                block.try_into().unwrap(),
//            );
//        }
//
//        self.hash
//    }
//
//    fn dgst(contents: impl AsRef<[u8]>) -> String {
//        let mut hasher = CCSha256::new(Strategy::SimdBatch);
//        hasher.update(contents);
//        let out = hasher.finalize();
//        out.iter().map(|byte| format!("{:08x}", byte)).collect()
//    }
//}
