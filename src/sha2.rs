mod constants;
mod sha256;
mod sha512;
mod utils;

use crate::HasherAlg;
use crate::sha2::sha256::Sha256Core;
use crate::sha2::sha512::Sha512Core;

pub trait Sha2 {
    type State;
    type Output;
    type Block: AsRef<[u8]>;

    const BLOCK_SIZE: usize;
    const LENGTH_BYTES: usize;

    fn initial_state() -> Self::State;

    fn compress(state: &mut Self::State, block: &Self::Block, strategy: Strategy);

    fn output(state: Self::State) -> Self::Output;
}

pub struct Sha2Hasher<A: Sha2> {
    state: A::State,
    buffer: Vec<u8>,
    message_len: u128,
    strategy: Strategy,
}

impl<A: Sha2> Sha2Hasher<A> {
    pub fn new(strategy: Strategy) -> Self {
        Self {
            state: A::initial_state(),
            buffer: Vec::new(),
            message_len: 0,
            strategy,
        }
    }
}

impl HasherAlg for Sha2Hasher<Sha256Core> {
    type Output = <Sha256Core as Sha2>::Output;

    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.message_len += input.len() as u128;

        let diff = Sha256Core::BLOCK_SIZE - self.buffer.len();
        let input = if self.buffer.len() + input.len() >= Sha256Core::BLOCK_SIZE {
            self.buffer.extend_from_slice(&input[0..diff]);
            let block: &[u8; Sha256Core::BLOCK_SIZE] = &self
                .buffer
                .as_slice()
                .try_into()
                .expect("buffer contains exacty one block");
            Sha256Core::compress(&mut self.state, &block, self.strategy.clone());
            self.buffer.clear();
            &input[diff..]
        } else {
            input
        };

        for chunk in input.chunks(Sha256Core::BLOCK_SIZE) {
            if chunk.len() < Sha256Core::BLOCK_SIZE {
                self.buffer.extend_from_slice(chunk);
                break;
            }
            Sha256Core::compress(
                &mut self.state,
                chunk.try_into().unwrap(),
                self.strategy.clone(),
            );
        }
    }

    fn finalize(mut self) -> Self::Output {
        let bit_len = (self.message_len as u64).wrapping_mul(8);

        self.buffer.push(0x80);

        while self.buffer.len() % Sha256Core::BLOCK_SIZE
            != Sha256Core::BLOCK_SIZE - Sha256Core::LENGTH_BYTES
        {
            self.buffer.push(0);
        }

        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        let final_blocks = std::mem::take(&mut self.buffer);
        for block in final_blocks.chunks_exact(Sha256Core::BLOCK_SIZE) {
            Sha256Core::compress(
                &mut self.state,
                &block.try_into().unwrap(),
                self.strategy.clone(),
            );
        }
        Sha256Core::output(self.state)
    }

    fn dgst(contents: impl AsRef<[u8]>) -> String {
        let mut hasher = Self::new(Strategy::SimdBatch);
        hasher.update(contents);
        let out = hasher.finalize();
        out.iter()
            .map(|byte| {
                let width = size_of_val(byte) * 2;
                format!("{byte:0width$x}")
            })
            .collect()
    }
}

impl HasherAlg for Sha2Hasher<Sha512Core> {
    type Output = <Sha512Core as Sha2>::Output;

    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.message_len += input.len() as u128;

        let diff = Sha512Core::BLOCK_SIZE - self.buffer.len();
        let input = if self.buffer.len() + input.len() >= Sha512Core::BLOCK_SIZE {
            self.buffer.extend_from_slice(&input[0..diff]);
            let block: &[u8; Sha512Core::BLOCK_SIZE] = &self
                .buffer
                .as_slice()
                .try_into()
                .expect("buffer contains exacty one block");
            Sha512Core::compress(&mut self.state, &block, self.strategy.clone());
            self.buffer.clear();
            &input[diff..]
        } else {
            input
        };

        for chunk in input.chunks(Sha512Core::BLOCK_SIZE) {
            if chunk.len() < Sha512Core::BLOCK_SIZE {
                self.buffer.extend_from_slice(chunk);
                break;
            }
            Sha512Core::compress(
                &mut self.state,
                chunk.try_into().unwrap(),
                self.strategy.clone(),
            );
        }
    }

    fn finalize(mut self) -> Self::Output {
        let bit_len = (self.message_len as u128).wrapping_mul(8);

        self.buffer.push(0x80);

        while self.buffer.len() % Sha512Core::BLOCK_SIZE
            != Sha512Core::BLOCK_SIZE - Sha512Core::LENGTH_BYTES
        {
            self.buffer.push(0);
        }

        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        let final_blocks = std::mem::take(&mut self.buffer);
        for block in final_blocks.chunks_exact(Sha512Core::BLOCK_SIZE) {
            Sha512Core::compress(
                &mut self.state,
                &block.try_into().unwrap(),
                self.strategy.clone(),
            );
        }
        Sha512Core::output(self.state)
    }

    fn dgst(contents: impl AsRef<[u8]>) -> String {
        let mut hasher = Self::new(Strategy::SimdBatch);
        hasher.update(contents);
        let out = hasher.finalize();
        out.iter()
            .map(|byte| {
                let width = size_of_val(byte) * 2;
                format!("{byte:0width$x}")
            })
            .collect()
    }
}

#[derive(Clone)]
pub enum Strategy {
    SimdBatch,
    Batch,
}

pub type Sha256 = Sha2Hasher<Sha256Core>;
pub type Sha512 = Sha2Hasher<Sha512Core>;
