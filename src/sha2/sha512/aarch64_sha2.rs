use std::arch::aarch64::{uint64x2x2_t, vld1q_u64, vld1q_u64_x2, vst1q_u64_x2};
use std::arch::aarch64::{uint64x2x4_t, vaddq_u64, vld1q_u64_x4, vsha256su0q_u32, vsha256su1q_u32};
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::{
    vextq_u64, vsha512h2q_u64, vsha512hq_u64, vsha512su0q_u64, vsha512su1q_u64,
};

use crate::sha2::constants;
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn process(hash: &mut [u64; 8], content: &[u8; 128]) {
    let mut h1 = [0u64; 4];
    let mut h2 = [0u64; 4];

    unsafe {
        use std::arch::aarch64::{vaddq_u32, vld1q_u32, vst1q_u32};

        let mut abcd = vld1q_u64_x2(hash.as_ptr());
        let mut efgh = vld1q_u64_x2(hash.as_ptr().add(4));

        let abcd_init = abcd;
        let efgh_init = efgh;

        // W0..W15, four schedule words per vector.
        let mut m0 = load_be_u64x4(content, 0); // W0..W3
        let mut m1 = load_be_u64x4(content, 32); // W4..W7
        let mut m2 = load_be_u64x4(content, 64); // W8..W11
        let mut m3 = load_be_u64x4(content, 96); // W12..W15

        // Rounds 0..15.
        let wk = add_u64x2x2(m0, load_k4_at(&constants::SHA512_K, 0));
        rounds4(&mut abcd, &mut efgh, &wk);

        let wk = add_u64x2x2(m1, load_k4_at(&constants::SHA512_K, 4));
        rounds4(&mut abcd, &mut efgh, &wk);

        let wk = add_u64x2x2(m2, load_k4_at(&constants::SHA512_K, 8));
        rounds4(&mut abcd, &mut efgh, &wk);

        let wk = add_u64x2x2(m3, load_k4_at(&constants::SHA512_K, 12));
        rounds4(&mut abcd, &mut efgh, &wk);

        for block in 0..16 {
            let next = message_schedule(&mut m0, &mut m1, &mut m2, &mut m3);

            let kt = load_k4_at(&constants::SHA512_K, 4 * block + 16);
            let k = add_u64x2x2(next, kt);

            // Computes 4 rounds
            rounds4(&mut abcd, &mut efgh, &k);

            // Shift the message to compute on the next round
            m0 = m1;
            m1 = m2;
            m2 = m3;
            m3 = next;
        }

        abcd = add_u64x2x2(abcd, abcd_init);
        efgh = add_u64x2x2(efgh, efgh_init);

        vst1q_u64_x2(h1.as_mut_ptr().add(0) as *mut u64, abcd);
        vst1q_u64_x2(h2.as_mut_ptr().add(0) as *mut u64, efgh);
    }

    let [e, f, g, h] = h2;
    let [a, b, c, d] = h1;
    hash.copy_from_slice(&[a, b, c, d, e, f, g, h]);
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "sha3")]
unsafe fn rounds4(abcd: &mut uint64x2x2_t, efgh: &mut uint64x2x2_t, wk_k: &uint64x2x2_t) {
    let mut ab = (*abcd).0;
    let mut cd = (*abcd).1;
    let mut ef = (*efgh).0;
    let mut gh = (*efgh).1;

    let w1_2 = (*wk_k).0;
    let w3_4 = (*wk_k).1;

    for message in [w1_2, w3_4] {
        let pre_sum_t1 = vaddq_u64(gh, vextq_u64(message, message, 1));

        let t1 = vsha512hq_u64(pre_sum_t1, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));

        let new_ab = vsha512h2q_u64(t1, cd, ab);

        let new_ef = vaddq_u64(cd, t1);

        gh = ef;
        cd = ab;

        ab = new_ab;
        ef = new_ef;
    }

    (*abcd).0 = ab;
    (*abcd).1 = cd;
    (*efgh).0 = ef;
    (*efgh).1 = gh;
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "sha3")]
unsafe fn message_schedule(
    m0: &mut uint64x2x2_t,
    m1: &mut uint64x2x2_t,
    m2: &mut uint64x2x2_t,
    m3: &mut uint64x2x2_t,
) -> uint64x2x2_t {
    let partial_sum = vsha512su0q_u64((*m0).0, (*m0).1);
    let msg_lower = vsha512su1q_u64(partial_sum, (*m3).1, vextq_u64((*m2).0, (*m2).1, 1));

    let partial_sum = vsha512su0q_u64((*m0).1, (*m1).0);
    let msg_upper = vsha512su1q_u64(partial_sum, msg_lower, vextq_u64((*m2).1, (*m3).0, 1));

    uint64x2x2_t(msg_lower, msg_upper)
}

#[inline]
fn load_be_u64x4(content: &[u8; 128], offset: usize) -> uint64x2x2_t {
    let w0 = u64::from_be_bytes([
        content[offset],
        content[offset + 1],
        content[offset + 2],
        content[offset + 3],
        content[offset + 4],
        content[offset + 5],
        content[offset + 6],
        content[offset + 7],
    ]);

    let w1 = u64::from_be_bytes([
        content[offset + 8],
        content[offset + 9],
        content[offset + 10],
        content[offset + 11],
        content[offset + 12],
        content[offset + 13],
        content[offset + 14],
        content[offset + 15],
    ]);

    let w2 = u64::from_be_bytes([
        content[offset + 16],
        content[offset + 17],
        content[offset + 18],
        content[offset + 19],
        content[offset + 20],
        content[offset + 21],
        content[offset + 22],
        content[offset + 23],
    ]);

    let w3 = u64::from_be_bytes([
        content[offset + 24],
        content[offset + 25],
        content[offset + 26],
        content[offset + 27],
        content[offset + 28],
        content[offset + 29],
        content[offset + 30],
        content[offset + 31],
    ]);

    unsafe { vld1q_u64_x2([w0, w1, w2, w3].as_ptr()) }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn load_k4_at(table: &[u64; 80], offset: usize) -> uint64x2x2_t {
    vld1q_u64_x2(table[offset..offset + 4].as_ptr())
}

unsafe fn add_u64x2x2(a: uint64x2x2_t, b: uint64x2x2_t) -> uint64x2x2_t {
    let low = vaddq_u64(a.0, b.0);
    let high = vaddq_u64(a.1, b.1);
    uint64x2x2_t(low, high)
}
