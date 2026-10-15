use crate::sha2::constants;
use crate::sha2::utils::mixing_functions::Word;
pub fn process(hash: &mut [u64; 8], content: &[u8; 128]) {
    let (h1, h2) = {
        let a_init: [u64; 4] = hash[0..4].try_into().unwrap();
        let b_init: [u64; 4] = hash[4..8].try_into().unwrap();

        let mut A: [u64; 4] = a_init;
        let mut B: [u64; 4] = b_init;

        // W0..W15, four schedule words per vector.
        let mut m0 = load_be_u64x4(content, 0); // W0..W3
        let mut m1 = load_be_u64x4(content, 32); // W4..W7
        let mut m2 = load_be_u64x4(content, 64); // W8..W11
        let mut m3 = load_be_u64x4(content, 96); // W12..W15

        // Rounds 0..15.
        let wk = add4(m0, load_k4_at(&constants::SHA512_K, 0));
        rounds4(&mut A, &mut B, &wk);

        let wk = add4(m1, load_k4_at(&constants::SHA512_K, 4));
        rounds4(&mut A, &mut B, &wk);

        let wk = add4(m2, load_k4_at(&constants::SHA512_K, 8));
        rounds4(&mut A, &mut B, &wk);

        let wk = add4(m3, load_k4_at(&constants::SHA512_K, 12));
        rounds4(&mut A, &mut B, &wk);

        for block in 0..16 {
            let next = message_schedule_batch(&mut m0, &mut m1, &mut m2, &mut m3);

            let kt = load_k4_at(&constants::SHA512_K, 4 * block + 16);
            let k = add4(next, kt);

            // Computes 4 rounds
            rounds4(&mut A, &mut B, &k);

            // Shift the message to compute on the next round
            m0 = m1;
            m1 = m2;
            m2 = m3;
            m3 = next;
        }

        A = add4(A, a_init);
        B = add4(B, b_init);
        (A, B)
    };

    let [e, f, g, h] = h2;
    let [a, b, c, d] = h1;
    hash.copy_from_slice(&[a, b, c, d, e, f, g, h]);
}

fn message_schedule_batch(m0: &[u64; 4], m1: &[u64; 4], m2: &[u64; 4], m3: &[u64; 4]) -> [u64; 4] {
    let m4_0 = u64::ssig1(m3[2])
        .wrapping_add(m2[1])
        .wrapping_add(u64::ssig0(m0[1]))
        .wrapping_add(m0[0]);

    let m4_1 = u64::ssig1(m3[3])
        .wrapping_add(m2[2])
        .wrapping_add(u64::ssig0(m0[2]))
        .wrapping_add(m0[1]);

    let m4_2 = u64::ssig1(m4_0)
        .wrapping_add(m2[3])
        .wrapping_add(u64::ssig0(m0[3]))
        .wrapping_add(m0[2]);

    let m4_3 = u64::ssig1(m4_1)
        .wrapping_add(m3[0])
        .wrapping_add(u64::ssig0(m1[0]))
        .wrapping_add(m0[3]);

    [m4_0, m4_1, m4_2, m4_3]
}

#[inline(always)]
fn rounds4(upper: &mut [u64; 4], lower: &mut [u64; 4], wk: &[u64; 4]) {
    let mut a = upper[0];
    let mut b = upper[1];
    let mut c = upper[2];
    let mut d = upper[3];

    let mut e = lower[0];
    let mut f = lower[1];
    let mut g = lower[2];
    let mut h = lower[3];

    for i in 0..4 {
        let t1 = h
            .wrapping_add(u64::bsig1(e))
            .wrapping_add(u64::ch(e, f, g))
            .wrapping_add(wk[i]);

        let t2 = u64::bsig0(a).wrapping_add(u64::maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    upper[0] = a;
    upper[1] = b;
    upper[2] = c;
    upper[3] = d;

    lower[0] = e;
    lower[1] = f;
    lower[2] = g;
    lower[3] = h;
}

#[inline]
fn load_be_u64x4(content: &[u8; 128], offset: usize) -> [u64; 4] {
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

    [w0, w1, w2, w3]
}
#[inline(always)]
fn load_k4_at(table: &[u64; 80], t: usize) -> [u64; 4] {
    [table[t], table[t + 1], table[t + 2], table[t + 3]]
}

#[inline(always)]
fn add4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
    ]
}

//    fn message_schedule_scalar(content: &[u8; 128]) -> [u64; 80] {
//        let mut wt = [0u64; 80];
//
//        for (i, word_bytes) in content.chunks_exact(8).enumerate() {
//            wt[i] = u64::from_be_bytes([
//                word_bytes[0],
//                word_bytes[1],
//                word_bytes[2],
//                word_bytes[3],
//                word_bytes[4],
//                word_bytes[5],
//                word_bytes[6],
//                word_bytes[7],
//            ]);
//        }
//
//        for t in 16..80 {
//            wt[t] = u64::ssig1(wt[t - 2])
//                .wrapping_add(wt[t - 7])
//                .wrapping_add(u64::ssig0(wt[t - 15]))
//                .wrapping_add(wt[t - 16]);
//        }
//        wt
//    }
//
//    fn process_block_scalar(&mut self, content: &[u8; 128]) {
//        let wt = Self::message_schedule_scalar(content);
//
//        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hash;
//
//        for t in 0..80 {
//            let t1 = h
//                .wrapping_add(u64::bsig1(e))
//                .wrapping_add(u64::ch(e, f, g))
//                .wrapping_add(self.table[t])
//                .wrapping_add(wt[t]);
//
//            let t2 = u64::bsig0(a).wrapping_add(u64::maj(a, b, c));
//
//            h = g;
//            g = f;
//            f = e;
//            e = d.wrapping_add(t1);
//            d = c;
//            c = b;
//            b = a;
//            a = t1.wrapping_add(t2);
//        }
//        self.update_hash([a, b, c, d, e, f, g, h]);
//    }
