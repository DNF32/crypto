use crypto::HasherAlg;
use crypto::sha2::Sha256;
use crypto::sha2::Strategy;

macro_rules! sha_tests {
    ($(($name: ident, $input:expr, $output: literal )),*) => {
        $(
        mod $name {
            use super::*;
            #[test]
            fn batch() {
                assert_hashed_content(Sha256::new(Strategy::Batch), $input, $output, "Batch");
            }

            #[test]
            fn simd() {
                assert_hashed_content(Sha256::new(Strategy::SimdBatch), $input, $output, "SimdBatch");
            }
        }
        )*
    };
}

sha_tests!(
    (
        empty_input,
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    (
        length_448,
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    ),
    (
        length_896,
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    ),
    (
        one_million_bytes,
        &"a".repeat(1_000_000),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    ),
    (
        one_gibibyte,
        &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
        "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
    )
);

fn assert_hashed_content(mut alg: impl HasherAlg, input: &str, output: &str, strategy: &str) {
    alg.update(input);
    let out = alg.finalize();

    assert_eq!(to_hex_string(out.as_ref()), output, "strategy: {strategy}")
}

fn to_hex_string(input: &[u8]) -> String {
    input
        .iter()
        .map(|byte| {
            let width = size_of_val(byte) * 2;
            format!("{byte:0width$x}")
        })
        .collect::<String>()
}
