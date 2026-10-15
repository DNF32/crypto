use crypto::HasherAlg;
use crypto::sha2::Sha512;
use crypto::sha2::Strategy;

macro_rules! sha_tests {
    ($(($name: ident, $input:expr, $output: literal )),*) => {
        $(
        mod $name {
            use super::*;
            #[test]
            fn batch() {
                assert_hashed_content(Sha512::new(Strategy::Batch), $input, $output, "Batch");
            }

            #[test]
            fn simd() {
                assert_hashed_content(Sha512::new(Strategy::SimdBatch), $input, $output, "SimdBatch");
            }
        }
        )*
    };
}

sha_tests!(
    (
        empty_input,
        "",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ),
    (
        length_448,
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    ),
    (
        length_896,
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    ),
    (
        one_million_bytes,
        &"a".repeat(1_000_000),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    ),
    (
        one_gibibyte,
        &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
        "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
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
