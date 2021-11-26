use criterion::{black_box, criterion_group, criterion_main, Criterion};

use atpmd::{
    nizkp_curve25519::{self, tokens::NizkpTokenEngine, tokens_batched::BatchedNizkpTokenEngine},
    atpm_pairing::{self, tokens::PairingTokenEngine, tokens_batched::BatchedPairingTokenEngine},
    SignedToken, TokenEngine, UnsignedToken,
};

// {{{ get tokens -- generate and sign

fn get_tokens<E: TokenEngine>(
    public_key: &E::UserVerification,
    secret_key: &E::SignKey,
    num: usize,
) -> Vec<E::SignedToken>
where
    E::UnsignedToken: UnsignedToken<Metadata = &'static [u8; 21]>,
{
    let metadata = b"this is some metadata";

    let mut unsigned_tokens = vec![];

    for _ in 0..num {
        unsigned_tokens.push(E::generate(metadata));
    }

    unsigned_tokens
        .into_iter()
        .map(|unsigned: E::UnsignedToken| {
            E::sign(unsigned, &public_key, |randomized| {
                E::sign_randomized(randomized, &secret_key)
            })
        })
        .map(|maybe_signed| maybe_signed.unwrap())
        .collect()
}

// }}}

// {{{ get token -- generate and sign

fn get_token<E: TokenEngine>(
    public_key: &E::UserVerification,
    secret_key: &E::SignKey,
) -> E::SignedToken
where
    E::UnsignedToken: UnsignedToken<Metadata = &'static [u8; 21]>,
{
    let metadata = b"this is some metadata";

    let unsigned = E::generate(metadata);
    E::sign(unsigned, &public_key, |randomized| {
        E::sign_randomized(randomized, &secret_key)
    })
    .unwrap()
}

// }}}

// {{{ comparison benchmarks

fn bench_all(c: &mut Criterion) {
    let pairing_private_key = atpm_pairing::keys::PrivateKey::new();
    let pairing_public_key = atpm_pairing::keys::PublicKey::from(&pairing_private_key);

    let nizkp_private_key = nizkp_curve25519::keys::PrivateKey::new();
    let nizkp_public_key = nizkp_curve25519::keys::PublicKey::from(&nizkp_private_key);

    let metadata = b"dummy metadata";

    // {{{ Generate 10
    {
        let mut group = c.benchmark_group("Generate 10");

        group.bench_function("pairing", |b| {
            b.iter(|| {
                black_box(
                    std::iter::repeat_with(|| PairingTokenEngine::generate(metadata))
                        .take(10)
                        .fold((), |s, elem| {
                            black_box(elem);
                            s
                        }),
                )
            })
        });

        group.bench_function("pairing batch", |b| {
            b.iter(|| black_box(BatchedPairingTokenEngine::<_, 10>::generate(metadata)))
        });

        group.bench_function("nizkp", |b| {
            b.iter(|| {
                black_box(
                    std::iter::repeat_with(|| NizkpTokenEngine::generate(metadata))
                        .take(10)
                        .fold((), |s, elem| {
                            black_box(elem);
                            s
                        }),
                )
            })
        });

        group.bench_function("nizkp batch", |b| {
            b.iter(|| black_box(BatchedNizkpTokenEngine::<_, 10>::generate(metadata)))
        });

        group.finish()
    }
    // }}}

    // {{{ generate and sign 10

    {
        let mut group = c.benchmark_group("generate and sign 10");

        group.bench_function("pairing", |b| {
            b.iter(|| {
                black_box(get_tokens::<PairingTokenEngine<&[u8; 21]>>(
                    &pairing_public_key,
                    &pairing_private_key,
                    10,
                ))
            })
        });

        group.bench_function("pairing batch", |b| {
            b.iter(|| {
                black_box(get_token::<BatchedPairingTokenEngine<&[u8; 21], 10>>(
                    &pairing_public_key,
                    &pairing_private_key,
                ))
            })
        });

        group.bench_function("nizkp", |b| {
            b.iter(|| {
                black_box(get_tokens::<NizkpTokenEngine<&[u8; 21]>>(
                    &nizkp_public_key,
                    &nizkp_private_key,
                    10,
                ))
            })
        });

        group.bench_function("nizkp batch", |b| {
            b.iter(|| {
                black_box(get_token::<BatchedNizkpTokenEngine<&[u8; 21], 10>>(
                    &nizkp_public_key,
                    &nizkp_private_key,
                ))
            })
        });

        group.finish()
    }

    // }}}

    // {{{ verify 10

    {
        let mut group = c.benchmark_group("verify 10");

        let tokens = get_tokens::<PairingTokenEngine<&[u8; 21]>>(
            &pairing_public_key,
            &pairing_private_key,
            10,
        );

        group.bench_function("pairing", |b| {
            b.iter(|| {
                assert!(
                    (tokens
                        .iter()
                        .fold(true, |s, token| s && token.verify(&pairing_public_key)))
                )
            })
        });

        let token = get_token::<BatchedPairingTokenEngine<&[u8; 21], 10>>(
            &pairing_public_key,
            &pairing_private_key,
        );

        group.bench_function("pairing batch", |b| {
            b.iter(|| assert!(black_box(token.verify(&pairing_public_key))))
        });

        let tokens =
            get_tokens::<NizkpTokenEngine<&[u8; 21]>>(&nizkp_public_key, &nizkp_private_key, 10);

        group.bench_function("nizkp", |b| {
            b.iter(|| {
                assert!(black_box(
                    tokens
                        .iter()
                        .fold(true, |s, token| s && token.verify(&nizkp_private_key))
                ))
            })
        });

        let token = get_token::<BatchedNizkpTokenEngine<&[u8; 21], 10>>(
            &nizkp_public_key,
            &nizkp_private_key,
        );

        group.bench_function("nizkp batch", |b| {
            b.iter(|| assert!(black_box(token.verify(&nizkp_private_key))))
        });

        group.finish()
    }

    // }}}

    // {{{ generate single

    {
        let mut group = c.benchmark_group("generate");

        group.bench_function("pairing", |b| {
            b.iter(|| black_box(PairingTokenEngine::generate(metadata)))
        });

        group.bench_function("pairing batch1", |b| {
            b.iter(|| black_box(BatchedPairingTokenEngine::<_, 1>::generate(metadata)))
        });

        group.bench_function("pairing batch10", |b| {
            b.iter(|| black_box(BatchedPairingTokenEngine::<_, 10>::generate(metadata)))
        });

        group.bench_function("nizkp", |b| {
            b.iter(|| black_box(NizkpTokenEngine::generate(metadata)))
        });

        group.bench_function("nizkp batch1", |b| {
            b.iter(|| black_box(BatchedNizkpTokenEngine::<_, 1>::generate(metadata)))
        });

        group.bench_function("nizkp batch10", |b| {
            b.iter(|| black_box(BatchedNizkpTokenEngine::<_, 10>::generate(metadata)))
        });

        group.finish()
    }

    // }}}

    // {{{ generate and sign single

    {
        let mut group = c.benchmark_group("generate and sign");

        macro_rules! sign {
            ($type:ty, $sign_key:expr, $verify_key:expr, $name:expr, $group:expr) => {
                group.bench_function($name, |b| {
                    b.iter(|| {
                        black_box(
                            <$type>::sign(
                                <$type>::generate(metadata),
                                &$verify_key,
                                |randomized| <$type>::sign_randomized(randomized, &$sign_key),
                            )
                            .unwrap(),
                        )
                    })
                });
            };
        }

        sign!(
            PairingTokenEngine<_>,
            pairing_private_key,
            pairing_public_key,
            "pairing",
            group
        );

        sign!(
            BatchedPairingTokenEngine<_, 1>,
            pairing_private_key,
            pairing_public_key,
            "pairing batch1",
            group
        );

        sign!(
            NizkpTokenEngine<_>,
            nizkp_private_key,
            nizkp_public_key,
            "nizkp",
            group
        );

        sign!(
            BatchedNizkpTokenEngine<_, 1>,
            nizkp_private_key,
            nizkp_public_key,
            "nizkp batch1",
            group
        );

        group.finish();
    }

    // }}}

    // {{{ verify single

    {
        let mut group = c.benchmark_group("verify");

        macro_rules! verify {
            ($type:ty, $sign_key:expr, $verify_key:expr, $v_key:expr, $name:expr, $group:expr) => {
                group.bench_function($name, |b| {
                    let signed =
                        <$type>::sign(<$type>::generate(metadata), &$verify_key, |randomized| {
                            <$type>::sign_randomized(randomized, &$sign_key)
                        })
                        .unwrap();
                    b.iter(|| assert!(black_box(signed.verify(&$v_key))))
                });
            };
        }

        verify!(
            PairingTokenEngine<_>,
            pairing_private_key,
            pairing_public_key,
            pairing_public_key,
            "pairing",
            group
        );

        verify!(
            BatchedPairingTokenEngine<_, 1>,
            pairing_private_key,
            pairing_public_key,
            pairing_public_key,
            "pairing batch1",
            group
        );

        verify!(
            BatchedPairingTokenEngine<_, 10>,
            pairing_private_key,
            pairing_public_key,
            pairing_public_key,
            "pairing batch10",
            group
        );

        verify!(
            NizkpTokenEngine<_>,
            nizkp_private_key,
            nizkp_public_key,
            nizkp_private_key,
            "nizkp",
            group
        );

        verify!(
            BatchedNizkpTokenEngine<_, 1>,
            nizkp_private_key,
            nizkp_public_key,
            nizkp_private_key,
            "nizkp batch1",
            group
        );

        verify!(
            BatchedNizkpTokenEngine<_, 10>,
            nizkp_private_key,
            nizkp_public_key,
            nizkp_private_key,
            "nizkp batch10",
            group
        );

        group.finish();
    }

    // }}}

    // {{{ randomize

    {
        let mut group = c.benchmark_group("randomize");

        macro_rules! randomize {
            ($type:ty, $name:expr, $group:expr) => {
                let token = <$type>::generate(metadata);

                group.bench_function($name, |b| b.iter(|| black_box(<$type>::randomize(&token))));
            };
        }

        randomize!(PairingTokenEngine<_>, "pairing", group);
        randomize!(BatchedPairingTokenEngine<_, 1>, "pairing batch1", group);
        randomize!(BatchedPairingTokenEngine<_, 10>, "pairing batch10", group);
        randomize!(NizkpTokenEngine<_>, "nizkp", group);
        randomize!(BatchedNizkpTokenEngine<_, 1>, "nizkp batch1", group);
        randomize!(BatchedNizkpTokenEngine<_, 10>, "nizkp batch10", group);

        group.finish();
    }

    // }}}

    // {{{ sign_randomized

    {
        let mut group = c.benchmark_group("sign_randomized");

        macro_rules! sign_randomized {
            ($type:ty, $sign_key:expr, $name:expr, $group:expr) => {
                let token = <$type>::generate(metadata);

                let (_r, randomized) = <$type>::randomize(&token);

                group.bench_function($name, |b| {
                    b.iter(|| {
                        black_box(<$type>::sign_randomized(&randomized, &$sign_key).unwrap())
                    })
                });
            };
        }

        sign_randomized!(PairingTokenEngine<_>, pairing_private_key, "pairing", group);
        sign_randomized!(BatchedPairingTokenEngine<_, 1>, pairing_private_key, "pairing batch1", group);
        sign_randomized!(BatchedPairingTokenEngine<_, 10>, pairing_private_key, "pairing batch10", group);
        sign_randomized!(NizkpTokenEngine<_>, nizkp_private_key, "nizkp", group);
        sign_randomized!(BatchedNizkpTokenEngine<_, 1>,  nizkp_private_key, "nizkp batch1", group);
        sign_randomized!(BatchedNizkpTokenEngine<_, 10>, nizkp_private_key, "nizkp batch10", group);

        group.finish();
    }

    // }}}
}

// }}}

// {{{ batch verify pairing

fn bench_verify_pairing_batched(c: &mut Criterion) {
    let private_key = atpm_pairing::keys::PrivateKey::new();
    let public_key = atpm_pairing::keys::PublicKey::from(&private_key);

    let mut group = c.benchmark_group("batch verification");

    macro_rules! benchmark {
        ($num:expr, $group:expr) => {
            let metadata = b"dummy metadata";

            let tokens = BatchedPairingTokenEngine::<_, $num>::sign(
                BatchedPairingTokenEngine::generate(metadata),
                &public_key,
                |randomized| BatchedPairingTokenEngine::sign_randomized(randomized, &private_key),
            )
            .unwrap();

            $group.bench_function(format!("pairing batch {}", $num).as_str(), |b| {
                b.iter(|| tokens.verify(&public_key))
            });
        };
    }

    benchmark!(16, group);
    benchmark!(32, group);
    benchmark!(64, group);
    benchmark!(128, group);
    benchmark!(256, group);
    benchmark!(512, group);
}

// }}}

criterion_group!(benches, bench_all, bench_verify_pairing_batched);
criterion_main!(benches);
