//! Algebra laws of the GF(2) CRC-32 module.

use par_rs::gf2::*;

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed.wrapping_mul(97)) >> 13) as u8).collect()
}

const ONE: u32 = 1 << 31;

#[test]
fn ring_laws() {
    let xs = [0u32, 1, ONE, GF2_POLY, 0xdead_beef, 0x1234_5678, 0xffff_ffff, 0x8000_0001];
    for &a in &xs {
        assert_eq!(multmodp(a, ONE), a);
        assert_eq!(multmodp(ONE, a), a);
        assert_eq!(multmodp(a, 0), 0);
        for &b in &xs {
            assert_eq!(multmodp(a, b), multmodp(b, a), "commutative");
            for &c in &xs {
                assert_eq!(multmodp(multmodp(a, b), c), multmodp(a, multmodp(b, c)), "associative");
                assert_eq!(multmodp(a, b ^ c), multmodp(a, b) ^ multmodp(a, c), "distributive");
            }
        }
    }
    // x^(a+b) = x^a · x^b and the order of x.
    for (a, b) in [(1u64, 2u64), (31, 1), (100, 923), (1 << 20, 7), (GF2_ORDER - 5, 5)] {
        assert_eq!(xpow(a + b), multmodp(xpow(a), xpow(b)));
    }
    assert_eq!(xpow(GF2_ORDER), ONE);
    assert_eq!(xpow(GF2_ORDER + 3), xpow(3));
    for k in 0..40u32 {
        assert_eq!(x2nmodp(1, k), xpow(1u64 << (k % 32)), "x^(2^k) wraps with period 32");
    }
    assert_eq!(x2nmodp(13, 3), xpow(13 * 8));
}

#[test]
fn combine_family_round_trips() {
    for (la, lb) in [(0usize, 0usize), (1, 0), (0, 1), (5, 7), (1000, 3), (4096, 4096), (70_001, 999)] {
        let a = data(la, 1);
        let b = data(lb, 2);
        let ab: Vec<u8> = a.iter().chain(&b).copied().collect();
        let (ca, cb, cab) = (crc32(&a), crc32(&b), crc32(&ab));
        assert_eq!(crc32_combine(ca, cb, lb), cab);
        assert_eq!(crc32_combine_u64(ca, cb, lb as u64), cab);
        assert_eq!(crc32_uncombine_suffix(cab, cb, lb as u64), ca);
        assert_eq!(crc32_uncombine_prefix(cab, ca, lb as u64), cb);
        let mut az = a.clone();
        az.extend(std::iter::repeat_n(0u8, lb));
        assert_eq!(crc32_zeros(lb), crc32(&vec![0u8; lb]));
        assert_eq!(crc32_unzero(crc32(&az), lb), ca);
        assert_eq!(crc32_zero_unpad(crc32(&az), lb), ca);
        assert_eq!(crc32_combine(ca, crc32_zeros(lb), lb), crc32(&az));
    }
    // Known vectors.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn yenc_and_ifsc_folding() {
    let file = data(3_000_000, 3);
    // yEnc articles of 716_800 bytes.
    let art = 716_800usize;
    let parts: Vec<(u32, usize)> = file.chunks(art).map(|c| (crc32(c), c.len())).collect();
    assert_eq!(fold_yenc_parts(&parts), Ok(crc32(&file)));
    let mut indexed: Vec<(usize, u32, usize)> = parts.iter().enumerate().map(|(i, &(c, l))| (i, c, l)).collect();
    indexed.reverse();
    assert_eq!(fold_yenc_indexed_parts(parts.len(), &indexed), Ok(crc32(&file)));
    assert_eq!(fold_yenc_indexed_parts(parts.len(), &indexed[1..]), Err(FoldError::MissingPart(parts.len() - 1)));
    assert_eq!(fold_yenc_parts(&[]), Err(FoldError::Empty));

    // IFSC slices of 1 MiB with the last one zero padded.
    let bs = 1 << 20;
    let crcs: Vec<u32> = file
        .chunks(bs)
        .map(|c| {
            let mut p = c.to_vec();
            p.resize(bs, 0);
            crc32(&p)
        })
        .collect();
    assert_eq!(fold_ifsc_crcs(&crcs, bs as u64, file.len() as u64), Some(crc32(&file)));
    assert_eq!(fold_ifsc_crcs(&crcs, bs as u64, file.len() as u64 + bs as u64), None);

    // Interval CRCs on the LCM grid of two article sizes.
    let grid = lcm_grid(&[716_800, 768_000]).unwrap();
    assert_eq!(grid, 10_752_000);
    let big = data(2 * grid as usize + 12_345, 4);
    for art in [716_800usize, 768_000] {
        let parts: Vec<(u32, u64)> = big.chunks(art).map(|c| (crc32(c), c.len() as u64)).collect();
        let iv = compute_interval_crcs(&parts, grid).unwrap();
        assert_eq!(iv.len(), 3);
        for (k, c) in iv.iter().enumerate() {
            let s = k * grid as usize;
            let e = ((k + 1) * grid as usize).min(big.len());
            assert_eq!(*c, crc32(&big[s..e]), "article {art} interval {k}");
        }
    }
}

#[test]
fn rolling_crc_matches_direct_everywhere() {
    let buf = data(20_000, 5);
    for n in [1u64, 3, 16, 100, 4096, 10_000] {
        let r = RollingCrc32::new(n).unwrap();
        let n = n as usize;
        let mut c = r.first(&buf[..n]).unwrap();
        for pos in 1..=buf.len() - n {
            c = r.roll(c, buf[pos - 1], buf[pos - 1 + n]);
            if pos % 97 == 0 || pos + n == buf.len() {
                assert_eq!(c, crc32(&buf[pos..pos + n]), "window {n} at {pos}");
            }
        }
        // Rolling into virtual zero padding equals the zero-padded tail.
        let mut tail_crc = c;
        for k in 1..=n.min(50) {
            tail_crc = r.roll(tail_crc, buf[buf.len() - n + k - 1], 0);
            let mut padded = buf[buf.len() - n + k..].to_vec();
            padded.resize(n, 0);
            assert_eq!(tail_crc, crc32(&padded));
        }
    }
}
