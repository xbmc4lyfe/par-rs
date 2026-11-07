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

#[test]
fn shift_tables_equal_the_multiply() {
    for len in [1u64, 7, 4096, 716_800, 10_752_000, 1 << 33] {
        let s = Crc32Shift::new(len);
        assert_eq!(s.byte_len(), len);
        for &c1 in &[0u32, 1, ONE, GF2_POLY, 0xdead_beef, 0x1234_5678, 0xffff_ffff] {
            for &c2 in &[0u32, 0x0bad_f00d, 0xffff_ffff] {
                assert_eq!(s.combine(c1, c2), crc32_combine_u64(c1, c2, len), "len {len} c1 {c1:#x} c2 {c2:#x}");
            }
        }
    }
    // Folding past the table threshold gives the brute-force CRC, equal and unequal parts alike.
    let file = data(150 * 1024 + 123, 42);
    let want = crc32(&file);
    let parts: Vec<(u32, usize)> = file.chunks(1024).map(|c| (crc32(c), c.len())).collect();
    assert!(parts.len() >= Crc32Shift::MIN_PARTS);
    assert_eq!(fold_yenc_parts(&parts).unwrap(), want);
    let indexed: Vec<(usize, u32, usize)> = parts.iter().enumerate().rev().map(|(i, &(c, l))| (i, c, l)).collect();
    assert_eq!(fold_yenc_indexed_parts(parts.len(), &indexed).unwrap(), want);
    // Alternating part sizes: the folder gives up on tables and stays correct.
    let mut alt = Vec::new();
    let mut off = 0;
    for i in 0.. {
        if off >= file.len() {
            break;
        }
        let l = if i % 2 == 0 { 1000 } else { 3000 }.min(file.len() - off);
        alt.push((crc32(&file[off..off + l]), l));
        off += l;
    }
    assert_eq!(fold_yenc_parts(&alt).unwrap(), want);
    // IFSC: one shared table for many files of a set.
    let bs = 1024u64;
    let shift = Crc32Shift::new(bs);
    for size in [1usize, 1023, 1024, 1025, 100 * 1024, 150 * 1024 + 123] {
        let f = &file[..size];
        let mut padded = f.to_vec();
        padded.resize(size.div_ceil(bs as usize) * bs as usize, 0);
        let crcs: Vec<u32> = padded.chunks(bs as usize).map(crc32).collect();
        assert_eq!(fold_ifsc_crcs_with(&shift, &crcs, size as u64), Some(crc32(f)));
        assert_eq!(fold_ifsc_crcs(&crcs, bs, size as u64), Some(crc32(f)));
    }
}

#[test]
fn ifsc_crcs_on_an_article_grid() {
    // A file posted in 7000-byte articles and protected with 1000-byte slices: both sides fold
    // onto the LCM grid and agree interval by interval, and each interval is the real CRC.
    let file = data(10 * 7000 * 2 + 4321, 7);
    let (art, bs) = (7000u64, 1000u64);
    let grid = lcm_grid(&[art, bs]).unwrap();
    assert_eq!(grid, 7000);
    let articles: Vec<(u32, u64)> = file.chunks(art as usize).map(|c| (crc32(c), c.len() as u64)).collect();
    let mut padded = file.clone();
    padded.resize(file.len().div_ceil(bs as usize) * bs as usize, 0);
    let slices: Vec<u32> = padded.chunks(bs as usize).map(crc32).collect();
    let from_articles = compute_interval_crcs(&articles, grid).unwrap();
    let from_ifsc = ifsc_interval_crcs(&slices, bs, file.len() as u64, grid).unwrap();
    let direct: Vec<u32> = file.chunks(grid as usize).map(crc32).collect();
    assert_eq!(from_ifsc, direct);
    assert_eq!(from_articles, direct);
    // Damage one article: exactly that interval differs.
    let mut bad = articles.clone();
    bad[3].0 ^= 1;
    let diff: Vec<usize> = compute_interval_crcs(&bad, grid).unwrap().iter().zip(&from_ifsc).enumerate().filter(|(_, (a, b))| a != b).map(|(i, _)| i).collect();
    assert_eq!(diff, vec![3]);
    // Coarser grid, exact multiple of the file, single slice files, and the refusals.
    assert_eq!(ifsc_interval_crcs(&slices, bs, file.len() as u64, 35_000).unwrap(), file.chunks(35_000).map(crc32).collect::<Vec<_>>());
    let exact = &file[..140_000];
    let crcs: Vec<u32> = exact.chunks(bs as usize).map(crc32).collect();
    assert_eq!(ifsc_interval_crcs(&crcs, bs, 140_000, 7000).unwrap(), exact.chunks(7000).map(crc32).collect::<Vec<_>>());
    let mut one = file[..999].to_vec();
    one.resize(1000, 0);
    assert_eq!(ifsc_interval_crcs(&[crc32(&one)], bs, 999, 5000).unwrap(), vec![crc32(&file[..999])]);
    assert_eq!(ifsc_interval_crcs(&[], bs, 0, 5000), Some(vec![]));
    assert_eq!(ifsc_interval_crcs(&slices, bs, file.len() as u64, 1500), None, "grid must be a multiple of the block size");
    assert_eq!(ifsc_interval_crcs(&slices, 0, file.len() as u64, 7000), None);
    assert_eq!(ifsc_interval_crcs(&slices, bs, file.len() as u64, 0), None);
    assert_eq!(ifsc_interval_crcs(&slices[1..], bs, file.len() as u64, 7000), None, "slice count must fit the file");
}
