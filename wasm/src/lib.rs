// TRON vanity search kernel, compiled to WebAssembly.
//
// The whole inner loop (EC point increment -> keccak -> Base58Check -> match)
// runs inside WASM so there is no per-candidate JS<->WASM boundary crossing.
//
// Two engines live here:
//   * run()      - simple, k256 projective addition + batch normalize. Proven
//                  correct; used as the reference for the self-test.
//   * run_fast() - the fast path: keeps everything in AFFINE coordinates and
//                  computes a whole group of consecutive points B+i*G using a
//                  precomputed table of i*G and a SINGLE shared modular
//                  inversion per group (the classic VanitySearch trick).
use k256::elliptic_curve::group::Curve as _;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crypto_bigint::modular::constant_mod::Residue;
use crypto_bigint::{impl_modulus, Encoding, U256};

// Field modulus p of secp256k1.
impl_modulus!(
    Modp,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
);
type Fp = Residue<Modp, { U256::LIMBS }>;

// Curve order n (for reducing private-key scalars).
const N: U256 = U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

// Group size for the fast path: points computed per shared inversion.
const GRP: usize = 256;
// Points converted to affine per batch in the reference engine.
const BATCH: usize = 256;

const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// --- Shared buffers (fixed offsets exported to JS). ---
static mut START_KEY: [u8; 32] = [0u8; 32]; // input: starting private key
static mut OUT_KEY: [u8; 32] = [0u8; 32]; // output: private key of a match
static mut TARGET: [u8; 64] = [0u8; 64]; // input: target text (ASCII Base58)

// --- Reference-engine state. ---
static mut CUR_SCALAR: Option<Scalar> = None;
static mut CUR_POINT: Option<ProjectivePoint> = None;

// --- Fast-engine state. ---
// TABLE[i] = (i+1)*G in affine coordinates, for i in 0..=GRP.
static mut TABLE_X: [Fp; GRP + 1] = [Fp::ZERO; GRP + 1];
static mut TABLE_Y: [Fp; GRP + 1] = [Fp::ZERO; GRP + 1];
static mut TABLE_READY: bool = false;
static mut FAST_XB: Fp = Fp::ZERO; // current base point B
static mut FAST_YB: Fp = Fp::ZERO;
static mut FAST_S: U256 = U256::ZERO; // scalar of B

#[no_mangle]
pub extern "C" fn start_key_ptr() -> *const u8 {
    core::ptr::addr_of!(START_KEY) as *const u8
}
#[no_mangle]
pub extern "C" fn out_key_ptr() -> *const u8 {
    core::ptr::addr_of!(OUT_KEY) as *const u8
}
#[no_mangle]
pub extern "C" fn target_ptr() -> *const u8 {
    core::ptr::addr_of!(TARGET) as *const u8
}

// ---------------------------------------------------------------------------
// Reference engine (k256). Kept for fallback and as the self-test oracle.
// ---------------------------------------------------------------------------

/// Seed the reference search from the 32-byte START_KEY buffer.
#[no_mangle]
pub extern "C" fn init() {
    let bytes = unsafe { START_KEY };
    let scalar = scalar_from_bytes(&bytes);
    let point = ProjectivePoint::GENERATOR * scalar;
    unsafe {
        CUR_SCALAR = Some(scalar);
        CUR_POINT = Some(point);
    }
}

/// Reference run: 0=prefix, 1=suffix, 2=contains. Returns match index or -1.
#[no_mangle]
pub extern "C" fn run(target_len: u32, mode: u32, ignore_case: u32, max_iters: u32) -> i64 {
    let tlen = target_len as usize;
    let target = unsafe { &TARGET[..tlen] };
    let ic = ignore_case != 0;
    let g = ProjectivePoint::GENERATOR;

    let mut scalar = unsafe { CUR_SCALAR.unwrap() };
    let mut point = unsafe { CUR_POINT.unwrap() };

    let mut points = [ProjectivePoint::IDENTITY; BATCH];
    let mut affines = [AffinePoint::IDENTITY; BATCH];
    let mut addr = [0u8; 40];

    let mut done: u32 = 0;
    while done < max_iters {
        let n = core::cmp::min(BATCH as u32, max_iters - done) as usize;
        for p in points.iter_mut().take(n) {
            *p = point;
            point += g;
        }
        ProjectivePoint::batch_normalize(&points[..n], &mut affines[..n]);

        for j in 0..n {
            let enc = affines[j].to_encoded_point(false);
            let len = address_from_xy(&enc.as_bytes()[1..33], &enc.as_bytes()[33..65], &mut addr);
            let a = &mut addr[..len];
            if ic {
                for b in a.iter_mut() {
                    b.make_ascii_lowercase();
                }
            }
            if matches(a, target, mode) {
                let key_scalar = scalar + Scalar::from(j as u64);
                unsafe {
                    OUT_KEY.copy_from_slice(&key_scalar.to_bytes());
                    CUR_SCALAR = Some(key_scalar + Scalar::ONE);
                    CUR_POINT = Some(ProjectivePoint::from(affines[j]) + g);
                }
                return (done as usize + j) as i64;
            }
        }
        scalar += Scalar::from(n as u64);
        done += n as u32;
    }
    unsafe {
        CUR_SCALAR = Some(scalar);
        CUR_POINT = Some(point);
    }
    -1
}

// ---------------------------------------------------------------------------
// Fast engine (affine increments + shared inversion).
// ---------------------------------------------------------------------------

/// Build TABLE[i] = (i+1)*G once.
fn ensure_table() {
    if unsafe { TABLE_READY } {
        return;
    }
    let g = ProjectivePoint::GENERATOR;
    let mut acc = g; // 1*G
    for i in 0..=GRP {
        let enc = acc.to_affine().to_encoded_point(false);
        let b = enc.as_bytes();
        unsafe {
            TABLE_X[i] = Fp::new(&U256::from_be_slice(&b[1..33]));
            TABLE_Y[i] = Fp::new(&U256::from_be_slice(&b[33..65]));
        }
        acc += g;
    }
    unsafe { TABLE_READY = true };
}

/// Seed the fast search from the 32-byte START_KEY buffer.
#[no_mangle]
pub extern "C" fn init_fast() {
    ensure_table();
    let sc = scalar_from_bytes(&unsafe { START_KEY });
    let enc = (ProjectivePoint::GENERATOR * sc).to_affine().to_encoded_point(false);
    let b = enc.as_bytes();
    unsafe {
        FAST_XB = Fp::new(&U256::from_be_slice(&b[1..33]));
        FAST_YB = Fp::new(&U256::from_be_slice(&b[33..65]));
        FAST_S = U256::from_be_slice(&sc.to_bytes());
    }
}

/// Fast run: 0=prefix, 1=suffix, 2=contains. Returns match index or -1.
#[no_mangle]
pub extern "C" fn run_fast(target_len: u32, mode: u32, ignore_case: u32, max_iters: u32) -> i64 {
    let tlen = target_len as usize;
    let target = unsafe { &TARGET[..tlen] };
    let ic = ignore_case != 0;

    let mut xb = unsafe { FAST_XB };
    let mut yb = unsafe { FAST_YB };
    let mut s = unsafe { FAST_S };

    let m = GRP + 1; // GRP test points + 1 advance, all sharing one inversion
    let mut den = [Fp::ZERO; GRP + 1];
    let mut pre = [Fp::ZERO; GRP + 1];
    let mut inv = [Fp::ZERO; GRP + 1];
    let mut addr = [0u8; 40];

    let mut iters: u32 = 0;
    while iters < max_iters {
        // Test the base point B (scalar s).
        if test_point(&xb, &yb, target, mode, ic, &mut addr) {
            finish_match(xb, yb, s, s);
            return iters as i64;
        }
        iters += 1;

        // Denominators (TABLE_X[i] - xb) for B + (i+1)*G, i in 0..=GRP.
        for i in 0..m {
            den[i] = unsafe { TABLE_X[i] } - xb;
        }
        pre[0] = den[0];
        for i in 1..m {
            pre[i] = pre[i - 1] * den[i];
        }
        let (mut acc, ok) = pre[m - 1].invert();
        if !bool::from(ok) {
            // Zero denominator (astronomically rare): nudge scalar and reseed.
            s = add_mod_n(s, 1);
            reseed_fast(&mut xb, &mut yb, s);
            continue;
        }
        for i in (0..m).rev() {
            inv[i] = if i == 0 { acc } else { acc * pre[i - 1] };
            if i != 0 {
                acc = acc * den[i];
            }
        }

        let mut adv_x = Fp::ZERO;
        let mut adv_y = Fp::ZERO;
        for i in 0..m {
            let tx = unsafe { TABLE_X[i] };
            let ty = unsafe { TABLE_Y[i] };
            let lambda = (ty - yb) * inv[i];
            let xr = lambda * lambda - xb - tx;
            let yr = lambda * (xb - xr) - yb;
            if i < GRP {
                if test_point(&xr, &yr, target, mode, ic, &mut addr) {
                    let key = add_mod_n(s, (i as u64) + 1);
                    finish_match(xb, yb, s, key);
                    return iters as i64;
                }
                iters += 1;
            } else {
                adv_x = xr;
                adv_y = yr;
            }
        }
        xb = adv_x;
        yb = adv_y;
        s = add_mod_n(s, (GRP as u64) + 1);
    }

    unsafe {
        FAST_XB = xb;
        FAST_YB = yb;
        FAST_S = s;
    }
    -1
}

/// Self-test: compare the fast affine path against the k256 reference for the
/// first `count` consecutive points from the current base. Returns the number
/// of mismatching addresses (0 means the fast path is correct).
#[no_mangle]
pub extern "C" fn selftest(count: u32) -> u32 {
    ensure_table();
    let xb = unsafe { FAST_XB };
    let yb = unsafe { FAST_YB };
    let s = unsafe { FAST_S };
    let mut fa = [0u8; 40];
    let mut ra = [0u8; 40];
    let mut mism = 0u32;
    let lim = core::cmp::min(count as usize, GRP);
    for i in 0..lim {
        let (fx, fy) = if i == 0 {
            (xb, yb)
        } else {
            affine_add(xb, yb, unsafe { TABLE_X[i - 1] }, unsafe { TABLE_Y[i - 1] })
        };
        let fl = address_from_xy(&fx.retrieve().to_be_bytes(), &fy.retrieve().to_be_bytes(), &mut fa);

        let sc = scalar_from_u256(add_mod_n(s, i as u64));
        let enc = (ProjectivePoint::GENERATOR * sc).to_affine().to_encoded_point(false);
        let b = enc.as_bytes();
        let rl = address_from_xy(&b[1..33], &b[33..65], &mut ra);

        if fl != rl || fa[..fl] != ra[..rl] {
            mism += 1;
        }
    }
    mism
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn finish_match(xb: Fp, yb: Fp, s: U256, key: U256) {
    unsafe {
        OUT_KEY.copy_from_slice(&key.to_be_bytes());
        FAST_XB = xb;
        FAST_YB = yb;
        FAST_S = s;
    }
}

/// Compute the address for an affine point and test it against the target.
fn test_point(x: &Fp, y: &Fp, target: &[u8], mode: u32, ic: bool, addr: &mut [u8; 40]) -> bool {
    let len = address_from_xy(&x.retrieve().to_be_bytes(), &y.retrieve().to_be_bytes(), addr);
    let a = &mut addr[..len];
    if ic {
        for b in a.iter_mut() {
            b.make_ascii_lowercase();
        }
    }
    matches(a, target, mode)
}

/// Affine point addition P + Q (P != +/-Q). One inversion; used only off the
/// hot path (self-test / reseed).
fn affine_add(xb: Fp, yb: Fp, xq: Fp, yq: Fp) -> (Fp, Fp) {
    let (inv, _) = (xq - xb).invert();
    let lambda = (yq - yb) * inv;
    let xr = lambda * lambda - xb - xq;
    let yr = lambda * (xb - xr) - yb;
    (xr, yr)
}

fn reseed_fast(xb: &mut Fp, yb: &mut Fp, s: U256) {
    let sc = scalar_from_u256(s);
    let enc = (ProjectivePoint::GENERATOR * sc).to_affine().to_encoded_point(false);
    let b = enc.as_bytes();
    *xb = Fp::new(&U256::from_be_slice(&b[1..33]));
    *yb = Fp::new(&U256::from_be_slice(&b[33..65]));
}

/// (s + off) mod n. off is small, so a single conditional subtraction suffices.
fn add_mod_n(s: U256, off: u64) -> U256 {
    let sum = s.wrapping_add(&U256::from_u64(off));
    if sum >= N {
        sum.wrapping_sub(&N)
    } else {
        sum
    }
}

fn scalar_from_u256(u: U256) -> Scalar {
    scalar_from_bytes(&u.to_be_bytes())
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    use k256::elliptic_curve::scalar::FromUintUnchecked;
    let n = k256::U256::from_be_slice(bytes);
    let s = Scalar::from_uint_unchecked(n);
    if bool::from(<Scalar as k256::elliptic_curve::ff::Field>::is_zero(&s)) {
        Scalar::ONE
    } else {
        s
    }
}

fn matches(addr: &[u8], target: &[u8], mode: u32) -> bool {
    let tlen = target.len();
    if tlen > addr.len() {
        return false;
    }
    match mode {
        1 => &addr[addr.len() - tlen..] == target,    // suffix
        2 => addr.windows(tlen).any(|w| w == target),  // contains
        _ => &addr[..tlen] == target,                  // prefix
    }
}

/// Build the TRON Base58Check address from 32-byte X and Y into `out`.
fn address_from_xy(x: &[u8], y: &[u8], out: &mut [u8; 40]) -> usize {
    let mut xy = [0u8; 64];
    xy[..32].copy_from_slice(x);
    xy[32..].copy_from_slice(y);

    let mut k = Keccak256::new();
    k.update(xy);
    let hash = k.finalize();

    let mut payload = [0u8; 21];
    payload[0] = 0x41;
    payload[1..].copy_from_slice(&hash[12..32]);

    let c1 = Sha256::digest(payload);
    let c2 = Sha256::digest(c1);

    let mut full = [0u8; 25];
    full[..21].copy_from_slice(&payload);
    full[21..].copy_from_slice(&c2[..4]);

    base58_into(&full, out)
}

/// Base58-encode `input` (no leading zeros expected for 0x41) into `out`.
fn base58_into(input: &[u8; 25], out: &mut [u8; 40]) -> usize {
    let mut digits = [0u8; 40];
    let mut len = 0usize;
    for &byte in input.iter() {
        let mut carry = byte as u32;
        for d in digits.iter_mut().take(len) {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }
    for i in 0..len {
        out[i] = BASE58_ALPHABET[digits[len - 1 - i] as usize];
    }
    len
}
