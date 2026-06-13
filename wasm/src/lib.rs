// TRON vanity search kernel, compiled to WebAssembly.
//
// The whole inner loop (EC point increment -> keccak -> Base58Check -> match)
// runs inside WASM so there is no per-candidate JS<->WASM boundary crossing.
// JS only: writes a random start key + target into shared memory, then calls
// `run(...)` for a chunk of iterations and reads back any match.
use k256::elliptic_curve::group::Curve as _;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

// Points converted to affine per single batched inversion.
const BATCH: usize = 256;

const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// --- Shared buffers (fixed offsets exported to JS). ---
static mut START_KEY: [u8; 32] = [0u8; 32]; // input: starting private key
static mut OUT_KEY: [u8; 32] = [0u8; 32]; // output: private key of a match
static mut TARGET: [u8; 64] = [0u8; 64]; // input: target text (ASCII Base58)

// --- Persistent search state across run() calls. ---
static mut CUR_SCALAR: Option<Scalar> = None;
static mut CUR_POINT: Option<ProjectivePoint> = None;

#[no_mangle]
pub extern "C" fn start_key_ptr() -> *const u8 {
    unsafe { START_KEY.as_ptr() }
}
#[no_mangle]
pub extern "C" fn out_key_ptr() -> *const u8 {
    unsafe { OUT_KEY.as_ptr() }
}
#[no_mangle]
pub extern "C" fn target_ptr() -> *const u8 {
    unsafe { TARGET.as_ptr() }
}

/// Seed the search from the 32-byte START_KEY buffer.
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

/// Run up to `max_iters` candidates. mode: 0=prefix, 1=suffix, 2=contains.
/// Returns the iteration index of a match (and writes its key to OUT_KEY), or
/// -1 if no match was found within this chunk.
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

        // Collect a batch of consecutive points, then normalize with ONE
        // field inversion instead of one per point.
        for p in points.iter_mut().take(n) {
            *p = point;
            point += g;
        }
        ProjectivePoint::batch_normalize(&points[..n], &mut affines[..n]);

        for j in 0..n {
            let len = address_into(&affines[j], &mut addr);
            let a = &mut addr[..len];
            if ic {
                for b in a.iter_mut() {
                    b.make_ascii_lowercase();
                }
            }
            if matches(a, target, mode) {
                let key_scalar = scalar + Scalar::from(j as u64);
                let kb = key_scalar.to_bytes();
                unsafe {
                    OUT_KEY.copy_from_slice(&kb);
                    // Continue just past the match next time.
                    CUR_SCALAR = Some(key_scalar + Scalar::ONE);
                    CUR_POINT = Some(affines[j].into_projective_plus_g(g));
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

// Small helper to make the "resume point" explicit and readable.
trait NextPoint {
    fn into_projective_plus_g(self, g: ProjectivePoint) -> ProjectivePoint;
}
impl NextPoint for AffinePoint {
    fn into_projective_plus_g(self, g: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::from(self) + g
    }
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    use k256::elliptic_curve::scalar::FromUintUnchecked;
    use k256::U256;
    // Reduce into range; if zero, bump to 1 (caller supplies random nonzero).
    let n = U256::from_be_slice(bytes);
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
        1 => &addr[addr.len() - tlen..] == target, // suffix
        2 => addr.windows(tlen).any(|w| w == target), // contains
        _ => &addr[..tlen] == target,               // prefix
    }
}

/// Build the TRON Base58Check address for an affine point into `out`; returns length.
fn address_into(aff: &AffinePoint, out: &mut [u8; 40]) -> usize {
    let enc = aff.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let xy = &enc.as_bytes()[1..65];

    let mut k = Keccak256::new();
    k.update(xy);
    let hash = k.finalize(); // 32 bytes

    // payload = 0x41 || last 20 bytes of keccak
    let mut payload = [0u8; 21];
    payload[0] = 0x41;
    payload[1..].copy_from_slice(&hash[12..32]);

    // checksum = first 4 bytes of sha256(sha256(payload))
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
    // digits are little-endian base58; reverse into ASCII alphabet.
    for i in 0..len {
        out[i] = BASE58_ALPHABET[digits[len - 1 - i] as usize];
    }
    len
}
