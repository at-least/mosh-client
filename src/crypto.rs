//! mosh crypto + packet layer — spec §2-§3.
//!
//! Every datagram on the wire is `nonce_suffix(8) || OCB3 ct || tag(16)`;
//! the plaintext is `u16_be timestamp || u16_be timestamp_reply || fragment
//! bytes`. Nonces are 12 bytes: four zero bytes plus the big-endian u64
//! value whose bit 63 is the direction flag and whose low 63 bits are the
//! per-datagram sequence number. AES-128 comes from the crate graph's
//! pinned `aes`; the OCB3 mode from RustCrypto's `ocb3` — the acceptance
//! oracles are the draft-krovetz-ocb-03 Appendix-A vectors (the same ones
//! mosh's own test suite uses) and the golden stock-session fixture.
//!
//! Nonce safety is structural, not conventional: a [`MoshSealer`] owns
//! one direction and the monotonic u63 counter, so no API path can seal
//! two datagrams under the same nonce, and sealing in the peer's
//! direction (which would collide with the server's nonces — both
//! directions share one key) is unrepresentable. A [`MoshOpener`] is
//! built for the peer's direction and rejects datagrams carrying our own
//! direction bit (stock mosh `dos_assert`s here, i.e. aborts; we drop —
//! a deliberate hardening difference, spec §3).
//!
//! Residual, accepted: `ocb3`'s derived subkey tables are not zeroized
//! on drop by the crate (its AES key schedule is, via `aes/zeroize`).

use std::fmt;

use aes::Aes128;
use base64ct::{Base64, Encoding};
use ocb3::aead::consts::{U12, U16};
use ocb3::aead::{Aead, Key, KeyInit, Nonce as AeadNonce};
use ocb3::Ocb3;
use thiserror::Error;
use zeroize::Zeroizing;

/// The 8-byte value suffix carried on the wire (nonce bytes 4..12).
pub const WIRE_NONCE_LEN: usize = 8;
/// Full OCB3 nonce length: four zero bytes plus [`WIRE_NONCE_LEN`].
pub const NONCE_LEN: usize = 12;
/// OCB3 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Smallest legal datagram: nonce suffix + tag, empty plaintext.
pub const MIN_DATAGRAM_LEN: usize = WIRE_NONCE_LEN + TAG_LEN;
/// mosh kills a session after 2^47 encrypted blocks (≈2 PB); both
/// directions share one key, hence half the RFC's 2^48 per-key ceiling.
pub const BLOCK_LIMIT: u64 = 1 << 47;

/// Direction flag: bit 63 of the nonce value (network.cc `DIRECTION_MASK`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    /// Client to server — direction bit 0.
    ToServer,
    /// Server to client — direction bit 1.
    ToClient,
}

impl Direction {
    /// The opposite direction.
    pub fn opposite(self) -> Self {
        match self {
            Direction::ToServer => Direction::ToClient,
            Direction::ToClient => Direction::ToServer,
        }
    }

    fn bit(self) -> u64 {
        match self {
            Direction::ToServer => 0,
            Direction::ToClient => 1,
        }
    }
}

const DIRECTION_MASK: u64 = 1 << 63;
const SEQ_MASK: u64 = u64::MAX ^ DIRECTION_MASK;

/// A 12-byte mosh nonce: `00 00 00 00 || u64_be(value)`, where `value`'s
/// bit 63 is the direction and bits 0..62 the sequence number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Nonce {
    value: u64,
}

impl Nonce {
    /// The nonce for a packet sent in `direction` with sequence `seq`.
    /// Sequence numbers are u63; bits above are masked, so this cannot
    /// leak into the direction flag.
    pub fn new(direction: Direction, seq: u64) -> Self {
        Nonce {
            value: (direction.bit() << 63) | (seq & SEQ_MASK),
        }
    }

    fn from_wire_suffix(suffix: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&suffix[..8]);
        Nonce {
            value: u64::from_be_bytes(bytes),
        }
    }

    /// The 12 bytes handed to OCB3.
    fn to_nonce12(self) -> [u8; NONCE_LEN] {
        let mut out = [0u8; NONCE_LEN];
        out[4..].copy_from_slice(&self.value.to_be_bytes());
        out
    }

    /// The 8 bytes carried on the wire.
    fn wire_suffix(self) -> [u8; WIRE_NONCE_LEN] {
        self.value.to_be_bytes()
    }

    fn seq(self) -> u64 {
        self.value & SEQ_MASK
    }

    fn direction(self) -> Direction {
        if self.value & DIRECTION_MASK == 0 {
            Direction::ToServer
        } else {
            Direction::ToClient
        }
    }
}

/// The 16-byte session key in its 22-character printable form (standard
/// base64 alphabet, `==` padding stripped). Parsing verifies the
/// round-trip so non-canonical encodings are rejected, matching mosh's
/// `Base64Key` (crypto.cc:110-131).
#[derive(Clone)]
pub struct Base64Key(Zeroizing<[u8; 16]>);

impl Base64Key {
    /// Parse a 22-character key. Errors on wrong length, non-base64
    /// characters, or a non-canonical encoding of the 16 bytes.
    pub fn parse(printable: &str) -> Result<Self, MoshCryptoError> {
        if printable.len() != 22 {
            return Err(MoshCryptoError::BadKeyLength);
        }
        let padded = Zeroizing::new(format!("{printable}=="));
        let bytes = Zeroizing::new(
            Base64::decode_vec(padded.as_str()).map_err(|_| MoshCryptoError::BadKeyEncoding)?,
        );
        let Ok(key) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            return Err(MoshCryptoError::BadKeyLength);
        };
        let parsed = Base64Key(Zeroizing::new(key));
        if parsed.printable() != printable {
            return Err(MoshCryptoError::BadKeyNotCanonical);
        }
        Ok(parsed)
    }

    /// The 22-character printable form.
    pub fn printable(&self) -> String {
        Base64::encode_string(&self.0[..16])[..22].to_string()
    }
}

impl fmt::Debug for Base64Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print key material
        f.write_str("Base64Key(<16 bytes>)")
    }
}

/// The plaintext packet header: two big-endian u16 timestamps, 0xFFFF
/// meaning "none" (spec §3). Everything after it is fragment payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PacketHeader {
    pub timestamp: u16,
    pub timestamp_reply: u16,
}

impl PacketHeader {
    fn parse(payload: &[u8]) -> Option<(PacketHeader, &[u8])> {
        if payload.len() < 4 {
            return None;
        }
        let header = PacketHeader {
            timestamp: u16::from_be_bytes([payload[0], payload[1]]),
            timestamp_reply: u16::from_be_bytes([payload[2], payload[3]]),
        };
        Some((header, &payload[4..]))
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.timestamp_reply.to_be_bytes());
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MoshCryptoError {
    #[error("mosh key must be 22 characters (16 bytes)")]
    BadKeyLength,
    #[error("mosh key is not well-formed base64")]
    BadKeyEncoding,
    #[error("mosh key is not a canonical encoding of a 128-bit key")]
    BadKeyNotCanonical,
    #[error("datagram too short to contain nonce and tag")]
    DatagramTooShort,
    #[error("datagram failed the integrity check")]
    TagMismatch,
    #[error("packet plaintext shorter than the 4-byte timestamp header")]
    PacketTooShort,
    #[error("datagram carries our own direction bit (reflected packet)")]
    DirectionMismatch,
    #[error("send sequence numbers exhausted")]
    SequenceExhausted,
    #[error("session exceeded the 2^47-block per-key limit")]
    SessionExhausted,
    #[error("the AEAD rejected the packet on send")]
    EncryptFailed,
}

/// The concrete AEAD: AES-128 in OCB3, 96-bit nonce, 128-bit tag.
pub type AesOcb = Ocb3<Aes128, U12, U16>;

fn new_ocb(key: &Base64Key) -> AesOcb {
    // the intermediate key copy is wiped on scope exit
    let key_copy = Zeroizing::new(*key.0);
    Ocb3::new(&Key::<AesOcb>::from(*key_copy))
}

/// The sending half of a session: owns our direction and the monotonic
/// u63 packet counter, so nonce reuse is structurally impossible and
/// sealing "as the peer" is unrepresentable. Counts encrypted blocks
/// toward [`BLOCK_LIMIT`] (spec §2).
pub struct MoshSealer {
    ocb: AesOcb,
    direction: Direction,
    next_seq: u64,
    blocks_encrypted: u64,
}

impl MoshSealer {
    /// A sealer sending in `direction` (the client passes
    /// [`Direction::ToServer`]).
    pub fn new(key: &Base64Key, direction: Direction) -> Self {
        MoshSealer {
            ocb: new_ocb(key),
            direction,
            next_seq: 0,
            blocks_encrypted: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<Nonce, MoshCryptoError> {
        if self.next_seq > SEQ_MASK {
            return Err(MoshCryptoError::SequenceExhausted);
        }
        let nonce = Nonce::new(self.direction, self.next_seq);
        self.next_seq += 1;
        Ok(nonce)
    }

    /// Seal `header + fragment` into a full datagram, consuming one
    /// sequence number.
    pub fn seal(
        &mut self,
        header: &PacketHeader,
        fragment: &[u8],
    ) -> Result<Vec<u8>, MoshCryptoError> {
        let mut packet = Vec::with_capacity(4 + fragment.len());
        header.write(&mut packet);
        packet.extend_from_slice(fragment);

        self.blocks_encrypted += (packet.len() as u64).div_ceil(16);
        if self.blocks_encrypted >= BLOCK_LIMIT {
            return Err(MoshCryptoError::SessionExhausted);
        }

        let nonce = self.next_nonce()?;
        let aead_nonce = AeadNonce::<AesOcb>::from(nonce.to_nonce12());
        let ct_and_tag = self
            .ocb
            .encrypt(&aead_nonce, packet.as_slice())
            .map_err(|_| MoshCryptoError::EncryptFailed)?;

        let mut out = Vec::with_capacity(WIRE_NONCE_LEN + ct_and_tag.len());
        out.extend_from_slice(&nonce.wire_suffix());
        out.extend_from_slice(&ct_and_tag);
        Ok(out)
    }

    /// Blocks encrypted so far (test/diagnostic access).
    pub fn blocks_encrypted(&self) -> u64 {
        self.blocks_encrypted
    }
}

/// The receiving half of a session: decrypts datagrams from one peer
/// direction and rejects anything carrying our own direction bit
/// (reflected playback, spec §3). The u63 sequence number is returned —
/// the replay window itself belongs to the session layer (§3 seq gate).
pub struct MoshOpener {
    ocb: AesOcb,
    peer_direction: Direction,
}

impl MoshOpener {
    /// An opener for datagrams arriving FROM `peer_direction` (the client
    /// passes [`Direction::ToClient`]).
    pub fn new(key: &Base64Key, peer_direction: Direction) -> Self {
        MoshOpener {
            ocb: new_ocb(key),
            peer_direction,
        }
    }

    /// Open a datagram into its sequence number, header and fragment
    /// bytes. Tag mismatches are [`MoshCryptoError::TagMismatch`] —
    /// callers drop the datagram, never the session.
    pub fn open(&self, datagram: &[u8]) -> Result<(u64, PacketHeader, Vec<u8>), MoshCryptoError> {
        if datagram.len() < MIN_DATAGRAM_LEN {
            return Err(MoshCryptoError::DatagramTooShort);
        }
        let nonce = Nonce::from_wire_suffix(&datagram[..WIRE_NONCE_LEN]);
        if nonce.direction() != self.peer_direction {
            return Err(MoshCryptoError::DirectionMismatch);
        }
        let aead_nonce = AeadNonce::<AesOcb>::from(nonce.to_nonce12());
        let packet = self
            .ocb
            .decrypt(&aead_nonce, &datagram[WIRE_NONCE_LEN..])
            .map_err(|_| MoshCryptoError::TagMismatch)?;
        let (header, fragment) =
            PacketHeader::parse(&packet).ok_or(MoshCryptoError::PacketTooShort)?;
        Ok((nonce.seq(), header, fragment.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // draft-krovetz-ocb-03 Appendix A — the same vectors mosh's own
    // ocb-aes.cc runs. (aad, plaintext, ciphertext||tag)
    const IETF_KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const IETF_NONCE: &str = "000102030405060708090a0b";

    #[test]
    fn ocb3_draft_vectors() {
        let vectors: &[(&str, &str, &str)] = &[
            ("", "", "197b9c3c441d3c83eafb2bef633b9182"),
            (
                "0001020304050607",
                "0001020304050607",
                "92b657130a74b85a16dc76a46d47e1ead537209e8a96d14e",
            ),
            ("0001020304050607", "", "98b91552c8c009185044e30a6eb2fe21"),
            (
                "",
                "0001020304050607",
                "92b657130a74b85a971effcae19ad4716f88e87b871fbeed",
            ),
            (
                "000102030405060708090a0b0c0d0e0f",
                "000102030405060708090a0b0c0d0e0f",
                "bea5e8798dbe7110031c144da0b26122776c9924d6723a1fc4524532ac3e5beb",
            ),
            (
                "000102030405060708090a0b0c0d0e0f",
                "",
                "7ddb8e6cea6814866212509619b19cc6",
            ),
            (
                "",
                "000102030405060708090a0b0c0d0e0f",
                "bea5e8798dbe7110031c144da0b2612213cc8b747807121a4cbb3e4bd6b456af",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "bea5e8798dbe7110031c144da0b26122fcfcee7a2a8d4d485fa94fc3f38820f1dc3f3d1fd4e55e1c",
            ),
        ];
        let key_src: [u8; 16] = hex(IETF_KEY).try_into().unwrap();
        let nonce_bytes: [u8; 12] = hex(IETF_NONCE).try_into().unwrap();
        for (aad, pt, expected) in vectors {
            let ocb: AesOcb = Ocb3::new(&Key::<AesOcb>::from(key_src));
            let nonce = AeadNonce::<AesOcb>::from(nonce_bytes);
            let pt_bytes = hex(pt);
            let aad_bytes = hex(aad);
            let payload = ocb3::aead::Payload {
                msg: pt_bytes.as_slice(),
                aad: aad_bytes.as_slice(),
            };
            let sealed = ocb.encrypt(&nonce, payload).expect("seal");
            assert_eq!(sealed, hex(expected), "aad={aad} pt={pt}");
            let payload = ocb3::aead::Payload {
                msg: sealed.as_slice(),
                aad: aad_bytes.as_slice(),
            };
            assert_eq!(ocb.decrypt(&nonce, payload).unwrap(), pt_bytes);
        }
    }

    #[test]
    fn key_codec_roundtrip_and_rejections() {
        let key = Base64Key::parse("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(key.printable(), "AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(key.0[..], [0u8; 16]);

        assert_eq!(
            Base64Key::parse("AAAAAAAAAAAAAAAAAAAA").unwrap_err(),
            MoshCryptoError::BadKeyLength
        );
        assert_eq!(
            Base64Key::parse("AAAAAAAAAAAAAAAAAAAAAAA").unwrap_err(),
            MoshCryptoError::BadKeyLength
        );
        assert_eq!(
            Base64Key::parse("AAAAAAAAAAAAAAAAAAAAA!").unwrap_err(),
            MoshCryptoError::BadKeyEncoding
        );
        // decodes to the same 16 zero bytes but is not canonical ('D' sets
        // the two padding bits) — mosh rejects it via round-trip compare;
        // base64ct's strict decoder rejects at decode time. Either error
        // is correct, it must simply be rejected.
        assert!(matches!(
            Base64Key::parse("AAAAAAAAAAAAAAAAAAAAAD").unwrap_err(),
            MoshCryptoError::BadKeyEncoding | MoshCryptoError::BadKeyNotCanonical
        ));

        let printed = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        assert_eq!(printed.printable(), "7l1cNvxYVkWP1j8zMC08Jg");
        // Debug never leaks the printable form
        assert!(!format!("{printed:?}").contains("7l1c"));
    }

    #[test]
    fn sealer_never_reuses_a_nonce_or_direction() {
        let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        let mut sealer = MoshSealer::new(&key, Direction::ToServer);
        let opener = MoshOpener::new(&key, Direction::ToClient);

        let header = PacketHeader {
            timestamp: 1,
            timestamp_reply: 0xFFFF,
        };
        // two identical sends still use distinct nonces
        let a = sealer.seal(&header, b"x").unwrap();
        let b = sealer.seal(&header, b"x").unwrap();
        assert_ne!(&a[..8], &b[..8]);

        // nonces advance by exactly one, direction bit stays ours
        let first = u64::from_be_bytes(a[..8].try_into().unwrap());
        let second = u64::from_be_bytes(b[..8].try_into().unwrap());
        assert_eq!(first & DIRECTION_MASK, 0);
        assert_eq!(second & DIRECTION_MASK, 0);
        assert_eq!(second - first, 1);

        // our own datagrams reflected back at us are rejected outright
        assert_eq!(
            opener.open(&a).unwrap_err(),
            MoshCryptoError::DirectionMismatch
        );

        // cross-check: the same bytes as a server datagram fail the tag
        // (the direction bit is part of the nonce), never silently decode
        let mut forged = a.clone();
        forged[0] |= 0x80; // flip direction bit of the wire nonce
        assert_eq!(
            opener.open(&forged).unwrap_err(),
            MoshCryptoError::TagMismatch
        );
    }

    #[test]
    fn opener_roundtrip_tamper_and_truncation() {
        let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        let mut peer_sealer = MoshSealer::new(&key, Direction::ToClient);
        let opener = MoshOpener::new(&key, Direction::ToClient);

        let header = PacketHeader {
            timestamp: 1234,
            timestamp_reply: 0xFFFF,
        };
        let datagram = peer_sealer.seal(&header, b"fragment bytes").unwrap();

        let (seq, parsed, fragment) = opener.open(&datagram).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(
            parsed,
            PacketHeader {
                timestamp: 1234,
                timestamp_reply: 0xFFFF
            }
        );
        assert_eq!(fragment, b"fragment bytes");

        let mut bad = datagram.clone();
        bad[10] ^= 1;
        assert_eq!(opener.open(&bad).unwrap_err(), MoshCryptoError::TagMismatch);

        let mut bad = datagram.clone();
        bad[0] ^= 1; // different nonce -> different keystream -> tag fails
        assert_eq!(opener.open(&bad).unwrap_err(), MoshCryptoError::TagMismatch);

        assert_eq!(
            opener.open(&datagram[..23]).unwrap_err(),
            MoshCryptoError::DatagramTooShort
        );

        // an empty fragment is legal: the 4-byte header is always present
        // (PacketTooShort is defense against a peer sending less than
        // that, which stock mosh never does)
        let bare = peer_sealer.seal(&header, b"").unwrap();
        let (_, parsed, fragment) = opener.open(&bare).unwrap();
        assert_eq!(fragment, b"");
        assert_eq!(parsed, header);
    }

    #[test]
    fn sequence_exhaustion_is_an_error_not_a_wrap() {
        let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        let mut sealer = MoshSealer::new(&key, Direction::ToServer);
        sealer.next_seq = SEQ_MASK + 1;
        assert_eq!(
            sealer
                .seal(
                    &PacketHeader {
                        timestamp: 0,
                        timestamp_reply: 0
                    },
                    b"x"
                )
                .unwrap_err(),
            MoshCryptoError::SequenceExhausted
        );
    }

    #[test]
    fn block_limit_boundary() {
        let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        let mut sealer = MoshSealer::new(&key, Direction::ToServer);
        let header = PacketHeader {
            timestamp: 0xFFFF,
            timestamp_reply: 0xFFFF,
        };
        // the packet landing exactly at BLOCK_LIMIT-1 blocks still goes;
        // the next one (which would reach BLOCK_LIMIT) is refused
        sealer.blocks_encrypted = BLOCK_LIMIT - 5; // 16-byte pt = 1 block
        assert!(sealer.seal(&header, &[0u8; 12]).is_ok()); // -> -4 ... up
        sealer.blocks_encrypted = BLOCK_LIMIT - 1;
        assert_eq!(
            sealer.seal(&header, &[0u8; 12]).unwrap_err(),
            MoshCryptoError::SessionExhausted
        );
        assert_eq!(sealer.blocks_encrypted(), BLOCK_LIMIT); // refused, counted
    }

    /// The golden transcript: every datagram from a real stock mosh 1.4.0
    /// session must open under the recorded key with the recorded
    /// direction. The fixture's c2s/s2c labels come from WHICH PROXY
    /// SOCKET a datagram arrived on (independent of the nonce bits), so
    /// this cross-checks our nonce-layout reading against real traffic.
    #[test]
    fn golden_transcript_opens() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let fixture = format!("{manifest}/tests/fixtures/mosh");
        let key_text = std::fs::read_to_string(format!("{fixture}/key.txt"))
            .expect("committed key.txt")
            .trim()
            .to_string();
        let transcript =
            std::fs::read_to_string(format!("{fixture}/transcript.json")).expect("fixture");
        let parsed: serde_json::Value = serde_json::from_str(&transcript).unwrap();

        let key = Base64Key::parse(&key_text).unwrap();
        assert_eq!(key.printable(), key_text);
        let c2s_opener = MoshOpener::new(&key, Direction::ToServer);
        let s2c_opener = MoshOpener::new(&key, Direction::ToClient);

        let events = parsed["events"].as_array().expect("events");
        assert!(
            events.len() >= 10,
            "golden transcript too thin ({} events)",
            events.len()
        );
        let mut seen = std::collections::HashSet::new();
        for event in events {
            let dir_label = event["dir"].as_str().unwrap();
            let bytes = hex(event["hex"].as_str().unwrap());
            let opener = match dir_label {
                "c2s" => &c2s_opener,
                "s2c" => &s2c_opener,
                other => panic!("bad dir label {other}"),
            };
            let (seq, _header, fragment) = opener
                .open(&bytes)
                .unwrap_or_else(|e| panic!("{dir_label} datagram failed to open: {e}"));
            // sequence numbers are unique per direction (monotonic counter)
            assert!(seen.insert((dir_label, seq)), "duplicate seq {seq}");
            // fragment sanity: >= the 10-byte fragment header, nonzero id
            // (stock instruction ids start at 1)
            assert!(
                fragment.len() >= 10,
                "fragment shorter than its own 10-byte header"
            );
            let id = u64::from_be_bytes(fragment[..8].try_into().unwrap());
            assert_ne!(id, 0);
        }
    }

    /// Boundary: the last usable sequence number must still seal, and
    /// only the one past it is exhausted — this gate is the key-reuse
    /// guard, so its `>` cannot tolerate an off-by-one.
    #[test]
    fn sequence_exhaustion_boundary_is_exact() {
        let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        let mut sealer = MoshSealer::new(&key, Direction::ToServer);
        sealer.next_seq = SEQ_MASK; // the last usable sequence number
        let header = PacketHeader {
            timestamp: 0,
            timestamp_reply: 0,
        };
        sealer
            .seal(&header, b"boundary")
            .expect("the last sequence before exhaustion must still seal");
        assert_eq!(
            sealer.seal(&header, b"boundary").unwrap_err(),
            MoshCryptoError::SequenceExhausted,
            "the sequence one past the last usable one must be exhausted"
        );
    }

    /// Boundary: a datagram of exactly MIN_DATAGRAM_LEN gets past the
    /// length gate (to the tag check), only a shorter one is rejected
    /// as too short.
    #[test]
    fn min_datagram_len_boundary_is_exact() {
        let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
        let opener = MoshOpener::new(&key, Direction::ToClient);
        let short = vec![0u8; MIN_DATAGRAM_LEN - 1];
        assert_eq!(
            opener.open(&short).unwrap_err(),
            MoshCryptoError::DatagramTooShort
        );
        // exact length, ToClient direction bit set, garbage payload:
        // past the length gate, dead at the tag check
        let mut exact = vec![0u8; MIN_DATAGRAM_LEN];
        exact[0] = 0x80;
        assert_eq!(
            opener.open(&exact).unwrap_err(),
            MoshCryptoError::TagMismatch,
            "an exact-length datagram must reach the tag check"
        );
    }
}
