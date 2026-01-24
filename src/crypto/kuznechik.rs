// src/crypto/kuznechik.rs
//! Реализация блочного шифра ГОСТ 34.12-2018 "Кузнечик" (Kuznyechik)
//!
//! Ссылки:
//! - RFC 7801: GOST R 34.12-2015: Block Cipher "Kuznyechik" [web:30]

pub const BLOCK_SIZE: usize = 16; // 128 бит
pub const KEY_SIZE: usize = 32;   // 256 бит
pub const ROUNDS: usize = 10;     // 10 раундовых ключей

/// S-блок Pi (прямой) из RFC 7801
pub const PI: [u8; 256] = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
];

/// Коэффициенты для линейной функции l() из RFC 7801:
/// l(a_15..a_0) = Σ (c_i * a_i) в GF(2^8), где полином x^8+x^7+x^6+x+1 (0xC3). [web:30]
const L_COEFFS: [u8; 16] = [
    0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
    0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01,
];

#[derive(Clone)]
pub struct Kuznechik {
    round_keys: [[u8; BLOCK_SIZE]; ROUNDS],
    pi_inv: [u8; 256],
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] ^ b[i];
    }
    r
}

/// Умножение в GF(2^8) по модулю x^8 + x^7 + x^6 + x + 1 (0xC3) [web:30]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0xC3;
        }
        b >>= 1;
    }
    res
}

/// Линейная функция l(a_15..a_0) из RFC 7801 (возвращает 1 байт) [web:30]
fn l_func(state: &[u8; 16]) -> u8 {
    let mut x = 0u8;
    for i in 0..16 {
        x ^= gf_mul(L_COEFFS[i], state[i]);
    }
    x
}

/// Преобразование R: (a15..a0) -> (l(a15..a0), a15, ..., a1) [web:30]
fn r(state: &mut [u8; 16]) {
    let x = l_func(state);
    for i in (1..16).rev() {
        state[i] = state[i - 1];
    }
    state[0] = x;
}

/// Обратное R^{-1} [web:30]
fn r_inv(state: &mut [u8; 16]) {
    let x0 = state[0];
    for i in 0..15 {
        state[i] = state[i + 1];
    }
    // после сдвига state содержит (a14..a0, ?), нужно восстановить последний байт a15
    // Из определения R: x0 = l(a15..a0) => a15 = x0 XOR Σ_{i=0..14} c_i*a_i (с учётом расположения)
    // Удобно: вычисляем l_func() от текущего state, где последний байт пока любой (0),
    // и решаем относительно последнего байта, но проще стандартный трюк:
    // выставляем последний байт = 0, считаем l_func, потом a15 = x0 XOR l_func (при last=0) / c_last.
    // Однако c_last = 0x01 (последний коэффициент), поэтому деление не нужно.
    let mut tmp = *state;
    tmp[15] = 0;
    let t = l_func(&tmp);
    state[15] = x0 ^ t;
}

fn l(state: &mut [u8; 16]) {
    for _ in 0..16 {
        r(state);
    }
}

fn l_inv(state: &mut [u8; 16]) {
    for _ in 0..16 {
        r_inv(state);
    }
}

impl Kuznechik {
    fn build_pi_inv() -> [u8; 256] {
        let mut inv = [0u8; 256];
        for (i, &v) in PI.iter().enumerate() {
            inv[v as usize] = i as u8;
        }
        inv
    }

    fn s(state: &mut [u8; 16]) {
        for i in 0..16 {
            state[i] = PI[state[i] as usize];
        }
    }

    fn s_inv(&self, state: &mut [u8; 16]) {
        for i in 0..16 {
            state[i] = self.pi_inv[state[i] as usize];
        }
    }

    fn l(state: &mut [u8; 16]) {
        l(state);
    }

    fn l_inv(state: &mut [u8; 16]) {
        l_inv(state);
    }

    /// LSX = L(S(X ⊕ K))
    fn lsx(&self, x: &[u8; 16], k: &[u8; 16]) -> [u8; 16] {
        let mut t = xor16(x, k);
        Self::s(&mut t);
        Self::l(&mut t);
        t
    }

    /// Итерация F из key schedule: F(Ci, (a,b)) = (b ⊕ L(S(a⊕Ci)), a) [web:30]
    fn f(&self, c: &[u8; 16], a: &[u8; 16], b: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
        let t = self.lsx(a, c);
        (xor16(&t, b), *a)
    }

    /// C_i = L(Vec_128(i)), i=1..32 [web:30]
    fn build_iter_constants(&self) -> [[u8; 16]; 32] {
        let mut cs = [[0u8; 16]; 32];
        for i in 0..32 {
            let mut v = [0u8; 16];
            v[15] = (i as u8) + 1; // Vec_128(i+1): число в младшем байте, big-endian нулей
            // (в RFC это Vec_128(i), где i=1..32) [web:30]
            Self::l(&mut v);
            cs[i] = v;
        }
        cs
    }

    pub fn new(master_key: [u8; KEY_SIZE]) -> Self {
        let pi_inv = Self::build_pi_inv();
        let mut kuz = Self {
            round_keys: [[0u8; 16]; ROUNDS],
            pi_inv,
        };

        // K1, K2
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        k1.copy_from_slice(&master_key[0..16]);
        k2.copy_from_slice(&master_key[16..32]);

        kuz.round_keys[0] = k1;
        kuz.round_keys[1] = k2;

        let c = kuz.build_iter_constants();

        // 32 итерации F, каждые 8 итераций сохраняем очередные K_{2i+1}, K_{2i+2} [web:30]
        let mut a = k1;
        let mut b = k2;

        for j in 0..32 {
            let (na, nb) = kuz.f(&c[j], &a, &b);
            a = na;
            b = nb;

            // после 8,16,24,32 итерации кладём ключи
            if (j + 1) % 8 == 0 {
                let idx = (j + 1) / 4; // 8->2, 16->4, 24->6, 32->8
                // idx принимает 2,4,6,8 => это позиции K3..K10
                kuz.round_keys[idx] = a;
                kuz.round_keys[idx + 1] = b;
            }
        }

        kuz
    }

    pub fn encrypt_block(&self, block: [u8; 16]) -> [u8; 16] {
        let mut x = block;

        // 9 раундов: X <- LSX(X, K_i)
        for i in 0..9 {
            x = self.lsx(&x, &self.round_keys[i]);
        }

        // 10-й: X <- X ⊕ K_10
        xor16(&x, &self.round_keys[9])
    }

    pub fn decrypt_block(&self, block: [u8; 16]) -> [u8; 16] {
        let mut x = xor16(&block, &self.round_keys[9]);

        for i in (0..9).rev() {
            // обратный раунд: X <- K_i ⊕ S^{-1}(L^{-1}(X))
            Self::l_inv(&mut x);
            self.s_inv(&mut x);
            x = xor16(&x, &self.round_keys[i]);
        }

        x
    }

    #[cfg(test)]
    pub fn get_round_keys(&self) -> &[[u8; 16]; ROUNDS] {
        &self.round_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand::Rng;

    #[test]
    fn test_pi_inv_is_inverse() {
        let pi_inv = Kuznechik::build_pi_inv();
        for i in 0u8..=255 {
            let s = PI[i as usize];
            assert_eq!(pi_inv[s as usize], i);
        }
    }

    /// Официальный тест-вектор из RFC 7801 (должен проходить).
    #[test]
    fn test_rfc_7801_vector() {
        let key = hex!("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        let pt  = hex!("1122334455667700ffeeddccbbaa9988");
        let ct  = hex!("7f679d90bebc24305a468d42b9d4edcd");

        let kuz = Kuznechik::new(key);
        assert_eq!(kuz.encrypt_block(pt), ct);
        assert_eq!(kuz.decrypt_block(ct), pt);
    }

    /// Заменяем неправильный AES-вектор 66e94b... на корректную проверку:
    /// нулевой ключ + нулевой блок должны корректно roundtrip’иться.
    #[test]
    fn test_zero_key_zero_block_roundtrip() {
        let key = [0u8; KEY_SIZE];
        let pt  = [0u8; BLOCK_SIZE];

        let kuz = Kuznechik::new(key);
        let ct = kuz.encrypt_block(pt);
        let dec = kuz.decrypt_block(ct);

        assert_eq!(dec, pt, "zero-key/zero-pt roundtrip failed");
    }

    #[test]
    fn test_roundtrip_random() {
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            let mut key = [0u8; KEY_SIZE];
            let mut pt  = [0u8; BLOCK_SIZE];
            rng.fill(&mut key);
            rng.fill(&mut pt);

            let kuz = Kuznechik::new(key);
            let ct = kuz.encrypt_block(pt);
            let dec = kuz.decrypt_block(ct);
            assert_eq!(dec, pt);
        }
    }
}