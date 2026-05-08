// src/cipher/core.rs
use super::block::Block;
use super::keys::Keys;
use super::operations::*;

/// incr_l: инкремент старших 64 бит (байты 0–7), счётчик Y для шифрования.
fn incr_l(y: &mut [u8; BLOCK_SIZE]) {
    let mut hi = u64::from_be_bytes(y[..8].try_into().unwrap());
    hi = hi.wrapping_add(1);
    y[..8].copy_from_slice(&hi.to_be_bytes());
}

/// incr_r: инкремент младших 64 бит (байты 8–15), счётчик Z для MAC.
fn incr_r(z: &mut [u8; BLOCK_SIZE]) {
    let mut lo = u64::from_be_bytes(z[8..].try_into().unwrap());
    lo = lo.wrapping_add(1);
    z[8..].copy_from_slice(&lo.to_be_bytes());
}

pub struct Kuznechik {
    keys: Keys,
}

impl Kuznechik {
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self { keys: Keys::new(key) }
    }

    #[inline(always)]
    fn encrypt_raw(&self, mut block: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        for round in 1..=9 {
            block = x_transform(block, self.keys.get_round_key(round));
            block = sl_transform(&block);
        }
        x_transform(block, self.keys.get_round_key(10))
    }

    /// Шифрует два независимых блока за один проход, интерливируя раунды.
    /// CPU может выполнять оба потока параллельно через ILP.
    #[inline(always)]
    fn encrypt_raw_pair(&self, mut a: [u8; BLOCK_SIZE], mut b: [u8; BLOCK_SIZE]) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
        for round in 1..=9 {
            let k = self.keys.get_round_key(round);
            a = x_transform(a, k);
            a = sl_transform(&a);
            b = x_transform(b, k);
            b = sl_transform(&b);
        }
        let k10 = self.keys.get_round_key(10);
        (x_transform(a, k10), x_transform(b, k10))
    }

    pub fn encrypt_block(&self, block: &mut Block) -> [u8; BLOCK_SIZE] {
        for round in 1..=9 {
            block.x(self.keys.get_round_key(round));
            block.sl();
        }
        block.x(self.keys.get_round_key(10));
        block.get_block()
    }

    pub fn decrypt_block(&self, block: &mut Block) -> [u8; BLOCK_SIZE] {
        block.x(self.keys.get_round_key(10));
        for round in (1..=9).rev() {
            block.l_inv();
            block.s_inv();
            block.x(self.keys.get_round_key(round));
        }
        block.get_block()
    }

    /// Аутентифицированное шифрование в режиме MGM.
    /// iv — синхропосылка длиной от 1 до 16 байт (16 байт соответствует c=n=128).
    /// mac_len_bits — длина имитовставки (32..128, кратная 8).
    pub fn encrypt_mgm(&self, plaintext: &[u8], aad: &[u8], iv: &[u8], mac_len_bits: usize) -> (Vec<u8>, Vec<u8>) {
        assert!(iv.len() >= 1 && iv.len() <= BLOCK_SIZE);
        assert!(mac_len_bits >= 32 && mac_len_bits <= 128 && mac_len_bits % 8 == 0);

        // Формируем Y1 = E_K(0 || IV) и Z1 = E_K(1 || IV)
        let mut y_iv = [0u8; BLOCK_SIZE];
        let mut z_iv = [0u8; BLOCK_SIZE];

        if iv.len() == BLOCK_SIZE {
            // c = n: используем IV без сдвига, в Z1 старший бит = 1
            y_iv.copy_from_slice(iv);
            z_iv.copy_from_slice(iv);
            z_iv[0] ^= 0x80;
        } else {
            // c < n: IV размещается в младших битах, слева дополняется нулевым битом
            y_iv[..iv.len()].copy_from_slice(iv);
            // сдвиг вправо на 1 бит
            let mut carry = 0u8;
            for byte in y_iv.iter_mut() {
                let new_carry = *byte & 1;
                *byte = (*byte >> 1) | (carry << 7);
                carry = new_carry;
            }

            z_iv[..iv.len()].copy_from_slice(iv);
            let mut carry = 0u8;
            for byte in z_iv.iter_mut() {
                let new_carry = *byte & 1;
                *byte = (*byte >> 1) | (carry << 7);
                carry = new_carry;
            }
            z_iv[0] |= 0x80;
        }

        let y1 = self.encrypt_raw(y_iv);
        let z1 = self.encrypt_raw(z_iv);

        // MAC: A-блоки
        let mut z = z1;
        let mut r = [0u8; BLOCK_SIZE];
        for chunk in aad.chunks(BLOCK_SIZE) {
            let mut a_block = [0u8; BLOCK_SIZE];
            a_block[..chunk.len()].copy_from_slice(chunk);
            let h = self.encrypt_raw(z);
            r = xor_blocks(&r, &gf_mul128_mgm(&h, &a_block));
            incr_l(&mut z);
        }

        // Шифрование + MAC C-блоков за один проход (E_K(Y) и E_K(Z) параллельно)
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut y = y1;
        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let (gamma, h) = self.encrypt_raw_pair(y, z);
            let mut c_block = [0u8; BLOCK_SIZE];
            let len = chunk.len();
            for i in 0..len {
                c_block[i] = chunk[i] ^ gamma[i];
            }
            ciphertext.extend_from_slice(&c_block[..len]);
            r = xor_blocks(&r, &gf_mul128_mgm(&h, &c_block));
            incr_r(&mut y);
            incr_l(&mut z);
        }

        // len(A) || len(C) в битах как 128-битное число (big-endian)
        let mut len_block = [0u8; BLOCK_SIZE];
        let a_bits = (aad.len() as u64) * 8;
        let c_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&a_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&c_bits.to_be_bytes());
        let h_len = self.encrypt_raw(z);
        let f = xor_blocks(&r, &gf_mul128_mgm(&h_len, &len_block));
        let full_mac = self.encrypt_raw(f);

        let mac_bytes = mac_len_bits / 8;
        (ciphertext, full_mac[..mac_bytes].to_vec())
    }

    /// Аутентифицированное расшифрование в режиме MGM.
    pub fn decrypt_mgm(&self, ciphertext: &[u8], aad: &[u8], iv: &[u8], mac: &[u8], mac_len_bits: usize) -> Result<Vec<u8>, &'static str> {
        assert!(iv.len() >= 1 && iv.len() <= BLOCK_SIZE);
        assert!(mac_len_bits >= 32 && mac_len_bits <= 128 && mac_len_bits % 8 == 0);

        // Формируем Y1 и Z1
        let mut y_iv = [0u8; BLOCK_SIZE];
        let mut z_iv = [0u8; BLOCK_SIZE];

        if iv.len() == BLOCK_SIZE {
            y_iv.copy_from_slice(iv);
            z_iv.copy_from_slice(iv);
            z_iv[0] ^= 0x80;
        } else {
            y_iv[..iv.len()].copy_from_slice(iv);
            let mut carry = 0u8;
            for byte in y_iv.iter_mut() {
                let new_carry = *byte & 1;
                *byte = (*byte >> 1) | (carry << 7);
                carry = new_carry;
            }

            z_iv[..iv.len()].copy_from_slice(iv);
            let mut carry = 0u8;
            for byte in z_iv.iter_mut() {
                let new_carry = *byte & 1;
                *byte = (*byte >> 1) | (carry << 7);
                carry = new_carry;
            }
            z_iv[0] |= 0x80;
        }

        let y1 = self.encrypt_raw(y_iv);
        let z1 = self.encrypt_raw(z_iv);

        // MAC: A-блоки
        let mut z = z1;
        let mut r = [0u8; BLOCK_SIZE];
        for chunk in aad.chunks(BLOCK_SIZE) {
            let mut a_block = [0u8; BLOCK_SIZE];
            a_block[..chunk.len()].copy_from_slice(chunk);
            let h = self.encrypt_raw(z);
            r = xor_blocks(&r, &gf_mul128_mgm(&h, &a_block));
            incr_l(&mut z);
        }

        // MAC C-блоков + расшифрование за один проход (E_K(Z) и E_K(Y) параллельно)
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut y = y1;
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let mut c_block = [0u8; BLOCK_SIZE];
            c_block[..chunk.len()].copy_from_slice(chunk);
            let (h, gamma) = self.encrypt_raw_pair(z, y);
            r = xor_blocks(&r, &gf_mul128_mgm(&h, &c_block));
            let len = chunk.len();
            let mut p_block = [0u8; BLOCK_SIZE];
            for i in 0..len {
                p_block[i] = chunk[i] ^ gamma[i];
            }
            plaintext.extend_from_slice(&p_block[..len]);
            incr_l(&mut z);
            incr_r(&mut y);
        }

        let mut len_block = [0u8; BLOCK_SIZE];
        let a_bits = (aad.len() as u64) * 8;
        let c_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&a_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&c_bits.to_be_bytes());
        let h_len = self.encrypt_raw(z);
        let f = xor_blocks(&r, &gf_mul128_mgm(&h_len, &len_block));
        let full_mac = self.encrypt_raw(f);

        let mac_bytes = mac_len_bits / 8;
        if &full_mac[..mac_bytes] != mac {
            return Err("MAC mismatch");
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_block() {
        let key = [
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let cipher = Kuznechik::new(key);
        let mut plaintext = Block::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88]);
        let ciphertext = cipher.encrypt_block(&mut plaintext);
        let expected = [0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd];
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_decrypt_block() {
        let key = [
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let cipher = Kuznechik::new(key);
        let mut ct_block = Block::new([0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd]);
        let plaintext = cipher.decrypt_block(&mut ct_block);
        let expected = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_mgm_roundtrip() {
        let key = [
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let cipher = Kuznechik::new(key);

        let plaintext = b"Hello, GOST! This is a test message for MGM mode.";
        let aad = b"important metadata";
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]; // 8 байт

        let (ct, mac) = cipher.encrypt_mgm(plaintext, aad, &iv, 128);
        assert_eq!(ct.len(), plaintext.len());
        assert_eq!(mac.len(), 16);

        let decrypted = cipher.decrypt_mgm(&ct, aad, &iv, &mac, 128);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_mgm_wrong_mac_fails() {
        let key = [
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let cipher = Kuznechik::new(key);

        let plaintext = b"Some data";
        let aad = b"some aad";
        let iv = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let (ct, mut mac) = cipher.encrypt_mgm(plaintext, aad, &iv, 128);
        mac[0] ^= 1;

        let result = cipher.decrypt_mgm(&ct, aad, &iv, &mac, 128);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "MAC mismatch");
    }

    #[test]
    fn test_mgm_official_vector() {
        let key = [
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let cipher = Kuznechik::new(key);

        let iv: [u8; 16] = hex::decode("1122334455667700ffeeddccbbaa9988").unwrap().try_into().unwrap();

        // Проверяем Y1 и Z1 (уже было)
        let mut y1_blk = Block::new(iv);
        let y1 = cipher.encrypt_block(&mut y1_blk);
        assert_eq!(y1.to_vec(), hex::decode("7f679d90bebc24305a468d42b9d4edcd").unwrap());

        let mut z1_iv = iv;
        z1_iv[0] |= 0x80;
        let mut z1_blk = Block::new(z1_iv);
        let z1 = cipher.encrypt_block(&mut z1_blk);
        assert_eq!(z1.to_vec(), hex::decode("7fc245a8586e6602a7bbdb2786bdc66f").unwrap());

        // Эталонные H_i (уже проверены ранее, здесь не дублируем)

        // Данные
        let aad = hex::decode(
            "02020202020202020101010101010101\
                            04040404040404040303030303030303\
                            ea0505050505050505",
        )
            .unwrap();
        let plaintext = hex::decode(
            "1122334455667700ffeeddccbbaa9988\
                                    00112233445566778899aabbcceeff0a\
                                    112233445566778899aabbcceeff0a00\
                                    2233445566778899aabbcceeff0a0011\
                                    aabbcc",
        )
            .unwrap();

        let expected_ct = hex::decode(
            "a9757b8147956e9055b8a33de89f42fc\
                                    8075d2212bf9fd5bd3f7069aadc16b39\
                                    497ab15915a6ba85936b5d0ea9f6851c\
                                    c60c14d4d3f883d0ab94420695c76deb\
                                    2c7552",
        )
            .unwrap();
        let expected_mac = hex::decode("cf5d656f40c34f5c46e8bb0e29fcdb4c").unwrap();

        let (ct, mac) = cipher.encrypt_mgm(&plaintext, &aad, &iv, 128);
        assert_eq!(ct, expected_ct, "Ciphertext mismatch");

        // === Ручное вычисление MAC ===
        // Формируем дополненные блоки A и C (процедура 1)
        let pad = |data: &[u8]| -> Vec<[u8; 16]> {
            data.chunks(16)
                .map(|chunk| {
                    let mut block = [0u8; 16];
                    block[..chunk.len()].copy_from_slice(chunk);
                    block
                })
                .collect()
        };
        let a_blocks = pad(&aad);
        let c_blocks = pad(&ct);

        // Z1 и текущий r
        let mut z = z1;
        let mut r = [0u8; 16];

        // Эталонные H_i из ГОСТ Р 34.13-2018, Приложение А.6ж
        let expected_h: Vec<[u8; 16]> = [
            "8db187d653830ea4bc446476952c300b",
            "7a24f72630e3763721c8f3cdb1da0e31",
            "4411962117d20635c525e0a24db4b90a",
            "d8c9623c4dbfe814ce7c1c0ceaa959db",
            "a5e1f195333e1482969931bfbe6dfd43",
            "b4ca808caccfb3f91724e48a2c7ee9d2",
            "72908fc074e469e8901bd188ea91c331",
            "23ca2715b02c68313bfdacb39e4d0fb8",
            "bcbce6c41aa355a4148862bf64bd830d",
        ]
            .iter()
            .map(|s| {
                let v = hex::decode(s).unwrap();
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&v);
                arr
            })
            .collect();

        // Обработка A блоков
        for (i, a_block) in a_blocks.iter().enumerate() {
            let h = cipher.encrypt_block(&mut Block::new(z));
            assert_eq!(h, expected_h[i], "H_{} mismatch", i + 1);
            r = xor_blocks(&r, &gf_mul128_mgm(&h, a_block));
            incr_l(&mut z);
        }
        // Обработка C блоков
        for (i, c_block) in c_blocks.iter().enumerate() {
            let h = cipher.encrypt_block(&mut Block::new(z));
            assert_eq!(h, expected_h[3 + i], "H_{} mismatch", 4 + i);
            r = xor_blocks(&r, &gf_mul128_mgm(&h, c_block));
            incr_l(&mut z);
        }

        // len(A) || len(C) в битах
        let a_bits = (aad.len() as u64) * 8;
        let c_bits = (ct.len() as u64) * 8;
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&a_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&c_bits.to_be_bytes());

        // RFC 9058: T = E_K(sum XOR (H_{h+q+1} * len_block))
        let h_len = cipher.encrypt_block(&mut Block::new(z));
        assert_eq!(h_len, expected_h[8], "H_9 mismatch");
        let f = xor_blocks(&r, &gf_mul128_mgm(&h_len, &len_block));
        let our_mac = cipher.encrypt_block(&mut Block::new(f));
        println!("F        : {:02x?}", f);
        println!("Our MAC  : {:02x?}", our_mac);
        println!("Expected : {:02x?}", expected_mac);
        println!("MAC from encrypt_mgm: {:02x?}", mac);

        assert_eq!(our_mac.to_vec(), expected_mac, "Manual MAC mismatch");
        assert_eq!(mac, expected_mac, "Encrypt MAC mismatch");
    }
}
