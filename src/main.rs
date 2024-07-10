const BLOCK_SIZE: usize = 32; // Size of each block in bits
const HASH_SIZE: usize = 32; // Size of the hash code in bits

struct XorHasher {
    state: [u8; HASH_SIZE],
    block_count: usize,
}

impl XorHasher {
    fn new() -> Self {
        XorHasher {
            // Internal state of SHA-256
            state: [0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19],
            block_count: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        while offset < data.len() {
            let mut block = [0u8; BLOCK_SIZE];
            let remaining = data.len() - offset;
            let block_size = remaining.min(BLOCK_SIZE);

            block[..block_size].copy_from_slice(&data[offset..offset + block_size]);

            // encode the length of the block in the last byte
            if block_size < BLOCK_SIZE {
                block[BLOCK_SIZE - 1] = block_size as u8;
            }
            self.process_block(&block);

            offset += block_size;
            self.block_count += 1;
        }
    }

    fn finalize(self) -> [u8; HASH_SIZE] {
        self.state
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        for i in 0..HASH_SIZE {
            for _ in 0..80 {
                self.state[i] ^= block[i];
                self.state[i] = self.state[i].rotate_left(1);
            }
            self.state[i] = self.state[i].overflowing_add(block[i]).0;
        }
    }
}

fn xor_hash(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = XorHasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn xor_hash_attack(data: &[u8]) -> Vec<u8> {
    let mut padded_data = Vec::new();
    let r = BLOCK_SIZE - (data.len() % BLOCK_SIZE);

    if r != 0 {
        let padding = vec![0; r];
        padded_data.extend_from_slice(data);
        padded_data.extend(padding);
    }
    let mut mathcing_message = Vec::new();

    for _ in 0..=u8::MAX {
        mathcing_message.extend_from_slice(&padded_data);
    }
    mathcing_message
}

#[cfg(test)]
mod tests {

    use quickcheck::QuickCheck;

    use super::*;

    #[test]
    fn test_xor_attack() {
        fn prop(data: Vec<u8>) -> bool {
            xor_hash(&data) == xor_hash(&xor_hash_attack(&data))
        }
        QuickCheck::new().quickcheck(prop as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn attack_demo() {
        let data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        println!("{}", data.len());
        let attack = xor_hash_attack(&data);
        println!("{:?}", attack.len());
        println!("{:?}", xor_hash(&data));
        println!("{:?}", xor_hash(&attack));
    }
}

fn main() {
    let data = String::from("Hello, World!").into_bytes();
    let hash = xor_hash(&data);
    // print hash as hex string
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
}
