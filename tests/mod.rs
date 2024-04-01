use eth_keystore::{decrypt_key, encrypt_key, encrypt_key_string, new};
use hex::FromHex;
use std::path::Path;

mod tests {

    use super::*;

    #[test]
    fn test_new() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let (secret, id) = new(&dir, &mut rng, "thebestrandompassword", None).unwrap();

        let keypath = dir.join(&id);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(decrypt_key(&keypath, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_new_with_name() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = "my_keystore";
        let (secret, _id) = new(&dir, &mut rng, "thebestrandompassword", Some(name)).unwrap();

        let keypath = dir.join(&name);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_pbkdf2() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key(&keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "wrongtestpassword").is_err());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(&keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(&keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = encrypt_key(&dir, &mut rng, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_encrypt_string_works() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();

        let expected = r#"{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "117be1de549d1d4322c4711f11efa0c5"
    },
    "ciphertext": "4ca41bc2454c796eb33251aac626de8dba874aa044587be2fe81d811b87a890f",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 8192,
      "p": 1,
      "r": 8,
      "salt": "7f6f2ccdb23f2abb7b69278e947c01c6160a31cf02c19d06d0f6e5ab1d768b95"
    },
    "mac": "6133bbc16f20d3866421bb8144d076d66b1f788139c91e047c7794baf26de2e0"
  },
  "id": "13790312-4f85-4c37-8761-ffc91ace30cb",
  "version": 3
}"#;

        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let (encrypted, _) = encrypt_key_string(&mut rng, &secret, "newpassword");

        print!("{encrypted}");

        assert_eq!(encrypted, expected)
    }
}
