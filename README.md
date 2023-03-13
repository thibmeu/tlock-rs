# tlock-rs: Practical Timelock Encryption/Decryption in Rust

This repo contains pure Rust implementation of [`drand/tlock`](https://github.com/drand/tlock) scheme. It provides time-based encryption and decryption capabilities by relying on a [drand](https://drand.love/) threshold network and identity-based encryption (IBE). The IBE scheme implemented here is [`Boneh-Franklin`](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf).

## Usage
The tlock system relies on [an unchained drand network](https://drand.love/docs/cryptography/#randomness). Working endpoints to retrieve these beacons are, for now:
- https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493
- https://drand.cloudflare.com/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493

This crate does not provide a drand client. You should consider using [drand_core](https://github.com/thibmeu/drand-rs).

### Encrypt and decrypt a file towards a specific round

```rust
// Initial parameters, retrieve from a drand beacon
// https://drand.cloudflare.com/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1000
  let round = 1000;
  let chain_hash =
      hex::decode("7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf").unwrap();
  let public_key_bytes = hex::decode("8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11").unwrap();

  let msg = b"Hello world! I'm encrypting a message using timelock encryption.".to_vec();

  // Encryption with armoring, making encrypted message ASCII printable
  let mut armored = tlock_age::armor::ArmoredWriter::wrap_output(vec![]).unwrap();
  tlock_age::encrypt(&mut armored, msg.as_slice(), &chain_hash, &public_key_bytes, round).unwrap();
  let encrypted = armored.finish().unwrap();

  // Decrypting the message. It requires the round signature, here retrieved from the beacon above.
  let mut decrypted = vec![];
  let signature = hex::decode("a4721e6c3eafcd823f138cd29c6c82e8c5149101d0bb4bafddbac1c2d1fe3738895e4e21dd4b8b41bf007046440220910bb1cdb91f50a84a0d7f33ff2e8577aa62ac64b35a291a728a9db5ac91e06d1312b48a376138d77b4d6ad27c24221afe").unwrap();

  tlock_age::decrypt(&mut decrypted, encrypted.as_slice(), &chain_hash, &signature).unwrap();
  let decrypted = std::str::from_utf8(&decrypted).unwrap();

  println!("{decrypted}");
```

## Known issues
- No cross-library compatibility at the moment
