# Handwaving Cryptography

> This is not a rigurous cryptography explanation, coming from a non-cryptographer. Takes this with caution, and refer to [drand](https://eprint.iacr.org/2016/1067) and [tlock](https://eprint.iacr.org/2023/189) paper as a source.

## drand

In the [drand network](https://drand.love), each participants has its own secret key, and the group (the League of Entropy) uses a public key derived from these private key shares.

During the setup call, each participants choose a number at random. This gives us group secret key `s`, and it's associated public key `S = s*g1`.

drand leverages a bilinear group `G1xG2 -> Gt`. On this group, we know a function `e` , implying `e(aP, bQ) = ab*e(P,Q)`. We also know a secure [hash function](https://en.wikipedia.org/wiki/Hash_function) `H`.

At each round, the group performs a BLS signature `sigma` over a deterministic message `m` : `sigma = s*H(m)`.

To verify a signature, dee client computes `e(S, H(m)) = e(s*g1, H(m)) = e(g1, s*H(m)) = e(g1, sigma)` using bilinearity.

Randomness is `rand = sha256(sigma)`.

The message `m` depends on the network mode:
* With chained randomness, message is `(round || previous_signature)`
* With unchained randomness, message is `(round)`.

The advantage of unchained randomness is it allows the message which the group is going to sign ahead of time. The security assumption remains the same: nodes do not collude.

## Timelock encryption

drand beacons produce signatures at regular interval (fastnet uses 3s for instance), which is the minimum interval we can lock data for. We assimilates this to a clock. We know that signature for round `p` is going to be for message `m = (p)`. We also know the public key `S`.

We want to encrypt text `M` towards round `p`.

To encrypt, we perform the following operations

```text
INPUT
(M, p, S)
COMPUTE
PK = e(S, H(p))
nonce = 32 random bytes
r = H(nonce, M)
// ciphertext
U = r*g1
V = nonce xor H(r*PK)
W = M xor H(nonce)
OUTPUT
(U, V, W)
```

Once we know the signature `sigma = s*H(p)` for decryption round `p`, we can decrypt `M`

```text
INPUT
(U, V, W, sigma, p)
COMPUTE
nonce' = V xor H(e(U, sigma))
       = nonce xor H(r*e(S, H(p))) xor H(e(U, s*H(p)))
       = nonce xor H(rs*e(g1, H(p))) xor H(rs*e(g1, H(p)))
       = nonce
M' = W xor H(nonce')
   = M xor H(nonce) xor H(nonce')
   = M
OUTPUT
(M')
```
