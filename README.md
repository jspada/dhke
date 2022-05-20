# DHKE - Diffie–Hellman key exchange

This is an example program that allows two parties to manually create a shared secret over
an insecure channel.  It assumes the elliptic curve discrete logarithm problem is a secure
cryptographic primative.

# Example usage

  1) Alice creates keypair
```console
      alice: $ dhke --mode keypair
      sec: 245b1368b1efd64fd134cef3591a3dfe75536b6747cc0a1645f973d228147e2f
      pub: 50b4c7926be1c75453c2fd01e212ebf17b5b3a344abab59914f0775ec601f80b34d08d057dbf18185744f316ee08a1ba32fc693f5d8ce6f3082a6c7bb02e4d36
```

  2) Bob creates keypair
```console
      bob: $ dhke --mode keypair
      sec: d1bca0e8acc65e8aa064532ef7fc862684ab174cdc968a17a1dc439552036e00
      pub: 67f6a72913d60b2afdd8b79c1ed438eb33b851e39a1168727e59c1e48411171df49a388e61c1545161c7aecc0a41febd73d610b6dc7a2f760245afa2e04ea036
```

  3) Alice and bob exchange pubkeys <->

  4) Alice generates shared secret using her secret key and Bob's public key
```console
      alice: $ dhke --mode shared-secret --sec 245b1368b1efd64fd134cef3591a3dfe75536b6747cc0a1645f973d228147e2f \
                    --pub 67f6a72913d60b2afdd8b79c1ed438eb33b851e39a1168727e59c1e48411171df49a388e61c1545161c7aecc0a41febd73d610b6dc7a2f760245afa2e04ea036
      shared secret: b3dfe7a1b642d02d6a25c236dfc9d8283ba52e756683a8c85efa86eba98c4b3f
```

  5) Bob generates shared secret using his secret key and Alice's public key
```console
      alice: $ dhke --mode shared-secret --sec d1bca0e8acc65e8aa064532ef7fc862684ab174cdc968a17a1dc439552036e00 \
                    --pub 50b4c7926be1c75453c2fd01e212ebf17b5b3a344abab59914f0775ec601f80b34d08d057dbf18185744f316ee08a1ba32fc693f5d8ce6f3082a6c7bb02e4d36
      shared secret: b3dfe7a1b642d02d6a25c236dfc9d8283ba52e756683a8c85efa86eba98c4b3f
```

  6) The shared secrets are equivalent 🎉

  7) Bob and Alice give thanks to mathematics for the associative property