# Hash Chain

## Concepts

The idea of a hash chain is simple: you start with a base (could be a
password, or just a number, or some other data) and hash it. You then take the
result and hash that too. You continue hashing the results repeatedly, till
you have a series of hashes like this:

    Base -> Hash0 = H(Base) -> Hash1 = H(Hash0) -> ... -> HashN = H(HashN-1)

The exciting property of these hash chains is that given the last hash in the
chain, HashN, it is very difficult to determine any of the previous hashes, or
the base. However, given the last hash, it is trivial to verify whether another
hash is part of the chain.

This means that a hash chain has the potential to be a limited source of
authentication. You can deploy a resource in public along with the last hash
of the chain. Then you can give commands to this resource, passing along each
previous hash as authentication of your identity.

## Build instructions
```shell
$ cargo build --release
```

### Usage

To create a hash chain, the arguments are:
```shell
$ target/release/hashchain create --algorithm ALGO \
                                  --index BASE_INDEX \
                                  --length LENGTH \
                                  --seed SEED
```

Simple example:
```shell
$ target/release/hashchain create --algorithm blake3 \
                                  --index 0 \
                                  --length 2 \
                                  --seed "my secret password"
```

### Verify

Say that you have the last two hashes from the previous example:
```shell
s8H9Ux1DgaDBGluPBM7gtzvU5VUrTNKxYL5byEoJC/4=
sinEkbvTB5wK0Deo9rVpEBgZChbqrO91UXT8eRNVDkQ=
```

To verify if two hashes are in the same chain, the arguments are:
```shell
$ target/release/hashchain verify --algorithm ALGO \
                                  --query QUERY \
                                  --anchor ANCHOR \
                                  --range MAX_RANGE 
```

You can verify with the command:
```shell
$ target/release/hashchain verify --algorithm blake3 \
                                  --query s8H9Ux1DgaDBGluPBM7gtzvU5VUrTNKxYL5byEoJC/4= \
                                  --anchor sinEkbvTB5wK0Deo9rVpEBgZChbqrO91UXT8eRNVDkQ= \
                                  --range 10
```

The verify command writes "success" and returns 0 if the hashes verify, and
writes "failure" and returns non-0 if they don't.

### Use case: Document Attestation
You can use these scripts to manipulate the PDF files. [exiftool](https://www.sno.phy.queensu.ca/~phil/exiftool/), [openssl](https://www.openssl.org/) and [b3sum](https://github.com/BLAKE3-team/BLAKE3/tree/master/b3sum) should be installed first in order to use these scripts

You can sign a pdf file with the command:
```shell
$ scripts/sign.sh PDF_FILE [SEED] [ALGO]
```
Note that `SEED` is necessary when initializing the first hash, and the default `ALGO`  is blake3 if not specified manually.

To verify if the given inputs are in the same chain, you can use the command:
```shell
$ scripts/verify.sh INPUT_PDF ANCHOR [ALGO] [RANGE]
```
Note that `ALGO` is blake3 and `RANGE` is 10 by default. 
`INPUT_PDF` and `ANCHOR` can be either base64 encoded hash or pdf file.
