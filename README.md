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
$ make
```

### Usage

To create a hash chain, the arguments are:
```shell
$ ./hashchain create ALGORITHM LENGTH SEED
```

Simple example:
```shell
$ ./hashchain create sha256 10 "my secret password"
```

Alternatively, use built-in configurations:
```shell
$ make gen
```

It randomly generates a chain of length 10 using sha256 and saves it to the
file `chains`.

Each line of the output is base64 encoded data which hashes to the next line.

### Verify

Say that you have the last two hashes from the previous example:
```shell
$ tail -n 2 chains
FBxCC4r4/u9oyBtuF3sets/MpX38yGPHkyL5rtaGB58=
fdW9x8zM1ztLel4upwt2qW8x4EFw/WEfBOiXBiyEcuk=
```

You can verify with the command:
```shell
$ ./hashchain verify sha256 \
              FBxCC4r4/u9oyBtuF3sets/MpX38yGPHkyL5rtaGB58= \
              fdW9x8zM1ztLel4upwt2qW8x4EFw/WEfBOiXBiyEcuk=
success
```

The verify command writes "success" and returns 0 if the hashes verify, and
writes "failure" and returns non-0 if they don't.
