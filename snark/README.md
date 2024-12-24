# zkrypto_circuits

`zkrypto_circuits` is a Rust project that provides circuit libraries for Zkvoting and zkWallet circuits.

## Paper

- [zkWallet](https://eprint.iacr.org/2022/211.pdf)
- [Zkvoting](https://zkvoting.com/)

## Features

- default = ["ark-crypto-primitives/r1cs"]
- zkwallet = []
- zkdid = []
- zksbt = []
- zkvoting-binary = []
  zkvoting-binary-weight = []
- zkvoting-preference = []
- zkvoting-score = []
- zkvoting = ["zkvoting-binary", "zkvoting-preference", "zkvoting-score", "zkvoting-binary-weight", "zkvoting-pollstation"]
- cc-groth16 = []
- api = ["zkwallet", "zkdid", "zksbt", "zkvoting-pollstation"]

## Bin

- generate_crs

---

## Library on zkrypto_circuits

### Gadgets

The library provides the following gadgets:

#### Hashes

- `mimc7`

#### Merkle-tree

(No specific gadgets mentioned. You can add details about the Merkle-tree gadgets if applicable.)

#### Public encryptions

- `Elgamal encryption`

#### Symmetric encryption

- `Symmetric encryption using mimc7`

### Zkvoting circuits

#### voting

- Binary voting circuit
- Binary weight voting circuit
- preference voting circuit
- score voting circuit
- pollstation voting circuit

### zkWallet circuits

The library provides Zktransfer in the zkWallet circuit.

- Fungible Token transfer circuit
- Non-Fungible Token transfer citcuit

### ZkDID circuits

Example the presentation proof circuit of Zero-knowledge based Decentralized IDentifier (ZkDID)

### ZkSBT circuits

Example the presentation proof circuit of Zero-knowledge based Soulbound Token (ZkSBT)

### cc-groth16

  [see](./src/cc_groth16/README.md)

---

## Binary on zkrypto-circuits

### Generate CRS

This command is used to generate Common Reference Strings (CRS) for the selected feature's circuit.

The CRS files will be created in the `{file_path}/{features}/` directory and will have the extensions .pk, .vk, and .pvk.

#### Usage

```bash
cargo run \
  --features [zkvoting-binary || zkvoting-binary-weight || zkvoting-preference || zkvoting-score || zkvoting-pollstation || zkvoting || zkwallet || zkdid || zksbt ] \
  --bin generate_crs \
  <file_path> <tree_height>
```

#### Examples

```bash
cargo run \
  --all-features \
  --bin generate_crs \
  ./crs 32
```

Upon running the above example command, the CRS files will be generated in the following directory structure:

```bash
$ tree crs
crs
├── zkvoting
│   ├── binary
│   │   ├── crs_height_32.pk
│   │   ├── crs_height_32.pvk
│   │   └── crs_height_32.vk
│   ├── preference
│   │   ├── crs_height_32.pk
│   │   ├── crs_height_32.pvk
│   │   └── crs_height_32.vk
│   ├── score
│   │   ├── crs_height_32.pk
│   │   ├── crs_height_32.pvk
│   │   └── crs_height_32.vk
│   ├── pollstation
│   │   ├── crs_height_32.pk
│   │   ├── crs_height_32.pvk
│   │   └── crs_height_32.vk
│   └── weight
│       ├── crs_height_32.pk
│       ├── crs_height_32.pvk
│       └── crs_height_32.vk
├── zkdid
│   ├── crs_height_32.pk
│   ├── crs_height_32.pvk
│   └── crs_height_32.vk
├── zksbt
│   ├── crs_height_32.pk
│   ├── crs_height_32.pvk
│   └── crs_height_32.vk
└── zkwallet
    ├── crs_height_32.pk
    ├── crs_height_32.pvk
    └── crs_height_32.vk
```

Please note that the command should be run with the appropriate feature flag (`zkvoting-binary`, `zkvoting-preference`, `zkvoting-score`, `zkvoting-pollstation`, `zkvoting`, `zkdid`, `zksbt`, or `zkwallet`) based on the circuit you want to generate CRS for.
