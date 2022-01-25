# tcbpftest

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
sudo target/debug/tcbpftest

16:59:54 [DEBUG] (1) aya::bpf: [/home/vagrant/.cargo/git/checkouts/aya-c55fbc69175ac116/2a18239/aya/src/bpf.rs:102] [FEAT PROBE] BPF progra
m name support: true
[..]
16:59:55 [DEBUG] (1) aya::obj::relocation: [/home/vagrant/.cargo/git/checkouts/aya-c55fbc69175ac116/2a18239/aya/src/obj/relocation.rs:349]
finished relocating program tcbpftest function tcbpftest
LOG: LEN 76, SRC_IP 10.0.2.2, DEST_IP 10.0.2.15
LOG: LEN 40, SRC_IP 10.0.2.2, DEST_IP 10.0.2.15
LOG: LEN 40, SRC_IP 10.0.2.2, DEST_IP 10.0.2.15
^C
```
