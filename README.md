# tcbpftest

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

On a RHEL or Fedora-like server or VM, you should be able to do:
```
# Install Rust - https://rust-lang.org
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Hit “Enter” to accept the default “> Proceed with installation” option.
source "$HOME/.cargo/env
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
sudo dnf -y install gcc git
```

# Build and Run
```
git clone https://github.com/dmitris/tcbpftest
cd tcbpftest
# build eBPF object file
cargo xtask build-ebpf
# build the user-space program
cargo build
# loadsinto the kernel and attaches to the tc hook the eBPF object file
# and runs the user-space program reading data from the maps and printing to stdout
sudo target/debug/tcbpftest
18:28:31 [DEBUG] (1) aya::bpf: [/home/dsavints/.cargo/git/checkouts/aya-c55fbc69175ac116/2a18239/aya/src/bpf.rs:102] [FEAT PROBE] BPF program name support: true
[...]
18:28:31 [DEBUG] (1) aya::obj::relocation: [/home/dsavints/.cargo/git/checkouts/aya-c55fbc69175ac116/2a18239/aya/src/obj/relocation.rs:349] finished relocating program tcbpftest function tcbpftest
LOG: LEN 40, SRC_IP 10.0.2.2, DEST_IP 10.0.2.15, PROTO 6, REMOTE_PORT 51342, LOCAL_PORT 22
LOG: LEN 40, SRC_IP 10.0.2.2, DEST_IP 10.0.2.15, PROTO 6, REMOTE_PORT 51342, LOCAL_PORT 22
LOG: LEN 250, SRC_IP 10.93.11.112, DEST_IP 10.229.106.123, PROTO 6, REMOTE_PORT 40292, LOCAL_PORT 4080
LOG: LEN 5760, SRC_IP 10.93.11.112, DEST_IP 10.229.106.123, PROTO 6, REMOTE_PORT 40292, LOCAL_PORT 4080
```
