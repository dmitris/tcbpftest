# tcbpftest

## Prerequisites

1. Install `rustup` following the instructions on https://rustup.rs/.
2. Install a rust stable toolchain: `rustup install stable`
3. Install a rust nightly toolchain: `rustup toolchain install nightly --component rust-src`
4. Ensure C compiler and linker are installed.
5. Install bpf-linker: `cargo install bpf-linker`

On a RHEL or Fedora-like server or VM, you should be able to do:
```
# Install Rust - https://rust-lang.org
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Hit “Enter” to accept the default “> Proceed with installation” option.
source "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src
sudo dnf -y install gcc git
cargo install bpf-linker
```

# Build and Run
You can remove the `--release` flag to perform a debug build. In this case,
it should also not be used in the next `cargo build` command (the two should
be in sync).
```
git clone https://github.com/dmitris/tcbpftest
cd tcbpftest

# build eBPF object file

cargo xtask build-ebpf --release

# build the user-space program

cargo build --release
```

If you want to build a static binary with musl, install the musl target and pass the `--target` parameter to `cargo build`:
```
rustup target add x86_64-unknown-linux-musl
cargo xtask build-ebpf --release
cargo build --release --target=x86_64-unknown-linux-musl
```

To run the program:
```
# release build
sudo ./target/release/tcbpftest

# debug build
sudo ./target/debug/tcbpftest
```

You can also use `RUST_LOG=info cargo xtask run [--release]` to build and run the program with one command.

The `tcbpftest` executable loads into the kernel the eBPF object file and attaches it to the `tc` hook,
then runs the user-space program reading data from the maps and printing to stdout:
```
sudo target/release/tcbpftest

LOG: LEN 238, CTX_LEN 252, SRC_IP 192.168.178.1, DEST_IP 192.168.178.255, ETH_PROTO 0x800, ETH_PROTO2 0x8000000, IP_PROTO 17, REMOTE_PORT 138, REMOTE_PORT2 138, LOCAL_PORT 138, LOCAL_PORT2 138
LOG: LEN 77, CTX_LEN 91, SRC_IP 140.82.113.26, DEST_IP 192.168.178.36, ETH_PROTO 0x800, ETH_PROTO2 0x8000000, IP_PROTO 6, REMOTE_PORT 443, REMOTE_PORT2 443, LOCAL_PORT 35628, LOCAL_PORT2 35628
LOG: LEN 52, CTX_LEN 66, SRC_IP 140.82.113.26, DEST_IP 192.168.178.36, ETH_PROTO 0x800, ETH_PROTO2 0x8000000, IP_PROTO 6, REMOTE_PORT 443, REMOTE_PORT2 443, LOCAL_PORT 35628, LOCAL_PORT2 35628

```

# Cross-compilation
The example program can be cross-compiled on a Mac for Linux:
```
rustup target add x86_64-unknown-linux-musl
brew install FiloSottile/musl-cross/musl-cross
brew install llvm
# adjust the path for LLVM installation as needed - if installed with brew on Mac,
# see `brew --prefix llvm`.
$ LLVM_SYS_160_PREFIX=$(brew --prefix llvm) cargo install bpf-linker --no-default-features --features system-llvm
$ cargo xtask build-ebpf --release
# '-C link-arg=-s' flag is optional (to produce a smaller executable file)
RUSTFLAGS="-Clinker=x86_64-linux-musl-ld -C link-arg=-s" cargo build --release --target=x86_64-unknown-linux-musl

```
The cross-compiled program `target/x86_64-unknown-linux-musl/release/tcbpftest` can be copied to a Linux server (having a capable kernel) and run there:
```
$ ls -lh target/x86_64-unknown-linux-musl/release/tcbpftest
-rwxr-xr-x  1 dmitris  staff   1.6M Mar 15 19:03 target/x86_64-unknown-linux-musl/release/tcbpftest
```

# References
* [Aya book](https://aya-rs.github.io/book/)
* [Adding BPF target support to the Rust compiler](https://confused.ai/posts/rust-bpf-target) by [@alessandrod](https://github.com/alessandrod)
