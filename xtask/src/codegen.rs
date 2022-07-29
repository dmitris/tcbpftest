use aya_gen::generate::InputFile;
use std::{
    fs::File,
    io::Write,
    path::PathBuf,
};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("tcbpftest-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr"];
    let bindings = aya_gen::generate(InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")), &names, &[])?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
