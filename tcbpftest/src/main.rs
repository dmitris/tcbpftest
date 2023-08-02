use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::net::Ipv4Addr;
use tokio::{signal, task};

use tcbpftest_common::PacketLog;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcbpftest"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcbpftest"
    ))?;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&args.iface);
    // this is just for information and debugging - show the found programs.
    for (name, program) in bpf.programs() {
        println!(
            "[INFO] found program `{}` of type `{:?}`",
            name,
            program.prog_type()
        );
    }
    let p = match bpf.program_mut("classifier") {
        Some(v) => v,
        None => panic!("bpf.program_mut('classifier') returned 'None'")
    };
    let program: &mut SchedClassifier = p.try_into()?;
    program.load()?;
    // program.attach(&args.iface, TcAttachType::Egress)?;
    program.attach(&args.iface, TcAttachType::Ingress)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketLog>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                // the iterator loop below is suggested by clippy and is  equivalent to:
                // for i in 0..events.read {
                //    let buf = &mut buffers[i];
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    println!(
                        "LOG: LEN {}, CTX_LEN {}, UDP_LEN {}, SRC_IP {}, DEST_IP {}, ETH_PROTO 0x{:X}, IP_PROTO {}, SRC_PORT {}, DEST_PORT {}",
                        data.len,
                        data.ctx_len,
                        data.udp_len,
                        Ipv4Addr::from(data.src_addr),
                        Ipv4Addr::from(data.dest_addr),
			            data.eth_proto,
			            data.ip_proto,
                        data.sport,
                        data.dport,
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
