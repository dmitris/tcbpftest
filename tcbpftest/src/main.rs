use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::net::Ipv4Addr;
use tokio::{signal, task};

use tcbpftest_common::PacketLog;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

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
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tcbpftest").unwrap().try_into()?;
    program.load()?;
    // program.attach(&opt.iface, TcAttachType::Egress)?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
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
                        "LOG: LEN {}, CTX_LEN {}, UDP_LEN {}, SRC_IP {}, DEST_IP {}, ETH_PROTO 0x{:X}, ETH_PROTO2 0x{:X}, IP_PROTO {}, REMOTE_PORT {}, REMOTE_PORT2 {}, LOCAL_PORT {}, LOCAL_PORT2 {}",
                        data.len,
                        data.ctx_len,
                        data.udp_len,
                        Ipv4Addr::from(data.src_addr),
                        Ipv4Addr::from(data.dest_addr),
			data.eth_proto,
			data.eth_proto2,
			data.ip_proto,
                        data.remote_port,
                        data.remote_port2,
                        data.local_port,
                        data.local_port2,
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
