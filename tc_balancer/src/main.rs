use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
use log::{debug, warn};
use tc_balancer_common::{Config, Port};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tc_balancer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program_ingress: &mut SchedClassifier = ebpf
        .program_mut("tc_balancer_ingress")
        .unwrap()
        .try_into()?;
    program_ingress.load()?;
    program_ingress.attach(&iface, TcAttachType::Ingress)?;

    let mut config_map = HashMap::try_from(ebpf.map_mut("CONFIG").expect("Get data"))?;
    config_map.insert(
        Port::new(8080),
        Config {
            redirect_port: Port::new(8081),
        },
        0,
    )?;
    // config_map.insert(
    //     Port::new(8081),
    //     Config {
    //         redirect_port: Port::new(8081),
    //     },
    //     0,
    // )?;

    let program_egress: &mut SchedClassifier =
        ebpf.program_mut("tc_balancer_egress").unwrap().try_into()?;
    program_egress.load()?;
    program_egress.attach(&iface, TcAttachType::Egress)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
