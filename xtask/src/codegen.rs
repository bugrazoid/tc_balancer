use std::{fs::File, path::PathBuf, process::Command};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("tc_balancer-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr", "ipv6hdr", "tcphdr"];
    let mut aya_tool = Command::new("aya-tool");
    aya_tool.arg("generate");
    for name in names {
        aya_tool.arg(name);
    }
    let path: &'static str = env!("PATH");
    aya_tool.env("PATH", format!("{path}:/usr/sbin"));
    let out = File::create(dir.join("bindings.rs"))?;
    aya_tool.stdout(out);
    aya_tool.spawn()?;
    Ok(())
}
