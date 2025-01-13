use std::{ffi::OsString, process::Command};

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use xtask::AYA_BUILD_EBPF;

pub enum CargoCommand {
    Run(Options),
    Build(Options),
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Build and run the release target.
    #[clap(long)]
    release: bool,
    /// The command used to wrap your application.
    #[clap(short, long, default_value = "sudo -E")]
    runner: String,
    /// Arguments to pass to your application.
    #[clap(global = true, last = true)]
    run_args: Vec<OsString>,
}

/// Build the project.
pub fn build(opts: Options) -> Result<()> {
    _run(CargoCommand::Build(opts))
}

/// Run the project.
pub fn run(opts: Options) -> Result<()> {
    _run(CargoCommand::Run(opts))
}

/// Build and run the project.
fn _run(cmd: CargoCommand) -> Result<()> {
    let (opts, build_only) = match cmd {
        CargoCommand::Run(opts) => (opts, false),
        CargoCommand::Build(opts) => (opts, true),
    };

    let Options {
        release,
        runner,
        run_args,
    } = opts;

    let cargo_cmd = if build_only { "build" } else { "run" };

    let mut cmd = Command::new("cargo");
    cmd.env(AYA_BUILD_EBPF, "true");
    cmd.args([cargo_cmd, "--package", "tc_balancer", "--config"]);
    if release {
        cmd.arg(format!("target.\"cfg(all())\".runner=\"{}\"", runner));
        cmd.arg("--release");
    } else {
        cmd.arg(format!("target.\"cfg(all())\".runner=\"{}\"", runner));
    }
    if !run_args.is_empty() {
        cmd.arg("--").args(run_args);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if status.code() != Some(0) {
        bail!("{cmd:?} failed: {status:?}")
    }
    Ok(())
}
