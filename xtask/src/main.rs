mod cargo;
mod codegen;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Run(cargo::Options),
    Build(cargo::Options),
    Generate,
}

fn main() -> Result<()> {
    let Options { command } = Parser::parse();

    match command {
        Command::Run(opts) => cargo::run(opts),
        Command::Build(opts) => cargo::build(opts),
        Command::Generate => codegen::generate(),
    }
}
