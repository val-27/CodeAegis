use clap::CommandFactory;
use std::env;
use std::fs;
use std::path::PathBuf;

#[path = "src/cli_args.rs"]
mod cli_args;

fn main() -> std::io::Result<()> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| std::io::ErrorKind::NotFound)?);
    let cmd = cli_args::Cli::command();

    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    // Write to standard Cargo OUT_DIR
    fs::write(out_dir.join("codeaegis.1"), &buffer)?;

    // Also write to a 'man' directory in the project root for easy distribution
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let man_dir = PathBuf::from(manifest_dir).join("man");
        fs::create_dir_all(&man_dir)?;
        fs::write(man_dir.join("codeaegis.1"), &buffer)?;
    }

    Ok(())
}
