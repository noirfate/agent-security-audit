use std::process::Command;

pub fn run(cmd: &str) -> std::io::Result<()> {
    Command::new(cmd).spawn()?;
    Ok(())
}
