use crate::driver::Driver;

pub fn launch(d: &Driver, cmd: &str) -> anyhow::Result<()> {
    driver.exec(cmd)?;
    Ok(())
}
