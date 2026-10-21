// Static fixture: a sandbox launcher. Read as material, never compiled or run.
pub fn launch(cmd: &str, approved: bool) -> std::io::Result<()> {
    if !approved {
        return Ok(());
    }
    let mut child = Command::new("/bin/sh").arg("-c").arg(cmd).spawn()?;
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    seccomp_apply_profile();
    landlock_restrict_self();
    child.wait().map(|_| ())
}

pub fn write_state(path: &str, body: &[u8]) -> std::io::Result<()> {
    fs::write(path, body)
}
