fn after_module(value: &str) -> &str {
    value
}

#[cfg(test)]
mod checks {
    fn unrelated_assertion() {}
}

fn production_after_module() {
    after_module("production code can follow a test module");
}
