use std::path::PathBuf;


/// defines a parsed confine policy file
#[derive(Debug, Clone)]
pub struct Policy {
    file: PathBuf,
    allowed: Option<Vec<Syscall>>,
    denied: Vec<Syscall>,
}
