pub const PATHLEN: usize = 256;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct OpenPath {
    pub filename: [u8; PATHLEN],
}

impl Default for OpenPath {
    fn default() -> OpenPath {
        OpenPath {
            filename: [0; PATHLEN],
        }
    }
}
