//! Seeds the fuzz corpora from the shared seed shapes. Run:
//! `cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds`

use std::fs;
use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let seeds = mosh_client_fuzz::seeds();
    for target in ["wire_decode", "fragment_assembly", "ssp_receive"] {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("corpus dir");
        for (i, seed) in seeds.iter().enumerate() {
            fs::write(dir.join(format!("seed-{i:02}")), seed).expect("seed write");
        }
        println!("{target}: {} seeds", seeds.len());
    }
}
