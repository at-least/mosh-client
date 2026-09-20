//! Seeds the fuzz corpora from the shared seed shapes. Run:
//! `cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds`

use std::fs;
use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let jobs: [(&str, Vec<Vec<u8>>); 3] = [
        ("wire_decode", mosh_client_fuzz::wire_seeds()),
        ("fragment_assembly", mosh_client_fuzz::sequence_seeds()),
        ("ssp_receive", mosh_client_fuzz::sequence_seeds()),
    ];
    for (target, seeds) in jobs {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("corpus dir");
        for (i, seed) in seeds.iter().enumerate() {
            fs::write(dir.join(format!("seed-{i:02}")), seed).expect("seed write");
        }
        println!("{target}: {} seeds", seeds.len());
    }
}
