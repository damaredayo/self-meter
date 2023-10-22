extern crate self_meter;
extern crate serde_json;

use std::collections::BTreeMap;
use std::io::{stderr, Write};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let mut meter = self_meter::Meter::new(Duration::new(1, 0)).unwrap();
    meter.track_current_thread("main");
    loop {
        meter
            .scan()
            .map_err(|e| writeln!(&mut stderr(), "Scan error: {}", e))
            .ok();
        println!(
            "Report: {}",
            serde_json::ser::to_string_pretty(&meter.report()).unwrap()
        );
        println!(
            "Threads: {}",
            serde_json::ser::to_string_pretty(
                &meter.thread_report().map(|x| x.collect::<BTreeMap<_, _>>())
            )
            .unwrap()
        );
        let mut x = 0;
        for _ in 0..10000000 {
            x = u64::wrapping_mul(x, 7);
        }
        sleep(Duration::new(1, 0));
    }
}
