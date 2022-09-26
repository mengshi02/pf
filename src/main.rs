// Copyright 2022 pf Project Authors. Licensed under Apache-2.0.

mod os;
mod pf;

use crate::pf::{Config, Runner};

fn main() {
    Runner::new(Config::new())
        .map(|mut r| {
            r.run();
            os::wait_for_signal(|| r.exit())
        })
        .map_err(|err| panic!("runner error {:?}", err));
}
