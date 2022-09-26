// Copyright 2022 pf Project Authors. Licensed under Apache-2.0.

pub use self::proc::{wait_for_signal};
pub use self::thread::{thread_affinity};

#[cfg(unix)]
mod proc {
    use libc::c_int;
    use nix::sys::signal::{SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2};
    use signal::trap::Trap;

    #[allow(dead_code)]
    pub fn wait_for_signal<F>(func: F)
    where
        F: FnOnce(),
    {
        let trap = Trap::trap(&[SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2]);
        for sig in trap {
            match sig {
                SIGTERM | SIGINT | SIGHUP => {
                    println!("receive signal {}, stopping server...", sig as c_int);
                    drop(func);
                    break;
                }
                SIGUSR1 => {
                    // Use SIGUSR1 to log metrics.
                    println!("receive signal {}, stopping server...", sig as c_int);
                    drop(func);
                    break;
                }
                // TODO: handle more signal
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(not(unix))]
mod proc {
    pub fn wait_for_signal<F>(func: F)
    where
        F: FnOnce(),
    {
    }
}

#[cfg(any(linux, windows))]
mod thread {
    use affinity::*;
    pub fn thread_affinity(core_id: &[usize]) {
        let _ = set_thread_affinity(core_id);
    }
}

#[cfg(unix)]
mod thread {
    pub fn thread_affinity(core_id: &[usize]) {}
}
