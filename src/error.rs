use std::io;
use std::num::ParseIntError;

use crate::Pid;

quick_error! {
    #[derive(Debug)]
    /// Error reading or parsing /proc/uptime
    pub enum UptimeError {
        Io(err: io::Error) {
            display("{}", err)
            from()
        }
        ParseInt(e: ParseIntError) {
            display("error parsing int: {}", e)
            from()
        }
        BadFormat {
            display("bad format")
        }
    }
}

quick_error! {
    #[derive(Debug)]
    /// Error reading or parsing /proc/self/stat or /proc/self/task/<TID>/stat
    pub enum StatError {
        Io(err: io::Error) {
            display("{}", err)
            from()
        }
        ParseInt(e: ParseIntError) {
            display("error parsing int: {}", e)
            from()
        }
        BadFormat {
            display("bad format")
        }
    }
}

quick_error! {
    #[derive(Debug)]
    /// Error reading or parsing /proc/self/io
    pub enum IoStatError {
        Io(err: io::Error) {
            display("{}", err)
            from()
        }
        ParseInt(e: ParseIntError) {
            display("error parsing int: {}", e)
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    /// Error reading or parsing /proc/self/status
    pub enum StatusError {
        Io(err: io::Error) {
            display("{}", err)
            from()
        }
        ParseInt(e: ParseIntError) {
            display("error parsing int: {}", e)
            from()
        }
        BadUnit {
            display("bad unit in memory data")
        }
        BadFormat {
            display("bad format")
        }
    }
}

quick_error! {
    #[derive(Debug)]
    /// Error scanning process info in /proc
    pub enum Error {
        /// Error reading uptime value
        Uptime(err: UptimeError) {
            display("Error reading /proc/uptime: {}", err)
            from()
        }
        /// Error reading /proc/self/status
        Status(err: StatusError) {
            display("Error reading /proc/self/status: {}", err)
            from()
        }
        /// Error reading /proc/self/stat
        Stat(err: StatError) {
            display("Error reading /proc/self/stat: {}", err)
        }

        /// Error reading from Windows API
        WinApi(err: StatError) {
            display("Error reading /proc/self/stat: {}", err)
        }
        /// Error reading thread status
        ThreadStat(tid: Pid, err: StatError) {
            display("Error reading /proc/self/task/{}/stat: {}", tid, err)
        }
        /// Error reading IO stats
        IoStat(err: IoStatError) {
            display("Error reading /proc/self/io: {}", err)
            from()
        }
    }
}
