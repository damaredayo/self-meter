use std::collections::HashMap;
use std::time::{Instant, SystemTime};

use crate::error::StatusError;
use crate::{Error, Meter, Pid, Snapshot, ThreadInfo};

#[cfg(target_os = "linux")]
use std::{
    fmt::Write,
    fs::File,
    io::{Read, Seek, SeekFrom},
    num::ParseIntError,
};

#[cfg(target_os = "linux")]
use crate::error::{IoStatError, StatError, UptimeError};

impl Meter {
    /// Scan system for metrics
    ///
    /// This method must be called regularly at intervals specified
    /// in constructor.
    pub fn scan(&mut self) -> Result<(), Error> {
        // We reuse Snapshot structure (mostly becasuse of threads hash map)
        // to have smaller allocations on the fast path
        let mut snap = if self.snapshots.len() >= self.num_snapshots {
            self.snapshots.pop_front().unwrap()
        } else {
            Snapshot::new(&self.thread_names)
        };
        snap.timestamp = SystemTime::now();
        snap.instant = Instant::now();

        // First scan everything that relates to cpu_time to have as accurate
        // CPU usage measurements as possible
        self.read_cpu_times(
            &mut snap.process,
            &mut snap.threads,
            &mut snap.uptime,
            &mut snap.idle_time,
        )?;

        self.read_memory(&mut snap)?;
        self.read_io(&mut snap)?;

        if snap.memory_rss > self.memory_rss_peak {
            self.memory_rss_peak = snap.memory_rss;
        }
        if snap.memory_swap > self.memory_swap_peak {
            self.memory_swap_peak = snap.memory_swap;
        }

        self.snapshots.push_back(snap);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn read_cpu_times(
        &mut self,
        process: &mut ThreadInfo,
        threads: &mut HashMap<Pid, ThreadInfo>,
        uptime: &mut u64,
        idle_time: &mut u64,
    ) -> Result<(), Error> {
        self.text_buf.truncate(0);
        File::open("/proc/uptime")
            .and_then(|mut f| f.read_to_string(&mut self.text_buf))
            .map_err(|e| Error::Uptime(e.into()))?;
        {
            let mut iter = self.text_buf.split_whitespace();
            let seconds = iter.next().ok_or(Error::Uptime(UptimeError::BadFormat))?;
            let idle_sec = iter.next().ok_or(Error::Uptime(UptimeError::BadFormat))?;
            *uptime = parse_uptime(seconds)?;
            *idle_time = parse_uptime(idle_sec)?;
        }
        read_stat(&mut self.text_buf, "/proc/self/stat", process).map_err(Error::Stat)?;
        for (&tid, _) in &self.thread_names {
            self.path_buf.truncate(0);
            write!(&mut self.path_buf, "/proc/self/task/{}/stat", tid).unwrap();
            read_stat(
                &mut self.text_buf,
                &self.path_buf[..],
                threads.entry(tid).or_insert_with(ThreadInfo::new),
            )
            .map_err(|e| Error::ThreadStat(tid, e))?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn read_cpu_times(
        &mut self,
        process: &mut ThreadInfo,
        threads: &mut HashMap<Pid, ThreadInfo>,
        uptime: &mut u64,
        idle_time: &mut u64,
    ) -> Result<(), Error> {
        use winapi::{
            shared::minwindef::DWORD,
            um::{processthreadsapi as ptapi, sysinfoapi::GetTickCount64, winnt::ULONGLONG},
        };

        use crate::error::StatError;

        macro_rules! filetime_to_unix {
            ($input:expr) => {{
                let val = unsafe { std::mem::transmute::<_, ULONGLONG>($input) };
                val as u64 / 10_000_000
            }};
        }

        let process_handle = unsafe { ptapi::GetCurrentProcess() };

        // process

        let mut nil: winapi::shared::minwindef::FILETIME = unsafe { std::mem::zeroed() };
        let mut kernel_time_t: winapi::shared::minwindef::FILETIME = unsafe { std::mem::zeroed() };
        let mut user_time_t: winapi::shared::minwindef::FILETIME = unsafe { std::mem::zeroed() };

        if unsafe {
            ptapi::GetProcessTimes(
                process_handle,
                &mut nil,
                &mut nil,
                &mut kernel_time_t,
                &mut user_time_t,
            )
        } == 0
        {
            return Err(Error::Stat(StatError::BadFormat));
        }

        process.user_time = filetime_to_unix!(user_time_t);

        process.system_time = filetime_to_unix!(kernel_time_t);

        // threads

        let mut thread_info_map: HashMap<Pid, ThreadInfo> = HashMap::new();

        let mut processes: [DWORD; 1024] = [0; 1024];
        let mut bytes_needed: DWORD = 0;

        if unsafe {
            winapi::um::psapi::EnumProcesses(
                processes.as_mut_ptr(),
                std::mem::size_of_val(&processes) as u32,
                &mut bytes_needed,
            )
        } == 0
        {
            return Err(Error::Stat(StatError::BadFormat));
        }

        let num_processes = bytes_needed / std::mem::size_of::<DWORD>() as DWORD;

        for i in 0..num_processes {
            let process_id = processes[i as usize];

            let process_handle = unsafe {
                winapi::um::processthreadsapi::OpenProcess(
                    winapi::um::winnt::PROCESS_QUERY_INFORMATION
                        | winapi::um::winnt::PROCESS_VM_READ,
                    0,
                    process_id,
                )
            };

            if process_handle == std::ptr::null_mut() {
                continue;
            }

            let mut kernel_time_t: winapi::shared::minwindef::FILETIME =
                unsafe { std::mem::zeroed() };
            let mut user_time_t: winapi::shared::minwindef::FILETIME =
                unsafe { std::mem::zeroed() };

            if unsafe {
                ptapi::GetProcessTimes(
                    process_handle,
                    &mut nil,
                    &mut nil,
                    &mut kernel_time_t,
                    &mut user_time_t,
                )
            } == 0
            {
                continue;
            }

            let mut thread_info = ThreadInfo::new();

            thread_info.user_time = filetime_to_unix!(kernel_time_t);
            thread_info.system_time = filetime_to_unix!(user_time_t);

            thread_info_map.insert(process_id, thread_info);
        }

        *threads = thread_info_map;

        // uptime

        *uptime = unsafe { GetTickCount64() / 10 };

        // idle cpu time

        let mut idle_time_t: winapi::shared::minwindef::FILETIME = unsafe { std::mem::zeroed() };

        unsafe {
            winapi::um::processthreadsapi::GetSystemTimes(
                &mut idle_time_t,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }

        *idle_time = filetime_to_unix!(idle_time_t) / 1000;

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn read_cpu_times(
        &mut self,
        process: &mut ThreadInfo,
        threads: &mut HashMap<Pid, ThreadInfo>,
        uptime: &mut u64,
        idle_time: &mut u64,
    ) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn read_memory(&mut self, snap: &mut Snapshot) -> Result<(), StatusError> {
        self.text_buf.truncate(0);
        File::open("/proc/self/status").and_then(|mut f| f.read_to_string(&mut self.text_buf))?;
        for line in self.text_buf.lines() {
            let mut pairs = line.split(':');
            match (pairs.next(), pairs.next()) {
                (Some("VmPeak"), Some(text)) => snap.memory_virtual_peak = parse_memory(text)?,
                (Some("VmSize"), Some(text)) => snap.memory_virtual = parse_memory(text)?,
                (Some("VmRSS"), Some(text)) => snap.memory_rss = parse_memory(text)?,
                (Some("VmSwap"), Some(text)) => snap.memory_swap = parse_memory(text)?,
                _ => {}
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn read_memory(&mut self, snap: &mut Snapshot) -> Result<(), StatusError> {
        use winapi::um::processthreadsapi as ptapi;
        use winapi::um::psapi;

        let process_handle = unsafe { ptapi::GetCurrentProcess() };

        let mut counters: psapi::PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        if unsafe {
            psapi::GetProcessMemoryInfo(
                process_handle,
                &mut counters,
                std::mem::size_of_val(&counters) as u32,
            )
        } == 0
        {
            return Err(StatusError::BadFormat);
        }

        snap.memory_virtual = counters.PagefileUsage as u64;
        snap.memory_virtual_peak = counters.PeakPagefileUsage as u64;
        snap.memory_rss = counters.WorkingSetSize as u64;
        snap.memory_swap = counters.QuotaNonPagedPoolUsage as u64;

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn read_memory(&mut self, snap: &mut Snapshot) -> Result<(), StatusError> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn read_io(&mut self, snap: &mut Snapshot) -> Result<(), Error> {
        let err = &|e: ParseIntError| Error::IoStat(e.into());
        self.text_buf.truncate(0);
        self.io_file
            .seek(SeekFrom::Start(0))
            .map_err(IoStatError::Io)?;
        self.io_file
            .read_to_string(&mut self.text_buf)
            .map_err(IoStatError::Io)?;
        for line in self.text_buf.lines() {
            let mut pairs = line.split(':');
            match (pairs.next(), pairs.next().map(|x| x.trim())) {
                (Some("rchar"), Some(text)) => snap.read_bytes = text.parse().map_err(err)?,
                (Some("wchar"), Some(text)) => snap.write_bytes = text.parse().map_err(err)?,
                (Some("syscr"), Some(text)) => snap.read_ops = text.parse().map_err(err)?,
                (Some("syscw"), Some(text)) => snap.write_ops = text.parse().map_err(err)?,
                (Some("read_bytes"), Some(text)) => {
                    snap.read_disk_bytes = text.parse().map_err(err)?
                }
                (Some("write_bytes"), Some(text)) => {
                    snap.write_disk_bytes = text.parse().map_err(err)?
                }
                (Some("cancelled_write_bytes"), Some(text)) => {
                    snap.write_cancelled_bytes = text.parse().map_err(err)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    fn read_io(&mut self, snap: &mut Snapshot) -> Result<(), Error> {
        // No IO tracking yet
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn parse_memory(value: &str) -> Result<u64, StatusError> {
    let mut pair = value.split_whitespace();
    let value = pair.next().ok_or(StatusError::BadFormat)?.parse::<u64>()?;
    match pair.next() {
        Some("kB") => Ok(value * 1024),
        _ => Err(StatusError::BadUnit),
    }
}

#[cfg(target_os = "linux")]
pub fn parse_uptime(value: &str) -> Result<u64, UptimeError> {
    if value.len() <= 3 {
        return Err(UptimeError::BadFormat);
    }
    let dot = value.find('.').ok_or(UptimeError::BadFormat)?;
    let (integer, decimals) = value.split_at(dot);
    if decimals.len() == 1 + 1 {
        Ok(integer.parse::<u64>()? * 100 + decimals[1..].parse::<u64>()? * 10)
    } else if decimals.len() == 1 + 2 {
        Ok(integer.parse::<u64>()? * 100 + decimals[1..].parse::<u64>()?)
    } else {
        Err(UptimeError::BadFormat)
    }
}

#[cfg(target_os = "linux")]
fn read_stat(
    text_buf: &mut String,
    path: &str,
    thread_info: &mut ThreadInfo,
) -> Result<(), StatError> {
    text_buf.truncate(0);
    File::open(path).and_then(|mut f| f.read_to_string(text_buf))?;
    let right_paren = text_buf.rfind(')').ok_or(StatError::BadFormat)?;
    let mut iter = text_buf[right_paren + 1..].split_whitespace();
    thread_info.user_time = iter
        .nth(11)
        .ok_or(StatError::BadFormat)?
        .parse()
        .map_err(|_| StatError::BadFormat)?;
    thread_info.system_time = iter
        .next()
        .ok_or(StatError::BadFormat)?
        .parse()
        .map_err(|_| StatError::BadFormat)?;
    thread_info.child_user_time = iter
        .next()
        .ok_or(StatError::BadFormat)?
        .parse()
        .map_err(|_| StatError::BadFormat)?;
    thread_info.child_system_time = iter
        .next()
        .ok_or(StatError::BadFormat)?
        .parse()
        .map_err(|_| StatError::BadFormat)?;
    Ok(())
}

impl ThreadInfo {
    fn new() -> ThreadInfo {
        ThreadInfo {
            user_time: 0,
            system_time: 0,
            child_user_time: 0,
            child_system_time: 0,
        }
    }
}

impl Snapshot {
    fn new(threads: &HashMap<Pid, String>) -> Snapshot {
        Snapshot {
            timestamp: SystemTime::now(),
            instant: Instant::now(),
            uptime: 0,
            idle_time: 0,
            process: ThreadInfo::new(),
            memory_rss: 0,
            memory_virtual: 0,
            memory_virtual_peak: 0,
            memory_swap: 0,
            read_bytes: 0,
            write_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            read_disk_bytes: 0,
            write_disk_bytes: 0,
            write_cancelled_bytes: 0,
            threads: threads
                .iter()
                .map(|(&pid, _)| (pid, ThreadInfo::new()))
                .collect(),
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod test {
    use super::parse_uptime;

    #[test]
    fn normal_uptime() {
        assert_eq!(parse_uptime("1927830.69").unwrap(), 192783069);
    }
    #[test]
    fn one_zero_uptime() {
        assert_eq!(parse_uptime("4780.0").unwrap(), 478000);
    }
}
