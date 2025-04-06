use std::{
    collections::HashSet,
    env, mem,
    num::NonZero,
    os::fd::{AsFd, FromRawFd, OwnedFd, RawFd},
    thread::sleep,
    time::Duration,
};

use chrono::Local;
use nix::{
    errno::Errno,
    fcntl::{open, renameat, Flock, OFlag},
    libc::{exit, sem_open, sem_post, sem_unlink, sem_wait},
    sys::{
        self,
        mman::{mmap, shm_open, shm_unlink, MapFlags, ProtFlags},
        stat::Mode,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{fork, ftruncate, read, unlink, write, ForkResult},
};

const FILENAME: &str = "http.log";
const CONFIG_NAME: &str = "/config_mem";
const CONFIG_SEM_NAME: &str = "/config_sem";

fn main() {
    println!("Hello!");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <run|count|rotate|update_config>", args[0]);
        return;
    }
    match args[1].as_str() {
        "run" => run(),
        "count" => count(),
        "rotate" => rotate(),
        "update_config" => update_config(args[2].parse::<u8>().expect("Failed to parse verbosity")),
        _ => {
            println!("Usage: {} <run|count|rotate|update_config>", args[0]);
            return;
        }
    }
    match shm_unlink(CONFIG_NAME) {
        Ok(_) => {}
        Err(e) => eprintln!("Failed to unlink shared memory: {}", e),
    }

    unsafe {
        match sem_unlink(std::ffi::CString::new(CONFIG_SEM_NAME).unwrap().as_ptr()) {
            x if x >= 0 => {}
            _ => eprintln!("Failed to unlink semaphore"),
        }
    }
}

struct Config {
    verbosity: u8,
}

fn init_config(mut config: &mut Config) {
    match shm_unlink(CONFIG_NAME) {
        Ok(_) => {}
        Err(e) => eprintln!("Failed to unlink shared memory: {}", e),
    }

    unsafe {
        match sem_unlink(std::ffi::CString::new(CONFIG_SEM_NAME).unwrap().as_ptr()) {
            x if x >= 0 => {}
            _ => eprintln!("Failed to unlink semaphore"),
        }
    }

    let fd = shm_open(
        CONFIG_NAME,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .expect("Failed to create shared memory");

    ftruncate(&fd, mem::size_of::<Config>().try_into().unwrap())
        .expect("Failed to truncate shared memory");

    unsafe {
        let map = mmap(
            None,
            NonZero::new(mem::size_of::<Config>()).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            &fd,
            0,
        )
        .expect("Failed memory map");

        let sem_name = std::ffi::CString::new(CONFIG_SEM_NAME).expect("Failed to create CString");
        let sem = sem_open(
            sem_name.as_ptr(),
            OFlag::O_CREAT.bits() | OFlag::O_EXCL.bits(),
            Mode::S_IRUSR | Mode::S_IWUSR,
            1,
        );
        if sem == nix::libc::SEM_FAILED {
            shm_unlink(CONFIG_NAME).expect("Failed to unlink shared memory");
            panic!("Failed to create semaphore");
        }

        let mut result = sem_wait(sem);
        if result < 0 {
            shm_unlink(CONFIG_NAME).expect("Failed to unlink shared memory");
            panic!("Failed to wait on semaphore");
        }

        config = &mut *(map.as_ptr() as *mut Config);
        config.verbosity = 1;

        result = sem_post(sem);
        if result < 0 {
            shm_unlink(CONFIG_NAME).expect("Failed to unlink shared memory");
            panic!("Failed to post semaphore");
        }
    }
}

fn update_config(new_verbosity: u8) {
    let fd = shm_open(CONFIG_NAME, OFlag::O_RDWR, Mode::S_IRUSR | Mode::S_IWUSR)
        .expect("Failed to create shared memory");

    unsafe {
        let map = mmap(
            None,
            NonZero::new(mem::size_of::<Config>()).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            &fd,
            0,
        )
        .expect("Failed memory map");

        let sem_name = std::ffi::CString::new(CONFIG_SEM_NAME).expect("Failed to create CString");
        let sem = sem_open(sem_name.as_ptr(), 0);
        if sem == nix::libc::SEM_FAILED {
            panic!("Failed to create semaphore");
        }

        let mut result = sem_wait(sem);
        if result < 0 {
            panic!("Failed to wait on semaphore");
        }
        let config: &mut Config = &mut *(map.as_ptr() as *mut Config);
        config.verbosity = new_verbosity;

        result = sem_post(sem);
        if result < 0 {
            panic!("Failed to post semaphore");
        }
    }
}

fn watch_config() {
    let fd = shm_open(CONFIG_NAME, OFlag::O_RDONLY | OFlag::O_EXCL, Mode::S_IRUSR)
        .expect("Failed to create shared memory");

    let config: &Config;
    unsafe {
        let map = mmap(
            None,
            NonZero::new(mem::size_of::<Config>()).unwrap(),
            ProtFlags::PROT_READ,
            MapFlags::MAP_SHARED,
            &fd,
            0,
        )
        .expect("Failed memory map");

        let sem_name = std::ffi::CString::new(CONFIG_SEM_NAME).expect("Failed to create CString");
        let sem = sem_open(sem_name.as_ptr(), 0);
        if sem == nix::libc::SEM_FAILED {
            panic!("Failed to create semaphore {}", Errno::last());
        }

        let mut result = sem_wait(sem);
        if result < 0 {
            panic!("Failed to wait on semaphore");
        }

        config = &*(map.as_ptr() as *mut Config);

        result = sem_post(sem);
        if result < 0 {
            panic!("Failed to post semaphore");
        }
        loop {
            println!("Config verbosity: {}", config.verbosity);
            sleep(Duration::from_secs(1));
        }
    }
}

fn run() {
    let config = &mut Config { verbosity: 0 };
    init_config(config);

    let mut children = Vec::new();
    for _ in 0..4 {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                children.push(child);
                continue;
            }
            Ok(ForkResult::Child) => {
                watch_config();
                unsafe {
                    exit(0);
                }
            }
            Err(_) => println!("Fork failed"),
        }
    }

    let mut output = HashSet::new();
    loop {
        'block: {
            for pid in &children {
                match waitpid(*pid, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED)) {
                    Ok(WaitStatus::Exited(child, status)) => {
                        output.insert((child, status));
                    }
                    Ok(WaitStatus::StillAlive) => break 'block,
                    Ok(WaitStatus::Signaled(child, ..)) | Ok(WaitStatus::Stopped(child, _)) => {
                        panic!("Pid exited unexpectedly: {}", child)
                    }
                    Err(e) => {
                        if e != Errno::ECHILD {
                            println!("Error waiting for pid {}: {}", *pid, e)
                        }
                    }
                    _ => panic!("Unexpected branch"),
                }
            }
            for (pid, status) in &output {
                println!("Process {} completed with status {}", pid, status)
            }
            children.clear();
            output.clear();
        }

        log(format!("{:#?}: Hello, world!", config.verbosity).as_str());
        sleep(Duration::from_secs(1));
    }
}

fn log(text: &str) {
    let fd = open(
        FILENAME,
        OFlag::O_APPEND | OFlag::O_CREAT | OFlag::O_WRONLY,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .expect("Failed to open file");

    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let lock =
        Flock::lock(owned_fd, nix::fcntl::FlockArg::LockExclusive).expect("Failed to obtain lock");

    let mut full_text = Local::now().to_rfc3339();
    full_text.push(' ');
    full_text.push_str(text);
    full_text.push('\n');
    write(lock.as_fd(), full_text.as_bytes()).expect("Failed to write to file");

    lock.unlock().expect("Failed to unlock");
}

fn rotate() {
    match sys::stat::stat("http.5.log") {
        Ok(_) => unlink("http.5.log").unwrap(),
        Err(_) => {}
    }
    for x in (1..5).rev() {
        let file = format!("http.{}.log", x);

        match sys::stat::stat(file.as_str()) {
            Ok(_) => renameat(
                None,
                file.as_str(),
                None,
                format!("http.{}.log", x + 1).as_str(),
            )
            .unwrap(),
            Err(_) => {}
        }
    }

    match sys::stat::stat(FILENAME) {
        Ok(_) => renameat(None, FILENAME, None, "http.1.log").unwrap(),
        Err(_) => {}
    }
}

fn count() {
    let fd: RawFd = open(FILENAME, OFlag::O_RDONLY, Mode::S_IRUSR | Mode::S_IWUSR)
        .expect("Failed to open file");

    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let lock =
        Flock::lock(owned_fd, nix::fcntl::FlockArg::LockExclusive).expect("Failed to obtain lock");

    let mut buf: [u8; 1] = [0; 1];
    let mut count = 0;

    let mut output = read(fd, &mut buf).expect("Failed to read file");
    while output > 0 {
        if buf[0] as char == '\n' {
            count += 1;
        }
        output = read(fd, &mut buf).expect("Failed to read file");
    }
    lock.unlock().expect("Failed to unlock");
    println!("Number of lines: {count}");
}
