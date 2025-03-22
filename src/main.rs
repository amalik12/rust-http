use std::{
    collections::HashSet,
    env,
    os::fd::{AsFd, FromRawFd, OwnedFd, RawFd},
    thread::sleep,
    time::Duration,
};

use chrono::Local;
use nix::{
    errno::Errno,
    fcntl::{Flock, OFlag, open, renameat},
    libc::exit,
    sys::{
        self,
        stat::Mode,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, fork, read, unlink, write},
};
use rand::Rng;

const FILENAME: &str = "http.log";

fn main() {
    println!("Hello!");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <run|count|rotate>", args[0]);
        return;
    }
    match args[1].as_str() {
        "run" => run(),
        "count" => count(),
        "rotate" => rotate(),
        _ => {
            println!("Usage: {} <run|count|rotate>", args[0]);
            return;
        }
    }
}

fn run() {
    let mut children = Vec::new();

    for _ in 0..4 {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                children.push(child);
                continue;
            }
            Ok(ForkResult::Child) => {
                let num = rand::rng().random_range(2..=10);
                sleep(Duration::from_secs(num));
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

        log("Hello, world!");
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
