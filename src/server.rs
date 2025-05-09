use std::{
    mem,
    num::NonZero,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
    process::exit,
    str::FromStr,
    sync::Arc,
    thread::{self},
};

use chrono::Local;
use nix::{
    errno::Errno,
    fcntl::{open, renameat, Flock, OFlag},
    libc::{sem_open, sem_post, sem_unlink, sem_wait},
    sys::{
        self,
        mman::{mmap, shm_open, shm_unlink, MapFlags, ProtFlags},
        signal::{sigaction, sigprocmask, SigAction, SigSet, SIGINT, SIGTERM},
        socket::{
            accept, bind, listen, socket, AddressFamily, Backlog, SockFlag, SockType, SockaddrIn,
        },
        stat::Mode,
    },
    unistd::{ftruncate, read, unlink, write},
};
use strum_macros::EnumString;

const FILENAME: &str = "http.log";
const CONFIG_NAME: &str = "/config_mem";
const CONFIG_SEM_NAME: &str = "/config_sem";

struct Config {
    verbosity: u8,
}

pub struct Request {
    pub method: Method,
    pub path: String,
}

pub enum ResponseType {
    Text,
    Json,
    Html,
}

pub struct Response {
    pub status: u32,
    pub body: String,
    pub response_type: ResponseType,
}

impl Response {
    fn to_string(&self) -> String {
        let status_text = match self.status {
            400 => "Bad Request",
            404 => "Not Found",
            _ => "OK",
        };

        let content_type = match self.response_type {
            ResponseType::Text => "text/plain",
            ResponseType::Json => "application/json",
            ResponseType::Html => "text/html",
        };

        // Process the message and return a response
        let response = format!(
            "HTTP/1.1 {} {}\n\
            Content-Type: {}\n\
            \n\
            {}\n",
            self.status, status_text, content_type, self.body
        );
        println!("{}", response);
        response
    }
}

#[derive(Eq, Hash, PartialEq, EnumString, Clone, Debug)]
pub enum Method {
    GET,
    PUT,
    POST,
    DELETE,
}

pub trait Server: Send + Sync + 'static {
    fn init_config() {
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

            let sem_name =
                std::ffi::CString::new(CONFIG_SEM_NAME).expect("Failed to create CString");
            let sem = sem_open(
                sem_name.as_ptr(),
                OFlag::O_CREAT.bits() | OFlag::O_EXCL.bits(),
                Mode::S_IRUSR | Mode::S_IWUSR,
                1,
            );
            if sem == nix::libc::SEM_FAILED {
                panic!("Failed to create semaphore");
            }

            let mut result = sem_wait(sem);
            if result < 0 {
                panic!("Failed to wait on semaphore");
            }

            let config = &mut *(map.as_ptr() as *mut Config);
            config.verbosity = 1;

            result = sem_post(sem);
            if result < 0 {
                panic!("Failed to post semaphore");
            }
        }
    }

    fn read_config() -> *mut Config {
        let fd = shm_open(CONFIG_NAME, OFlag::O_RDONLY | OFlag::O_EXCL, Mode::S_IRUSR)
            .expect("Failed to create shared memory");

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

            let sem_name =
                std::ffi::CString::new(CONFIG_SEM_NAME).expect("Failed to create CString");
            let sem = sem_open(sem_name.as_ptr(), 0);
            if sem == nix::libc::SEM_FAILED {
                panic!("Failed to create semaphore {}", Errno::last());
            }

            let mut result = sem_wait(sem);
            if result < 0 {
                panic!("Failed to wait on semaphore");
            }

            let config = map.as_ptr() as *mut Config;

            result = sem_post(sem);
            if result < 0 {
                panic!("Failed to post semaphore");
            }
            return config;
        }
    }

    fn process_path(path: &String) -> Option<Request> {
        let mut request = Request {
            method: Method::GET,
            path: String::default(),
        };
        let request_parts: Vec<&str> = path.split_whitespace().collect();

        if request_parts.len() != 3
            || request_parts[2] != "HTTP/1.1"
            || !request_parts[1].starts_with("/")
        {
            return None;
        }

        request.path = request_parts[1].to_string();

        match Method::from_str(request_parts[0]) {
            Ok(method) => request.method = method,
            Err(_) => return None,
        }

        return Some(request);
    }

    fn parse_path(message: String) -> String {
        match message.lines().next() {
            Some(value) => {
                let path = value.trim().to_string();
                println!("{}", value.to_string());
                return path;
            }
            None => {}
        }
        return String::default();
    }

    fn process_request(&self, request: &Request) -> Response;

    fn handle_connection(&self, conn: OwnedFd) {
        let config = unsafe { &*Self::read_config() };

        loop {
            let mut buf: [u8; 1024] = [0; 1024];
            match read(conn.as_raw_fd(), &mut buf) {
                Ok(0) => {
                    println!("Connection closed");
                    break;
                }
                Ok(n) => {
                    let message = String::from_utf8_lossy(&buf[..n]).into_owned();
                    println!("Received: {}", message);

                    let path = Self::parse_path(message);
                    let response = match Self::process_path(&path) {
                        Some(request) => self.process_request(&request),
                        None => Response {
                            status: 400,
                            body: "Invalid request".to_string(),
                            response_type: ResponseType::Text,
                        },
                    };
                    Self::log(
                        &path.replace("HTTP/1.1", ""),
                        config.verbosity,
                        response.status,
                    );
                    if Self::count() > 500 {
                        Self::rotate();
                    }
                    write(&conn, response.to_string().as_bytes())
                        .expect("Failed to write to socket");
                    break;
                }
                Err(e) => {
                    eprintln!("Error reading from socket: {}", e);
                    break;
                }
            };
        }
    }

    fn log(text: &str, verbosity: u8, status: u32) {
        let fd = open(
            FILENAME,
            OFlag::O_APPEND | OFlag::O_CREAT | OFlag::O_WRONLY,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .expect("Failed to open file");

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let lock = Flock::lock(owned_fd, nix::fcntl::FlockArg::LockExclusive)
            .expect("Failed to obtain lock");

        let mut full_text = Local::now().to_rfc3339();
        full_text.push(' ');
        full_text.push_str(&verbosity.to_string());
        full_text.push(' ');
        full_text.push_str(text.trim());
        full_text.push(' ');
        full_text.push_str(&status.to_string());
        full_text.push('\n');
        write(lock.as_fd(), full_text.as_bytes()).expect("Failed to write to file");

        lock.unlock().expect("Failed to unlock");
    }

    extern "C" fn handle_term(_signo: i32) {
        let _ = shm_unlink(CONFIG_NAME);

        unsafe {
            sem_unlink(std::ffi::CString::new(CONFIG_SEM_NAME).unwrap().as_ptr());
        }
        exit(0);
    }

    extern "C" fn ignore_term(_signo: i32) {}

    fn run(this: Arc<Self>) {
        Self::init_config();

        // Set empty handler for initial termination signal
        unsafe {
            let empty_handler = SigAction::new(
                sys::signal::SigHandler::Handler(Self::ignore_term),
                sys::signal::SaFlags::empty(),
                sys::signal::SigSet::empty(),
            );
            sigaction(SIGTERM, &empty_handler).expect("Failed to set signal handler");
            sigaction(SIGINT, &empty_handler).expect("Failed to set signal handler");
        }

        let fd = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("Failed to create socket");
        match bind(fd.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, 8080)) {
            Err(_) => Self::handle_term(0),
            _ => {}
        }

        listen(&fd, Backlog::new(128).unwrap()).expect("Failed to listen on socket");

        loop {
            match accept(fd.as_raw_fd()) {
                Ok(conn_fd) => {
                    let conn = unsafe { OwnedFd::from_raw_fd(conn_fd.as_raw_fd()) };
                    let self_arc = Arc::clone(&this);
                    thread::spawn(move || {
                        self_arc.handle_connection(conn);
                    });
                }
                Err(e) => {
                    // First termination signal received
                    if e == Errno::EINTR {
                        println!("\nNo longer accepting new connections, press Ctrl+C to exit");
                        // Block signals until new handler is set up, wait for next termination signal
                        let mut set = sys::signal::SigSet::empty();
                        set.add(SIGINT);
                        set.add(SIGTERM);
                        let mut old_set: SigSet = SigSet::empty();
                        sigprocmask(
                            sys::signal::SigmaskHow::SIG_BLOCK,
                            Some(&set),
                            Some(&mut old_set),
                        )
                        .expect("Failed to block signals");

                        unsafe {
                            let handler = SigAction::new(
                                sys::signal::SigHandler::Handler(Self::handle_term),
                                sys::signal::SaFlags::empty(),
                                sys::signal::SigSet::empty(),
                            );

                            sigaction(SIGTERM, &handler).expect("Failed to set signal handler");
                            sigaction(SIGINT, &handler).expect("Failed to set signal handler");
                        }

                        old_set.suspend().expect("Failed to suspend signals");
                        sigprocmask(sys::signal::SigmaskHow::SIG_UNBLOCK, Some(&old_set), None)
                            .expect("Failed to unblock signals");
                    }
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
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

    fn count() -> i32 {
        let fd: RawFd = open(FILENAME, OFlag::O_RDONLY, Mode::S_IRUSR | Mode::S_IWUSR)
            .expect("Failed to open file");

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let lock = Flock::lock(owned_fd, nix::fcntl::FlockArg::LockExclusive)
            .expect("Failed to obtain lock");

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
        return count;
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

            let sem_name =
                std::ffi::CString::new(CONFIG_SEM_NAME).expect("Failed to create CString");
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
}
