use rand::CryptoRng;
use rand::{SeedableRng, Rng};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

const N_BYTES: usize = 32;

fn prep_commitment_recv<T: Rng + CryptoRng>(mut rng: T) -> [u8; N_BYTES * 3] {
    let mut arr = [0u8; N_BYTES * 3];
    rng.fill(&mut arr[..]);
    arr
}

fn commit_send<T: SeedableRng + CryptoRng, U: Rng + CryptoRng>(
    mut rng: U,
    msg: bool,
    r: [u8; 3],
) -> [u8; N_BYTES] {
    let arr: [u8; N_BYTES] = [rng.gen(); N_BYTES];
    T::from_seed(arr);
    arr
    
}

fn silent_shutdown(stream: TcpStream) {
    match stream.shutdown(Shutdown::Both) {
        Ok(_) => {}
        Err(e) => {
            println!("Failed socket shutdown: {}", e);
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut data = [0 as u8; 50]; // using 50 byte buffer
    loop {
        match stream.read(&mut data) {
            Ok(size) => {
                if &data[0..size] == "quit\n".as_bytes() {
                    silent_shutdown(stream);
                    break;
                }
                match stream.write(&data[0..size]) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Failed stream write: {}", e);
                        if e.kind() == ErrorKind::BrokenPipe {
                            break;
                        }
                        silent_shutdown(stream);
                        break;
                    }
                }
            }
            Err(e) => {
                println!("Error: {}", e);
                if e.kind() == ErrorKind::ConnectionReset {
                    break;
                }
                match stream.peer_addr() {
                    Ok(addr) => println!("Terminating connection with {}", addr),
                    Err(e) => println!("Failed to get peer address: {}", e),
                }
                silent_shutdown(stream);
                break;
            }
        }
    }
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move || {
                    // connection succeeded
                    handle_client(stream)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
}
