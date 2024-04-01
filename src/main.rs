use std::{
    sync::{atomic::AtomicBool, mpsc},
    thread,
    time::Duration,
};

use nix::{libc::SIGINT, sys::signal};

use crate::packet::BlePacket;

mod packet;

static STOP_REQUEST: AtomicBool = AtomicBool::new(false);

fn main() {
    install_signal_hook();
    let (this_tx, thread_rx) = mpsc::channel::<String>();
    let (thread_tx, this_rx) = mpsc::channel::<BlePacket>();
    let thread_handle = thread::spawn(move || {
        packet::analyze_serial_packets("/dev/ttyUSB0", thread_tx, &thread_rx)
    });
    loop {
        thread::sleep(Duration::from_secs(1));
        if STOP_REQUEST.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = this_tx.send(String::from("thread-stop"));
            break;
        }
        loop {
            match this_rx.try_recv() {
                Ok(result) => {
                    if result.valid {
                        let mut device_name = String::new();
                        match result.ll_layer_data.complete_local_name {
                            Some(name) => {
                                device_name = name.device_name;
                            }
                            None => {}
                        }
                        match result.ll_layer_data.manufacturer_data {
                            Some(manufacturer_data) => {
                                if device_name.is_empty() {
                                    println!(
                                        "MAC: {}\tManufacturer: 0x{:04X}",
                                        get_mac_bytes_str(result.ll_layer_data.advertising_mac),
                                        manufacturer_data.company_id
                                    );
                                } else {
                                    println!(
                                        "MAC: {}\tManufacturer: 0x{:04X}\tDeviceName: {}",
                                        get_mac_bytes_str(result.ll_layer_data.advertising_mac),
                                        manufacturer_data.company_id,
                                        device_name.as_str()
                                    );
                                }
                            }
                            None => {
                                if device_name.is_empty() {
                                    println!(
                                        "MAC: {}",
                                        get_mac_bytes_str(result.ll_layer_data.advertising_mac)
                                    );
                                } else {
                                    println!(
                                        "MAC: {}\t\t\t\tDeviceName: {}",
                                        get_mac_bytes_str(result.ll_layer_data.advertising_mac),
                                        device_name.as_str()
                                    );
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
    }
    match thread_handle.join() {
        Ok(_) => {
            println!("ble_sniffer closed");
        }
        Err(_) => {}
    }
}

fn install_signal_hook() {
    let sig_action = signal::SigAction::new(
        signal::SigHandler::Handler(signal_handler),
        signal::SaFlags::SA_NODEFER,
        signal::SigSet::empty(),
    );
    unsafe {
        match signal::sigaction(signal::SIGINT, &sig_action) {
            Ok(_) => {
                println!("SIGINT signal has been set.");
            }
            Err(e) => {
                println!("SIGINT signal set failed, {:?}", e);
            }
        }
    }
}

extern "C" fn signal_handler(signal: i32) {
    if signal == SIGINT {
        STOP_REQUEST.fetch_or(true, std::sync::atomic::Ordering::SeqCst);
        println!("");
    }
}

fn get_mac_bytes_str(mac_bytes: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    )
}