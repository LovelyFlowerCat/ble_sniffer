use std::{
    sync::{atomic::AtomicBool, mpsc},
    thread,
    time::Duration,
};

use nix::{libc::SIGINT, sys::signal};

use crate::ble_sniffer::BlePacket;

mod ble_sniffer;

static STOP_REQUEST: AtomicBool = AtomicBool::new(false);

fn main() {
    let mut serial_path = String::new();
    println!("Please input serial path (e.g. /dev/ttyUSB0): ");
    loop {
        match std::io::stdin().read_line(&mut serial_path) {
            Ok(_) => {
                serial_path = serial_path.replace("\r", "").replace("\n", "");
                match serialport::new(serial_path.as_str(), 460800).open() {
                    Ok(_) => {
                        break;
                    }
                    Err(error) => {
                        println!("{}", serial_path.as_str());
                        println!("Error: {}", error.to_string());
                        println!("Please input serial path (e.g. /dev/ttyUSB0): ");
                    }
                }
            }
            Err(error) => {
                println!("Error occurs: {:?}", error);
                return;
            }
        }
    }
    install_signal_hook();
    let (this_tx, thread_rx) = mpsc::channel::<String>();
    let (thread_tx, this_rx) = mpsc::channel::<BlePacket>();
    let thread_handle = thread::spawn(move || {
        ble_sniffer::analyze_serial_packets(serial_path.as_str(), thread_tx, &thread_rx)
    });
    let mut recorded_macs: Vec<[u8; 6]> = Vec::new();
    loop {
        thread::sleep(Duration::from_secs(1));
        recorded_macs.clear();
        if STOP_REQUEST.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = this_tx.send(String::from("thread-stop"));
            break;
        }
        loop {
            match this_rx.try_recv() {
                Ok(result) => {
                    if result.valid
                        && result.ll_layer_data.pdu_type == ble_sniffer::ADV_TYPE_ADV_NONCONN_IND
                    {
                        match result.ll_layer_data.non_conn_ind {
                            Some(non_conn_ind_msg) => {
                                if mac_is_recorded(&recorded_macs, &non_conn_ind_msg.advertising_mac)
                                {
                                    continue;
                                }
                                recorded_macs.push(non_conn_ind_msg.advertising_mac.clone());
                                let mut device_name = String::new();
                                match non_conn_ind_msg.complete_local_name {
                                    Some(name) => {
                                        device_name = name.device_name;
                                    }
                                    None => {}
                                }
                                match non_conn_ind_msg.manufacturer_data {
                                    Some(manufacturer_data) => {
                                        if device_name.is_empty() {
                                            println!(
                                                "MAC: {}\tManufacturer: 0x{:04X}",
                                                get_mac_bytes_str(non_conn_ind_msg.advertising_mac),
                                                manufacturer_data.company_id
                                            );
                                        } else {
                                            println!(
                                                "MAC: {}\tManufacturer: 0x{:04X}\tDeviceName: {}",
                                                get_mac_bytes_str(non_conn_ind_msg.advertising_mac),
                                                manufacturer_data.company_id,
                                                device_name.as_str()
                                            );
                                        }
                                    }
                                    None => {
                                        if device_name.is_empty() {
                                            println!(
                                                "MAC: {}",
                                                get_mac_bytes_str(non_conn_ind_msg.advertising_mac)
                                            );
                                        } else {
                                            println!(
                                                "MAC: {}\t\t\t\tDeviceName: {}",
                                                get_mac_bytes_str(non_conn_ind_msg.advertising_mac),
                                                device_name.as_str()
                                            );
                                        }
                                    }
                                }
                            }
                            None => {}
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

fn mac_is_recorded(recorded_macs: &Vec<[u8; 6]>, check_mac: &[u8; 6]) -> bool {
    let mut byte_index: usize;
    for recorded_mac in recorded_macs {
        byte_index = 0;
        for mac_byte in recorded_mac {
            if *mac_byte != check_mac[byte_index] {
                break;
            }
            byte_index += 1;
        }
        if byte_index == 6 {
            return true;
        }
    }
    false
}
