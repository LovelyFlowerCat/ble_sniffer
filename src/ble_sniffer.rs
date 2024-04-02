use std::{
    sync::mpsc::{Receiver, Sender},
    thread,
    time::Duration,
};

// Author: CYY 3/30/2024
// Version: V1.0
pub const SNIFFER_VERSION: &str = "V1.1";
// Hardware: MCU: Nordic NRF52832 Board: RF-DG-32B
// Firmware: j-link-ob-sam3u128-v2-nordicsemi-170724.bin
// Firmware link: https://nsscprodmedia.blob.core.windows.net/prod/software-and-other-downloads/dev-kits/nrf5x-dk-files/j-link-ob-sam3u128-v2-nordicsemi-170724.bin
// Bluetooth Core Specification version: v5.4
// Bluetooth Core Specification link: https://www.bluetooth.com/specifications/core54-html/

// UART protocol packet codes start (see sniffer_uart_protocol.pdf)
pub const SLIP_START: u8 = 0xAB;
pub const SLIP_END: u8 = 0xBC;
pub const SLIP_ESC: u8 = 0xCD;
pub const SLIP_ESC_START: u8 = SLIP_START + 1;
pub const SLIP_ESC_END: u8 = SLIP_END + 1;
pub const SLIP_ESC_ESC: u8 = SLIP_ESC + 1;

pub const PROTOVER_V3: u8 = 3;
pub const PROTOVER_V2: u8 = 2;
pub const PROTOVER_V1: u8 = 1;
pub const HEADER_LENGTH: u8 = 6;
pub const REQ_FOLLOW: u8 = 0x00;
pub const EVENT_FOLLOW: u8 = 0x01;
pub const EVENT_PACKET_ADV_PDU: u8 = 0x02;
pub const EVENT_CONNECT: u8 = 0x05;
pub const EVENT_PACKET_DATA_PDU: u8 = 0x06;
pub const REQ_SCAN_CONT: u8 = 0x07;
pub const EVENT_DISCONNECT: u8 = 0x09;
pub const SET_TEMPORARY_KEY: u8 = 0x0C;
pub const PING_REQ: u8 = 0x0D;
pub const PING_RESP: u8 = 0x0E;
pub const SWITCH_BAUD_RATE_REQ: u8 = 0x13;
pub const SWITCH_BAUD_RATE_RESP: u8 = 0x14;
pub const SET_ADV_CHANNEL_HOP_SEQ: u8 = 0x17;
pub const SET_PRIVATE_KEY: u8 = 0x18;
pub const SET_LEGACY_LONG_TERM_KEY: u8 = 0x19;
pub const SET_SC_LONG_TERM_KEY: u8 = 0x1A;
pub const REQ_VERSION: u8 = 0x1B;
pub const RESP_VERSION: u8 = 0x1C;
pub const REQ_TIMESTAMP: u8 = 0x1D;
pub const RESP_TIMESTAMP: u8 = 0x1E;
pub const SET_IDENTITY_RESOLVING_KEY: u8 = 0x1F;
pub const GO_IDLE: u8 = 0xFE;
// UART protocol packet codes end

// Reference book: Bluetooth specification Core_v5.4
pub const PACKET_TYPE_UNKNOWN: u8 = 0x00;
pub const PACKET_TYPE_ADVERTISING: u8 = 0x01;
pub const PACKET_TYPE_DATA: u8 = 0x02;

pub const AUX_ADV_IND: u8 = 0;
pub const AUX_CHAIN_IND: u8 = 1;
pub const AUX_SYNC_IND: u8 = 2;
pub const AUX_SCAN_RSP: u8 = 3;

pub const ADV_TYPE_ADV_IND: u8 = 0x0;
pub const ADV_TYPE_ADV_DIRECT_IND: u8 = 0x1;
pub const ADV_TYPE_ADV_NONCONN_IND: u8 = 0x2;
pub const ADV_TYPE_ADV_SCAN_IND: u8 = 0x6;
pub const ADV_TYPE_SCAN_REQ: u8 = 0x3;
pub const ADV_TYPE_SCAN_RSP: u8 = 0x4;
pub const ADV_TYPE_CONNECT_REQ: u8 = 0x5;
pub const ADV_TYPE_ADV_EXT_IND: u8 = 0x7;

pub const PHY_1M: u8 = 0;
pub const PHY_2M: u8 = 1;
pub const PHY_CODED: u8 = 2;

pub const PHY_CODED_CI_S8: u8 = 0;
pub const PHY_CODED_CI_S2: u8 = 1;

pub struct BlePacket {
    pub valid: bool,
    pub protocol_version: u8,
    pub packet_counter: u16,
    pub packet_id: u8,
    pub packet_header: BlePacketHeader,
    pub ll_layer_data: BleLinkLayer,
}

pub struct BlePacketHeader {
    pub protocol_version: u8,
    pub crc_ok: bool,
    pub adv_header: Option<BlePacketHeaderAdv>,
    pub data_header: Option<BlePacketHeaderData>,
    pub phy: u8,
    pub channel_index: u8,
    pub rssi: i16,
    pub event_counter: u16,
    pub delta_time_us: u32,
}

pub struct BlePacketHeaderAdv {
    aux_type: u8,
    address_resolved: bool,
}

pub struct BlePacketHeaderData {
    direction_to_slave: bool,
    encrypted: bool,
    mic_ok: bool,
}

pub struct BleLinkLayer {
    pub access_address: u32,
    pub pdu_type: u8,
    pub channel_select: u8,
    pub tx_address_public: bool,
    pub rx_address_public: bool,
    pub non_conn_ind: Option<BleLLNonConnIndMsg>,
    pub scan_req: Option<BleLLScanReqMsg>,
}

pub struct BleLLNonConnIndMsg {
    pub advertising_mac: [u8; 6],
    pub advertising_types: Vec<u8>,
    pub flags: Option<BleLLDataFlags>,
    pub complete_local_name: Option<BleLLCompleteLocalName>,
    pub tx_power_level: Option<BleLLTxPowerLevel>,
    pub manufacturer_data: Option<BleLLManufacturerSpecificData>,
}

pub struct BleLLScanReqMsg {
    pub scanning_mac: [u8; 6],
    pub advertising_mac: [u8; 6],
}

pub struct BleLLDataFlags {
    pub simultaneous_host: bool,
    pub simultaneous_controller: bool,
    pub br_edr_support: bool,
    pub le_general_discoverale: bool,
    pub le_limited_discoverable: bool,
}

pub struct BleLLCompleteLocalName {
    pub device_name: String,
}

pub struct BleLLTxPowerLevel {
    pub tx_power_level: u8,
}

pub struct BleLLManufacturerSpecificData {
    pub company_id: u16,
    pub data: Vec<u8>,
}

impl BlePacket {
    pub fn new() -> BlePacket {
        BlePacket {
            valid: false,
            protocol_version: 0,
            packet_counter: 0,
            packet_id: 0,
            packet_header: BlePacketHeader::new(),
            ll_layer_data: BleLinkLayer::new(),
        }
    }

    pub fn from(bytes: &Vec<u8>) -> BlePacket {
        let mut ll_payload_len: u8 = 0;
        let mut ll_payload_index: u8 = 0;
        let mut ll_payload_read_status: u8 = 0;
        let mut ll_payload_info_len: u8 = 0;
        let mut ll_payload_info_index: u8 = 0;
        let mut ll_payload_info_type: u8 = 0;
        let mut result = BlePacket::new();
        let mut cache_bytes: Vec<u8> = Vec::new();
        let mut byte_index = 0;
        let mut non_conn_ind_msg = BleLLNonConnIndMsg::new();
        let mut scan_req_msg = BleLLScanReqMsg::new();
        for b in bytes {
            // Reference:
            // Bytes index < 16: Sniffer API Guide.pdf & sniffer_uart_protocol.txt
            // Bytes index >= 16: Core v5.4 vol.6. PartB Chapter2
            if byte_index == 0 && *b != HEADER_LENGTH {
                return result;
            } else if byte_index == 2 {
                result.protocol_version = *b;
            } else if byte_index == 3 {
                result.packet_counter |= *b as u16;
            } else if byte_index == 4 {
                result.packet_counter |= (*b as u16) << 8;
            } else if byte_index == 5 {
                result.packet_id = *b;
            } else if byte_index == 7 {
                result.packet_header.crc_ok = (*b & 1) == 1;
                result.packet_header.phy = (*b & 0b1110000) >> 4;
                if result.packet_id == EVENT_PACKET_DATA_PDU {
                    let data_header = BlePacketHeaderData {
                        direction_to_slave: ((*b & 0b10) >> 1) == 1,
                        encrypted: ((*b & 0b100) >> 2) == 1,
                        mic_ok: ((*b & 0b1000) >> 3) == 1,
                    };
                    result.packet_header.data_header = Some(data_header);
                } else if result.packet_id == EVENT_PACKET_ADV_PDU {
                    let adv_header = BlePacketHeaderAdv {
                        aux_type: (*b & 0b110) >> 1,
                        address_resolved: ((*b & 0b1000) >> 3) == 1,
                    };
                    result.packet_header.adv_header = Some(adv_header);
                }
            } else if byte_index == 8 {
                result.packet_header.channel_index = *b;
            } else if byte_index == 9 {
                result.packet_header.rssi = 0 - *b as i16;
            } else if byte_index == 10 {
                result.packet_header.event_counter |= *b as u16;
            } else if byte_index == 11 {
                result.packet_header.event_counter |= (*b as u16) << 8;
            } else if byte_index == 12 {
                result.packet_header.delta_time_us |= *b as u32;
            } else if byte_index == 13 {
                result.packet_header.delta_time_us |= (*b as u32) << 8;
            } else if byte_index == 14 {
                result.packet_header.delta_time_us |= (*b as u32) << 16;
            } else if byte_index == 15 {
                result.packet_header.delta_time_us |= (*b as u32) << 24;
            } else if byte_index == 16 {
                result.ll_layer_data.access_address |= *b as u32;
            } else if byte_index == 17 {
                result.ll_layer_data.access_address |= (*b as u32) << 8;
            } else if byte_index == 18 {
                result.ll_layer_data.access_address |= (*b as u32) << 16;
            } else if byte_index == 19 {
                result.ll_layer_data.access_address |= (*b as u32) << 24;
            } else if byte_index == 20 {
                result.ll_layer_data.pdu_type = *b & 0b1111;
                result.ll_layer_data.channel_select = (*b & 0x20) >> 5;
                result.ll_layer_data.tx_address_public = ((*b & 0x40) >> 6) == 0;
                result.ll_layer_data.rx_address_public = ((*b & 0x80) >> 7) == 0;
            } else if byte_index == 21 {
                // Differences between wireshark and raw uart bytes: WTF!
                // An extra zero byte is right here in the raw uart bytes
                if ll_payload_len == 0 {
                    ll_payload_len = *b;
                    byte_index -= 1;
                } else {
                    if result.ll_layer_data.pdu_type == ADV_TYPE_SCAN_REQ && ll_payload_len != 12 {
                        return result;
                    }
                }
            } else if byte_index >= 22 && byte_index <= 27 {
                if result.ll_layer_data.pdu_type == ADV_TYPE_ADV_NONCONN_IND {
                    non_conn_ind_msg.advertising_mac[27 - byte_index] = *b;
                } else if result.ll_layer_data.pdu_type == ADV_TYPE_SCAN_REQ {
                    scan_req_msg.scanning_mac[27 - byte_index] = *b;
                }
                ll_payload_index += 1;
            } else {
                if ll_payload_index < ll_payload_len {
                    if result.ll_layer_data.pdu_type == ADV_TYPE_ADV_NONCONN_IND {
                        if ll_payload_read_status == 0 {
                            ll_payload_info_len = *b;
                            ll_payload_info_index = 0;
                            ll_payload_info_type = 0;
                            ll_payload_read_status = 1;
                            cache_bytes.clear();
                        } else if ll_payload_read_status == 1 {
                            ll_payload_info_type = *b;
                            non_conn_ind_msg.advertising_types.push(*b);
                            ll_payload_read_status = 2;
                            ll_payload_info_index += 1;
                        } else if ll_payload_read_status == 2 {
                            ll_payload_info_index += 1;
                            if ll_payload_info_type == 0x01 {
                                let flags = BleLLDataFlags {
                                    simultaneous_host: ((*b >> 4) & 1) == 1,
                                    simultaneous_controller: ((*b >> 3) & 1) == 1,
                                    br_edr_support: ((*b >> 2) & 1) == 1,
                                    le_general_discoverale: ((*b >> 1) & 1) == 1,
                                    le_limited_discoverable: (*b & 1) == 1,
                                };
                                non_conn_ind_msg.flags = Some(flags);
                            } else if ll_payload_info_type == 0x09 {
                                cache_bytes.push(*b);
                                if ll_payload_info_index == ll_payload_info_len {
                                    match String::from_utf8(cache_bytes.clone()) {
                                        Ok(name) => {
                                            let complete_local_name =
                                                BleLLCompleteLocalName { device_name: name };
                                            non_conn_ind_msg.complete_local_name =
                                                Some(complete_local_name);
                                        }
                                        Err(_) => {}
                                    }
                                }
                            } else if ll_payload_info_type == 0x0a {
                                non_conn_ind_msg.tx_power_level =
                                    Some(BleLLTxPowerLevel { tx_power_level: *b });
                            } else if ll_payload_info_type == 0xff {
                                cache_bytes.push(*b);
                                if ll_payload_info_index == ll_payload_info_len {
                                    let mut cache_bytes_index = 0;
                                    let mut company_id: u16 = 0;
                                    let mut extra_data: Vec<u8> = Vec::new();
                                    for b1 in &cache_bytes {
                                        if cache_bytes_index == 0 {
                                            company_id |= *b1 as u16;
                                        } else if cache_bytes_index == 1 {
                                            company_id |= (*b1 as u16) << 8;
                                        } else {
                                            extra_data.push(*b1);
                                        }
                                        cache_bytes_index += 1;
                                    }
                                    let manufacturer_data = BleLLManufacturerSpecificData {
                                        company_id,
                                        data: extra_data,
                                    };
                                    non_conn_ind_msg.manufacturer_data = Some(manufacturer_data);
                                }
                            }
                            if ll_payload_info_index == ll_payload_info_len {
                                ll_payload_read_status = 0;
                            }
                        }
                    } else if result.ll_layer_data.pdu_type == ADV_TYPE_SCAN_REQ {
                        scan_req_msg.advertising_mac[33 - byte_index] = *b;
                    }
                    ll_payload_index += 1;
                }
            }
            byte_index += 1;
        }
        if result.ll_layer_data.pdu_type == ADV_TYPE_ADV_NONCONN_IND {
            result.ll_layer_data.non_conn_ind = Some(non_conn_ind_msg);
        } else if result.ll_layer_data.pdu_type == ADV_TYPE_SCAN_REQ {
            result.ll_layer_data.scan_req = Some(scan_req_msg);
        }
        result.valid = true;
        result
    }
}

impl BlePacketHeader {
    pub fn new() -> BlePacketHeader {
        BlePacketHeader {
            protocol_version: 0,
            crc_ok: false,
            data_header: Option::None,
            adv_header: Option::None,
            phy: 0,
            channel_index: 0,
            rssi: 0,
            event_counter: 0,
            delta_time_us: 0,
        }
    }
}

impl BleLinkLayer {
    pub fn new() -> BleLinkLayer {
        BleLinkLayer {
            access_address: 0,
            pdu_type: 0,
            channel_select: 0,
            tx_address_public: false,
            rx_address_public: false,
            non_conn_ind: None,
            scan_req: None,
        }
    }
}

impl BleLLNonConnIndMsg {
    pub fn new() -> BleLLNonConnIndMsg {
        BleLLNonConnIndMsg {
            advertising_mac: [0; 6],
            advertising_types: Vec::new(),
            flags: None,
            complete_local_name: None,
            tx_power_level: None,
            manufacturer_data: None,
        }
    }
}

impl BleLLScanReqMsg {
    pub fn new() -> BleLLScanReqMsg {
        BleLLScanReqMsg {
            scanning_mac: [0; 6],
            advertising_mac: [0; 6],
        }
    }
}

pub fn analyze_serial_packets(serial_name: &str, tx: Sender<BlePacket>, rx: &Receiver<String>) {
    let mut recv_buffer: [u8; 1024] = [0; 1024];
    let mut packet_start = false;
    let mut previous_byte_is_esc = false;
    let mut packet_bytes: Vec<u8> = Vec::new();
    let mut stop_request = false;
    loop {
        thread::sleep(Duration::from_secs(1));
        if thread_should_stop(rx) || stop_request {
            break;
        }
        match serialport::new(serial_name, 460800).open() {
            Ok(mut serial) => {
                let mut send_packet_counter: u16 = 0;
                let mut send_bytes = make_send_scan_bytes(false, false, false, send_packet_counter);
                send_packet_counter += 1;
                match serial.write_all(send_bytes.as_slice()) {
                    Ok(_) => {}
                    Err(error) => {
                        println!("Failed to send bytes to serial, {:?}", error);
                    }
                }
                send_bytes = make_send_tk_bytes(0, send_packet_counter);
                match serial.write_all(send_bytes.as_slice()) {
                    Ok(_) => {}
                    Err(error) => {
                        println!("Failed to send bytes to serial, {:?}", error);
                    }
                }
                thread::sleep(Duration::from_secs(1));
                loop {
                    thread::sleep(Duration::from_secs(1));
                    if thread_should_stop(rx) {
                        stop_request = true;
                        break;
                    }
                    match serial.read(&mut recv_buffer) {
                        Ok(available_len) => {
                            let mut read_index: usize = 0;
                            for b in recv_buffer {
                                if read_index == available_len {
                                    break;
                                }
                                read_index += 1;
                                if !packet_start {
                                    packet_start = b == SLIP_START;
                                    continue;
                                }
                                if b == SLIP_END {
                                    packet_start = false;
                                    // print_hex_bytes(&packet_bytes);
                                    let ble_packet = BlePacket::from(&packet_bytes);
                                    if ble_packet.valid {
                                        let _ = tx.send(ble_packet);
                                    }
                                    packet_bytes.clear();
                                } else if b == SLIP_ESC {
                                    previous_byte_is_esc = true;
                                } else if previous_byte_is_esc {
                                    if b == SLIP_ESC_START {
                                        packet_bytes.push(SLIP_START);
                                    } else if b == SLIP_ESC_END {
                                        packet_bytes.push(SLIP_END);
                                    } else if b == SLIP_ESC_ESC {
                                        packet_bytes.push(SLIP_ESC);
                                    } else {
                                        packet_bytes.push(b);
                                    }
                                    previous_byte_is_esc = false;
                                } else {
                                    packet_bytes.push(b);
                                }
                            }
                        }
                        Err(error) => {
                            println!("Serial error occurs: {}", error.to_string());
                        }
                    }
                }
            }
            Err(error) => {
                println!(
                    "Cannot open serial {}\nReason: {}",
                    serial_name,
                    error.to_string()
                );
            }
        }
    }
}

fn thread_should_stop(rx: &Receiver<String>) -> bool {
    let mut result = false;
    loop {
        match rx.try_recv() {
            Ok(msg) => {
                if msg.eq("thread-stop") {
                    result = true;
                }
            }
            Err(_) => {
                break;
            }
        }
    }
    result
}

pub fn get_packet_bytes(bytes: Vec<u8>) -> (Vec<Vec<u8>>, usize) {
    let mut packet_list: Vec<Vec<u8>> = Vec::new();
    let mut packet_bytes: Vec<u8> = Vec::new();
    let mut packet_start = false;
    let mut previous_byte_is_esc = false;
    let mut read_index: usize = 0;
    for b in bytes {
        read_index += 1;
        if !packet_start {
            packet_start = b == SLIP_START;
            continue;
        }
        if b == SLIP_END {
            packet_start = false;
            packet_list.push(packet_bytes);
            packet_bytes = Vec::new();
        } else if b == SLIP_ESC {
            previous_byte_is_esc = true;
        } else if previous_byte_is_esc {
            if b == SLIP_ESC_START {
                packet_bytes.push(SLIP_START);
            } else if b == SLIP_ESC_END {
                packet_bytes.push(SLIP_END);
            } else if b == SLIP_ESC_ESC {
                packet_bytes.push(SLIP_ESC);
            } else {
                packet_bytes.push(b);
            }
            previous_byte_is_esc = false;
        } else {
            packet_bytes.push(b);
        }
    }
    (packet_list, read_index)
}

fn print_hex_bytes(bytes: &Vec<u8>) {
    for b in bytes {
        print!("0x{:X},", b);
    }
    println!("\n");
}

fn add_bytes_to_slip(packet_bytes: &mut Vec<u8>, content_byte: u8) {
    if content_byte == SLIP_START || content_byte == SLIP_END || content_byte == SLIP_ESC {
        packet_bytes.push(SLIP_ESC);
        packet_bytes.push(content_byte + 1);
    } else {
        packet_bytes.push(content_byte);
    }
}

fn make_send_bytes(id: u8, payload: &[u8], packet_counter: u16) -> Vec<u8> {
    let mut packet_bytes: Vec<u8> = Vec::new();
    packet_bytes.push(SLIP_START);
    add_bytes_to_slip(&mut packet_bytes, HEADER_LENGTH);
    add_bytes_to_slip(&mut packet_bytes, payload.len() as u8);
    add_bytes_to_slip(&mut packet_bytes, PROTOVER_V1);
    add_bytes_to_slip(&mut packet_bytes, (packet_counter & 0xff) as u8);
    add_bytes_to_slip(&mut packet_bytes, (packet_counter >> 8) as u8);
    add_bytes_to_slip(&mut packet_bytes, id);
    for payload_byte in payload {
        add_bytes_to_slip(&mut packet_bytes, *payload_byte);
    }
    packet_bytes.push(SLIP_END);
    packet_bytes
}

fn make_send_scan_bytes(
    find_scan_rsp: bool,
    find_aux: bool,
    scan_coded: bool,
    packet_counter: u16,
) -> Vec<u8> {
    let mut flags: u8 = 0;
    if find_scan_rsp {
        flags = 1;
    }
    if find_aux {
        flags |= 1 << 1;
    }
    if scan_coded {
        flags |= 1 << 2;
    }
    let payload = [flags];
    make_send_bytes(REQ_SCAN_CONT, &payload, packet_counter)
}

fn make_send_tk_bytes(tk: u8, packet_counter: u16) -> Vec<u8> {
    let payload = [tk; 16];
    make_send_bytes(SET_TEMPORARY_KEY, &payload, packet_counter)
}
