BLE_Sniffer
=====================================================

Bluetooth Low Energy (BLE) is one of the sub types of bluetooth protocol. BLE_Sniffer is a program written in rust, which analyze serveral types of inputs and output with the result structure `BlePacket`. 

## Acceptable inputs
The program accepts either serial inputs or raw bytes input.
- Input with serial. It is recommended to call `ble_sniffer::analyze_serial_packets` in a new thread to continuously analyze input bytes. For supported 
- Input with raw bytes array. Call `ble_sniffer::BlePacket::from(bytes)` to convert raw BLE payload bytes to `BlePacket`.

## Hardware support
If you just try to convert raw BLE payload bytes to `BlePacket` result, you can skip this chapter.

Any NRF52832 chip with nordic ble sniffer firmware, whose default serial baudrate is 460800.

Develop firmware version: [j-link-ob-sam3u128-v2-nordicsemi-170724.bin](https://nsscprodmedia.blob.core.windows.net/prod/software-and-other-downloads/dev-kits/nrf5x-dk-files/j-link-ob-sam3u128-v2-nordicsemi-170724.bin)

Other firmware version for NRF52832 may be compatible, but havn't tested yet. It will be kind of you to have them tested and report in issues.

## Project structure
There are two files in this project: the `main.rs`  script is an example of using ble sniffer, which displays advertising mac, manufacturer id and device name if exists, the second `ble_sniffer.rs` script is the main content of this project. 

## Limitation
Until now, the program can only analyze the following types of BLE advertising data types.

<table>
<thead>
<tr>
<th>Type</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>0x01</td>
<td>Flags</td>
</tr>
<tr>
<td>0x09</td>
<td>Complete Local Name</td>
</tr>
<tr>
<td>0x0A</td>
<td>Tx Power Level</td>
</tr>
<td>0xFF</td>
<td>Manufacturer Specific Data</td>
</tr>
</tbody>
</table>

## Requirements

BLE_Sniffer requires rustc version 1.76.0 or greater, cargo version 1.76.0 or greater although individual sniffs may have additional requirements such as external applications and scripts.

It is recommended to keep rustc version the same as cargo version.

Cargo dependencies requirements are as follow:
- serialport = "4.3.0"
- nix = "0.26"

## Build and Run

The easiest way to get started with PHP_CodeSniffer is to download the Phar files for each of the commands:
```bash
# Clone the repository
git clone https://github.com/LovelyFlowerCat/ble_sniffer.git

# Change working directory
cd ./ble_sniffer

# Build default target
cargo build
```

## Getting Started

The default executable output is in ./target/debug/
```bash
cd ./target/debug/
./ble_sniffer
```
If everything works well, you will see outputs simliar to the following output:
```bash
MAC: 80:B6:55:0C:C2:67	Manufacturer: 0x027D
MAC: 23:EA:A2:EA:0E:30	Manufacturer: 0x0006
MAC: 36:72:DE:EF:29:A7	Manufacturer: 0x0006
MAC: 27:F7:D5:01:93:A4	Manufacturer: 0x0006
MAC: 1A:E3:AF:82:E6:C1	Manufacturer: 0x004C
```
Press Ctrl-C to exit the program.

## Issues

Bug reports and feature requests can be submitted on the [GitHub Issue Tracker](https://github.com/LovelyFlowerCat/ble_sniffer/issues).

## Contributing

Welcom every one to give me advice or improve the program with more functions or fix bugs~

## Versioning

Check `ble_sniffer::SNIFFER_VERSION` for version string.