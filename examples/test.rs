use std::fs::File;
use std::io::Write;

use logpacket::LogPacket;

fn main() {
    let mut new_packet = LogPacket::new();
    new_packet.set_process_id(0xBEEF);
    new_packet.set_thread_id(0xBABE);
    new_packet.set_process_name(String::from("test-process"));
    new_packet.set_user_system_clock(59);
    new_packet.set_text_log(String::from("Text log sample!"));

    let mut file = File::create("test.nxbinlog").unwrap();
    file.write_all(&new_packet.encode()).unwrap();
}