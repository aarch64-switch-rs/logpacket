use std::fs::File;
use std::io::Write;

use logpacket::LogPacket;

fn main() {
    let mut new_packet = LogPacket::new();
    new_packet.set_process_id(0xBEEF);
    new_packet.set_thread_id(0xBABE);
    new_packet.set_process_name(String::from("test-process"));
    new_packet.set_user_system_clock(59);
    new_packet.set_text_log(String::from(include_str!("test.rs")));

    let mut i: usize = 0;
    for binlog in new_packet.encode_binlog() {
        let mut file = File::create(format!("{:#X}.nxbinlog", i)).unwrap();
        file.write_all(&binlog).unwrap();
        i += 1;
    }
}