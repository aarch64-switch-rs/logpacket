#![no_std]

extern crate alloc;
use core::option::Option;
use alloc::string::String;
use alloc::vec::Vec;

pub mod detail;
use detail::VecExt;
use detail::ChunkType;

pub struct LogPacket {
    header: detail::LogPacketHeader,
    body: detail::LogPacketBody
}

impl LogPacket {
    pub fn new() -> Self {
        Self { header: detail::LogPacketHeader::new(), body: detail::LogPacketBody::new() }
    }

    #[allow(unreachable_patterns)]
    pub fn from(data: Vec<u8>) -> Option<Self> {
        let mut offset: usize = 0;
        let mut packet = Self::new();
        
        if let Some(header) = data.read_plain::<detail::LogPacketHeader>(&mut offset) {
            packet.header = header;
            let packet_len = offset + header.payload_size as usize;
            while offset < packet_len {
                if let Some(chunk_header) = data.read_plain::<detail::LogDataChunkHeader>(&mut offset) {
                    match chunk_header.key {
                        detail::LogDataChunkKey::LogSessionBegin => packet.body.log_session_begin = bool::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::LogSessionEnd => packet.body.log_session_end = bool::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::TextLog => packet.body.text_log = String::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::LineNumber => packet.body.line_number = u32::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::FileName => packet.body.file_name = String::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::FunctionName => packet.body.function_name = String::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::ModuleName => packet.body.module_name = String::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::ThreadName => packet.body.thread_name = String::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::LogPacketDropCount => packet.body.log_packet_drop_count = u64::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::UserSystemClock => packet.body.user_system_clock = u64::decode(&data, offset, chunk_header.len),
                        detail::LogDataChunkKey::ProcessName => packet.body.process_name = String::decode(&data, offset, chunk_header.len),
                        _ => return None
                    };
                    offset += chunk_header.len as usize;
                }
                else {
                    return None;
                }
            }
            return Some(packet);
        }

        None
    }

    fn get_chunk_impl<T: ChunkType>(t: T) -> Option<T> {
        if t.is_empty() {
            None
        }
        else {
            Some(t)
        }
    }

    pub fn get_process_id(&self) -> u64 {
        self.header.process_id
    }

    pub fn set_process_id(&mut self, process_id: u64) {
        self.header.process_id = process_id;
    }

    pub fn get_thread_id(&self) -> u64 {
        self.header.thread_id
    }

    pub fn set_thread_id(&mut self, thread_id: u64) {
        self.header.thread_id = thread_id;
    }

    pub fn get_flags(&self) -> detail::LogPacketFlag {
        self.header.flags
    }

    pub fn set_flags(&mut self, flags: detail::LogPacketFlag) {
        self.header.flags = flags;
    }

    pub fn get_text_log(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.text_log.clone())
    }

    pub fn set_text_log(&mut self, text_log: String) {
        self.body.text_log = text_log;
    }

    pub fn encode(&mut self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.header.payload_size = self.body.compute_size();
        buf.write_plain(self.header);

        self.body.log_session_begin.write_to(detail::LogDataChunkKey::LogSessionBegin, &mut buf);
        self.body.log_session_end.write_to(detail::LogDataChunkKey::LogSessionEnd, &mut buf);
        self.body.text_log.write_to(detail::LogDataChunkKey::TextLog, &mut buf);
        self.body.line_number.write_to(detail::LogDataChunkKey::LineNumber, &mut buf);
        self.body.file_name.write_to(detail::LogDataChunkKey::FileName, &mut buf);
        self.body.function_name.write_to(detail::LogDataChunkKey::FunctionName, &mut buf);
        self.body.module_name.write_to(detail::LogDataChunkKey::ModuleName, &mut buf);
        self.body.thread_name.write_to(detail::LogDataChunkKey::ThreadName, &mut buf);
        self.body.log_packet_drop_count.write_to(detail::LogDataChunkKey::LogPacketDropCount, &mut buf);
        self.body.user_system_clock.write_to(detail::LogDataChunkKey::UserSystemClock, &mut buf);
        self.body.process_name.write_to(detail::LogDataChunkKey::ProcessName, &mut buf);

        buf
    }
}