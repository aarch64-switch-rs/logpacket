#![no_std]

#[macro_use]
extern crate alloc;
use core::option::Option;
use alloc::string::String;
use alloc::vec::Vec;

pub mod detail;
use detail::VecExt;
use detail::ChunkType;

pub struct LogPacket {
    bin_header: detail::LogBinaryHeader,
    header: detail::LogPacketHeader,
    body: detail::LogPacketBody
}

impl LogPacket {
    pub fn new() -> Self {
        Self { bin_header: detail::LogBinaryHeader::empty(), header: detail::LogPacketHeader::new(), body: detail::LogPacketBody::new() }
    }

    #[allow(unreachable_patterns)]
    pub fn from(data: Vec<u8>) -> Option<Self> {
        let mut offset: usize = 0;
        let mut packet = Self::new();
        
        if let Some(bin_header) = data.read_plain::<detail::LogBinaryHeader>(&mut offset) {
            if bin_header.magic == detail::LOG_BINARY_HEADER_MAGIC {
                packet.bin_header = bin_header;
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
            }
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

    fn encode_impl(&mut self, include_bin_header: bool) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.header.payload_size = self.body.compute_size();
        if include_bin_header {
            buf.write_plain(self.bin_header);
        }
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

    pub fn encode_packet(&mut self) -> Vec<u8> {
        self.encode_impl(false)
    }

    pub fn encode_binlog(&mut self) -> Vec<u8> {
        self.encode_impl(true)
    }

    pub fn try_join(&mut self, other: Self) {
        if self.header.flags.is_head() && !self.header.flags.is_tail() {
            if !other.header.flags.is_head() {
                if other.header.flags.is_tail() {
                    self.header.flags.set_tail();
                }
                self.body.text_log = format!("{}{}", self.body.text_log, other.body.text_log);
            }
        }
    }

    pub fn is_head(&self) -> bool {
        self.header.flags.is_head()
    }

    pub fn is_tail(&self) -> bool {
        self.header.flags.is_tail()
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

    pub fn get_severity(&self) -> detail::LogSeverity {
        self.header.severity
    }

    pub fn set_severity(&mut self, severity: detail::LogSeverity) {
        self.header.severity = severity;
    }

    pub fn get_verbosity(&self) -> bool {
        self.header.verbosity
    }

    pub fn set_verbosity(&mut self, verbosity: bool) {
        self.header.verbosity = verbosity;
    }

    pub fn get_log_session_begin(&self) -> Option<bool> {
        Self::get_chunk_impl(self.body.log_session_begin)
    }

    pub fn set_log_session_begin(&mut self, log_session_begin: bool) {
        self.body.log_session_begin = log_session_begin;
    }

    pub fn get_log_session_end(&self) -> Option<bool> {
        Self::get_chunk_impl(self.body.log_session_end)
    }

    pub fn set_log_session_end(&mut self, log_session_end: bool) {
        self.body.log_session_end = log_session_end;
    }

    pub fn get_text_log(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.text_log.clone())
    }

    pub fn set_text_log(&mut self, text_log: String) {
        self.body.text_log = text_log;
    }

    pub fn get_line_number(&self) -> Option<u32> {
        Self::get_chunk_impl(self.body.line_number)
    }

    pub fn set_line_number(&mut self, line_number: u32) {
        self.body.line_number = line_number;
    }

    pub fn get_file_name(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.file_name.clone())
    }
    
    pub fn set_file_name(&mut self, file_name: String) {
        self.body.file_name = file_name;
    }

    pub fn get_function_name(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.function_name.clone())
    }
    
    pub fn set_function_name(&mut self, function_name: String) {
        self.body.function_name = function_name;
    }

    pub fn get_module_name(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.module_name.clone())
    }
    
    pub fn set_module_name(&mut self, module_name: String) {
        self.body.module_name = module_name;
    }

    pub fn get_thread_name(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.thread_name.clone())
    }
    
    pub fn set_thread_name(&mut self, thread_name: String) {
        self.body.thread_name = thread_name;
    }

    pub fn get_log_packet_drop_count(&self) -> Option<u64> {
        Self::get_chunk_impl(self.body.log_packet_drop_count)
    }

    pub fn set_log_packet_drop_count(&mut self, log_packet_drop_count: u64) {
        self.body.log_packet_drop_count = log_packet_drop_count;
    }

    pub fn get_user_system_clock(&self) -> Option<u64> {
        Self::get_chunk_impl(self.body.user_system_clock)
    }

    pub fn set_user_system_clock(&mut self, user_system_clock: u64) {
        self.body.user_system_clock = user_system_clock;
    }

    pub fn get_process_name(&self) -> Option<String> {
        Self::get_chunk_impl(self.body.process_name.clone())
    }
    
    pub fn set_process_name(&mut self, process_name: String) {
        self.body.process_name = process_name;
    }
}