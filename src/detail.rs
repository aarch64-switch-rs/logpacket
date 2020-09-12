use core::mem::{size_of};
use core::cmp::min;
use core::default::Default;
use alloc::vec::Vec;
use alloc::string::String;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LogPacketFlag {
    flag: u8
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum LogSeverity {
    Trace,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum LogDataChunkKey {
    LogSessionBegin,
    LogSessionEnd,
    TextLog,
    LineNumber,
    FileName,
    FunctionName,
    ModuleName,
    ThreadName,
    LogPacketDropCount,
    UserSystemClock,
    ProcessName,
}

const LOG_PACKET_FLAG_HEAD: u8 = 1 << 0;
const LOG_PACKET_FLAG_TAIL: u8 = 1 << 1;
const LOG_PACKET_FLAG_LITTLE_ENDIAN: u8 = 1 << 2;

impl LogPacketFlag {
    pub const fn new() -> Self {
        Self { flag: 0 }
    }
    
    pub const fn from(raw_flag: u8) -> Self {
        Self { flag: raw_flag }
    }

    const fn is_impl(self, flag: u8) -> bool {
        (self.flag & flag) != 0
    }

    pub const fn set_impl(mut self, flag: u8) {
        self.flag |= flag;
    }

    pub const fn is_head(self) -> bool {
        self.is_impl(LOG_PACKET_FLAG_HEAD)
    }

    pub const fn set_head(self) {
        self.set_impl(LOG_PACKET_FLAG_HEAD);
    }

    pub const fn is_tail(self) -> bool {
        self.is_impl(LOG_PACKET_FLAG_TAIL)
    }

    pub const fn set_tail(self) {
        self.set_impl(LOG_PACKET_FLAG_TAIL);
    }

    pub const fn is_little_endian(self) -> bool {
        self.is_impl(LOG_PACKET_FLAG_LITTLE_ENDIAN)
    }

    pub const fn set_little_endian(self) {
        self.set_impl(LOG_PACKET_FLAG_LITTLE_ENDIAN);
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LogPacketHeader {
    pub process_id: u64,
    pub thread_id: u64,
    pub flags: LogPacketFlag,
    pub pad: u8,
    pub severity: LogSeverity,
    pub verbosity: bool,
    pub payload_size: u32,
}

impl LogPacketHeader {
    pub fn new() -> Self {
        Self {
            process_id: 0,
            thread_id: 0,
            flags: LogPacketFlag::from(LOG_PACKET_FLAG_HEAD | LOG_PACKET_FLAG_TAIL | LOG_PACKET_FLAG_LITTLE_ENDIAN),
            pad: 0,
            severity: LogSeverity::Trace,
            verbosity: false,
            payload_size: 0
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LogDataChunkHeader {
    pub key: LogDataChunkKey,
    pub len: u8
}

impl LogDataChunkHeader {
    pub fn new() -> Self {
        Self { key: LogDataChunkKey::LogSessionBegin, len: 0 }
    }

    pub fn from(key: LogDataChunkKey, len: u8) -> Self {
        Self { key: key, len: len }
    }
}

pub trait PlainChunkType: Copy + Default + PartialEq {}

fn push_to_vec<T: PlainChunkType>(vec: &mut Vec<u8>, t: T) {
    let t_ptr = &t as *const T as *const u8;
    for i in 0..size_of::<T>() {
        unsafe {
            let cur_t_ptr = t_ptr.offset(i as isize);
            vec.push(*cur_t_ptr);
        }
    }
}

pub trait ChunkType {
    fn get_len(&self) -> u8;
    fn encode(&self, data: &mut Vec<u8>);
    fn decode(data: &Vec<u8>, offset: usize, len: u8) -> Self;
    fn is_empty(&self) -> bool;

    fn write_to(&self, key: LogDataChunkKey, data: &mut Vec<u8>) {
        if !self.is_empty() {
            let chunk_header = LogDataChunkHeader::from(key, self.get_len());
            data.write_plain(chunk_header);
            self.encode(data);
        }
    }

    fn get_full_len(&self) -> u32 {
        let mut len = self.get_len() as u32;
        if len > 0 {
            len += size_of::<LogDataChunkHeader>() as u32;
        }
        len
    }
}

impl<T: PlainChunkType> ChunkType for T {
    fn get_len(&self) -> u8 {
        if self.is_empty() {
            0
        }
        else {
            size_of::<T>() as u8
        }
    }

    fn encode(&self, data: &mut Vec<u8>) {
        push_to_vec(data, *self)
    }

    fn decode(data: &Vec<u8>, offset: usize, len: u8) -> Self {
        if len == 0 {
            Default::default()
        }
        else {
            unsafe {
                *(data.as_ptr().offset(offset as isize) as *mut Self)
            }
        }
    }

    fn is_empty(&self) -> bool {
        *self == Default::default()
    }
}

impl PlainChunkType for bool {}
impl PlainChunkType for u32 {}
impl PlainChunkType for u64 {}

const MAX_STRING_LEN: u8 = 0x7F;

impl ChunkType for String {
    fn get_len(&self) -> u8 {
        min(self.len() as u8, MAX_STRING_LEN)
    }

    fn encode(&self, data: &mut Vec<u8>) {
        let bytes = self.as_bytes();
        for i in 0..self.get_len() {
            data.push(bytes[i as usize]);
        }
    }

    fn decode(data: &Vec<u8>, offset: usize, len: u8) -> Self {
        let mut string = String::new();
        unsafe {
            let ptr = data.as_ptr().offset(offset as isize);
            for i in 0..len {
                let cur_ptr = ptr.offset(i as isize);
                string.push(*cur_ptr as char);
            }
        }
        string
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

pub trait VecExt {
    fn read_plain<T: Copy>(&self, offset: &mut usize) -> Option<T>;
    fn write_plain<T: Copy>(&mut self, t: T);
}

impl VecExt for Vec<u8> {
    fn read_plain<T: Copy>(&self, offset: &mut usize) -> Option<T> {
        let cur_offset = *offset;
        if self.len() < (cur_offset + size_of::<T>()) {
            return None;
        }

        unsafe {
            *offset += size_of::<T>();
            Some(*(self.as_ptr().offset(cur_offset as isize) as *mut T))
        }
    }

    fn write_plain<T: Copy>(&mut self, t: T) {
        let t_ptr = &t as *const T as *const u8;
        for i in 0..size_of::<T>() {
            unsafe {
                let cur_t_ptr = t_ptr.offset(i as isize);
                self.push(*cur_t_ptr);
            }
        }
    }
}

pub struct LogPacketBody {
    pub log_session_begin: bool,
    pub log_session_end: bool,
    pub text_log: String,
    pub line_number: u32,
    pub file_name: String,
    pub function_name: String,
    pub module_name: String,
    pub thread_name: String,
    pub log_packet_drop_count: u64,
    pub user_system_clock: u64,
    pub process_name: String
}

impl LogPacketBody {
    pub fn new() -> Self {
        Self {
            log_session_begin: false,
            log_session_end: false,
            text_log: String::new(),
            line_number: 0,
            file_name: String::new(),
            function_name: String::new(),
            module_name: String::new(),
            thread_name: String::new(),
            log_packet_drop_count: 0,
            user_system_clock: 0,
            process_name: String::new()
        }
    }

    pub fn compute_size(&self) -> u32 {
        let mut size: u32 = 0;
        size += self.log_session_begin.get_full_len();
        size += self.log_session_end.get_full_len();
        size += self.text_log.get_full_len();
        size += self.line_number.get_full_len();
        size += self.file_name.get_full_len();
        size += self.function_name.get_full_len();
        size += self.module_name.get_full_len();
        size += self.thread_name.get_full_len();
        size += self.log_packet_drop_count.get_full_len();
        size += self.user_system_clock.get_full_len();
        size += self.process_name.get_full_len();
        size
    }
}