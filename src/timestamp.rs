use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_timestamp() -> u64 {
    // 获取当前时间
    let current_time = SystemTime::now();
    // 计算与UNIX纪元的时间间隔
    let duration = current_time.duration_since(UNIX_EPOCH).expect("SystemTime before UNIX EPOCH!");
    // 获取时间戳（以秒为单位）
    let timestamp = duration.as_secs();

    timestamp
}