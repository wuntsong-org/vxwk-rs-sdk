use hmac::{Hmac, Mac};

type  HmacSha1 = Hmac<sha1::Sha1>;

pub fn calculate_hmac(key: &str, data: &str) -> String {
    let mut mac =HmacSha1::new_from_slice(key.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let result = mac.finalize();
    let code = result.into_bytes();
    let hmac_base64 = base64::engine::Engine
        ::encode(&base64::engine::general_purpose::STANDARD, &code);
    hmac_base64
}