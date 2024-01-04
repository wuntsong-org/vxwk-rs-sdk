use base64::Engine;
use base64::{alphabet, engine, read, write};
use model::livecodefile::{UpdateFileReq, UpdateLiveCodeNameReq};
use reqwest::header::ToStrError;
use reqwest::Response;
use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;
use urand::generate_unique_number;
use url::ParseError;
use url::Url;
use url::form_urlencoded;
///  这里是Vxwk项目对外开放的所有Api 
/// 简单使用案列
/// ```
///     use std::collections::HashMap;

/// use tokio::runtime;
/// use crate::VxwkConfig;
/// pub fn main(){
///     let confg = VxwkConfig{
///         access_key: "开放者access_key".to_string(),
///         access_secret: "开放者access_secret".to_owned(),
///         endpoint: "节点baseutl".to_string(),
///     };
///     let vxwk_api = super::VxwkAPI::new(confg);
///     let runtime = tokio::runtime::Runtime::new().unwrap();
///     runtime.block_on(async{
///         let res = vxwk_api.short_link_list(HashMap::new()).await;
///         println!("{:?}",res);
///     });
/// }```
pub struct VxwkAPI {
    client: reqwest::Client,
    config: VxwkConfig,
    accept_header: Option<HashMap<String, String>>,
}

mod model {
    pub(crate) mod livecodefile {
        use serde::Serialize;
        #[derive(Debug, Serialize)]
        pub struct UpdateFileReq {
            pub file: String,
            pub name: String,
        }
        #[derive(Debug, Serialize)]
        pub struct UpdateLiveCodeNameReq {
            pub fid: String,
            pub name: String,
        }
    }
}

mod timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    pub fn get_timestamp() -> u64 {
        // 获取当前时间
        let current_time = SystemTime::now();
        // 计算与UNIX纪元的时间间隔
        let duration = current_time
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!");
        // 获取时间戳（以秒为单位）
        let timestamp = duration.as_secs();

        timestamp
    }
}

mod uhmac {
    use hmac::{Hmac, Mac};

    type HmacSha1 = Hmac<sha1::Sha1>;

    pub fn calculate_hmac(key: &str, data: &str) -> String {
        let mut mac = HmacSha1::new_from_slice(key.as_bytes()).unwrap();
        mac.update(data.as_bytes());
        let result = mac.finalize();
        let code = result.into_bytes();
        let hmac_base64 =
            base64::engine::Engine::encode(&base64::engine::general_purpose::STANDARD, &code);
        hmac_base64
    }
}

mod urand {
    use rand::Rng;

    pub fn generate_unique_number(n: i32) -> String {
        let numbers = "0123456789";
        let mut rng = rand::thread_rng();
        let unique_number: String = (0..n)
            .map(|_| {
                numbers
                    .chars()
                    .nth(rng.gen_range(0..numbers.len()))
                    .unwrap()
            })
            .collect();
        unique_number
    }

    #[cfg(test)]
    mod test {
        #[test]
        fn test_generate_unique_number() {
            let rns = super::generate_unique_number(18);
            println!("生成18位随机数:{}", rns);
        }
    }
}

fn get_query(query: HashMap<&str, &str>) -> String {
    let mut target: Vec<_> = query.into_iter().collect();
    target.sort_by(|a, b| a.0.cmp(b.0));
    let encoded_query: String = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(target)
        .finish();

    encoded_query
}

#[derive(Debug, Clone)]
pub struct VxwkConfig {
    pub access_key: String,
    pub access_secret: String,
    pub endpoint: String,
}

#[derive(Debug, Error)]
pub enum VxwkError {
    #[error("http request error")]
    ReqwestError(#[from] reqwest::Error),
    #[error("url parse error")]
    ParseError(#[from] ParseError),
    #[error("Url To Str Error")]
    ToStrError(#[from] ToStrError),
    #[error("Unkonow error `{0}` ")]
    OtherError(String),
    #[error("Invalid response `{0}`")]
    InvalidResponse(String),
    #[error("Invalid Request `{0}`")]
    InvalidRequest(String),
    #[error("the data for key `{0}`")]
    InvalidAccessKey(String),
    #[error("the data for key `{0}`")]
    InvalidAccessSecret(String),
    #[error("Invalid Endpoint `{0}`")]
    InvalidEndpoint(String),
}

impl VxwkConfig {
    pub fn new(access_key: String, access_secret: String, endpoint: String) -> Self {
        Self {
            access_key,
            access_secret,
            endpoint,
        }
    }
}



impl VxwkAPI {
    pub fn new(config: VxwkConfig) -> Self {
        let client = reqwest::Client::new();
        let accept_header = Some(HashMap::from([(
            String::from("Accept"),
            String::from("application/json"),
        )]));
        Self {
            client,
            config,
            accept_header,
        }
    }
    fn gen_signature(
        &self,
        timestamp: &str,
        n: &str,
        path: &str,
        query: HashMap<&str, &str>,
    ) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n",
            reqwest::Method::GET,
            &self.config.access_key,
            timestamp,
            n,
            path,
            get_query(query)
        )
    }

    /// 用于发送GET请求
    async fn get(
        &self,
        path: &str,
        query_params: HashMap<&str, &str>,
    ) -> Result<Response, VxwkError> {
        // 构建完整的URL
        let mut url = Url::parse(&self.config.endpoint)?;
        url.set_path(path);
        url.query_pairs_mut().extend_pairs(query_params.iter());

        // 构建签名所需的参数
        let timestamp = format!("{}", timestamp::get_timestamp());
        let unique_number = generate_unique_number(18);

        let mut signature_params = query_params.clone();
        signature_params.insert("xaccesskey", self.config.access_key.as_str());
        signature_params.insert("xn", &unique_number);
        signature_params.insert("xtimestamp", &timestamp);
        signature_params.insert("xrunmode", "release");

        let signature =
            self.gen_signature(&timestamp, &unique_number, path, signature_params.clone());
        signature_params.insert("xsignature", &signature);

        let sign = uhmac::calculate_hmac(&self.config.access_secret, &signature);
        signature_params.insert("xsign", &sign);

        // 添加签名到URL
        url.query_pairs_mut().extend_pairs(signature_params.iter());

        // 发起GET请求
        let response = self.client.get(url).send().await?;

        // 获取响应体
        match response.error_for_status_ref() {
            Ok(_) => Ok(response),
            Err(err) => {
                log::error!("Error: {}", err);
                Err(VxwkError::from(err))
            }
        }
    }
    /// 用于发送POST请求
    async fn post<T>(&self, path: &str, body: &T) -> Result<serde_json::Value, VxwkError>
    where
        T: Serialize,
    {
        let mut url = self.config.endpoint.clone();
        url.push_str(path);

        let timestamp = format!("{}", timestamp::get_timestamp());
        let unique_number = generate_unique_number(18);

        let mut query_params = HashMap::new();
        query_params.insert("xaccesskey", self.config.access_key.as_str());
        query_params.insert("xn", &unique_number);
        query_params.insert("xtimestamp", timestamp.as_str());
        query_params.insert("xrunmode", "release");

        let signature = self.gen_signature(
            timestamp.as_str(),
            unique_number.as_str(),
            path,
            query_params.clone(),
        );
        query_params.insert("xsignature", signature.as_str());

        let sign = uhmac::calculate_hmac(&self.config.access_secret, &signature);
        query_params.insert("xsign", sign.as_str());

        // 构建URL
        let url_with_params = Url::parse_with_params(&url, query_params)?;

        // 发起POST请求
        let response = self.client.post(url_with_params).json(body).send().await?;

        // 获取响应体
        match response.error_for_status_ref() {
            Ok(_) => Ok(response.json().await?),
            Err(err) => {
                log::error!("Error: {}", err);
                Err(VxwkError::from(err))
            }
        }
    }

    //抖音卡片
    pub async fn dy_card_img_url(
        &self,
        id: &str,
        opt: Option<HashMap<&str, &str>>,
    ) -> Result<String, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("projectid", id);
        if let Some(opt_map) = opt {
            // 如果有传入的Option参数，将其合并到query_params中
            query_params.extend(opt_map.iter().map(|(k, v)| (k, v)));
        }
        let result = self.get("/api/v1/user/carddy/img", query_params).await?;
        let file_url = result.headers().get("Location");
        if let Some(file_url) = file_url {
            return Ok(file_url.to_str().unwrap().to_string());
        }
        Err(VxwkError::InvalidRequest("get url fail".into()))
    }
    /// 抖音卡片列表
    pub async fn dy_card_get_list(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.get("/api/v1/user/carddy/list", opt).await?;
        return Ok(result.json().await?);
    }
    /// 抖音卡片详情
    pub async fn dy_card_get_info(
        &self,
        id: &str,
        opt: Option<HashMap<&str, &str>>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        if let Some(opt_map) = opt {
            // 如果有传入的Option参数，将其合并到query_params中
            query_params.extend(opt_map.iter().map(|(k, v)| (k, v)));
        }
        let result = self.get("/api/v1/user/carddy", query_params).await?;
        return Ok(result.json().await?);
    }
    /// 抖音卡片创建
    pub async fn dy_card_create(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.post("/api/v1/user/carddy", &opt).await?;
        return Ok(result);
    }

    /// 抖音卡片修改
    pub async fn dy_card_update(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/carddy/update", &query_params)
            .await?;
        return Ok(result);
    }
    /// 抖音卡片删除
    pub async fn dy_card_delete(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/carddy/delete", &query_params)
            .await?;
        return Ok(result);
    }
    ///微信卡片
    pub async fn wx_card_img_url(
        &self,
        id: &str,
        opt: Option<HashMap<&str, &str>>,
    ) -> Result<String, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("projectid", id);
        if let Some(opt_map) = opt {
            // 如果有传入的Option参数，将其合并到query_params中
            query_params.extend(opt_map.iter().map(|(k, v)| (k, v)));
        }
        let result = self.get("/api/v1/user/wxcard/img", query_params).await?;
        let file_url = result.headers().get("Location");
        if let Some(file_url) = file_url {
            return Ok(file_url.to_str().unwrap().to_string());
        }
        Err(VxwkError::InvalidRequest("get url fail".into()))
    }
    /// 微信卡片详情
    pub async fn wx_card_list(
        &self,
        opt_map: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.get("/api/v1/user/wxcard", opt_map).await?;
        return Ok(result.json().await?);
    }
    /// 创建微信卡片
    pub async fn wx_card_create(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.post("/api/v1/user/wxcard", &opt).await?;
        return Ok(result);
    }
    /// 更新微信卡片
    pub async fn wx_card_update(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/wxcard/update", &query_params)
            .await?;
        return Ok(result);
    }
    /// 删除微信卡片
    pub async fn wx_card_delete(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/wxcard/delete", &query_params)
            .await?;
        return Ok(result);
    }

    /// 获取微信卡片详情
    pub async fn wx_card_info(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self.get("/api/v1/user/cardwx", query_params).await?;
        return Ok(result.json().await?);
    }
    //// 活码
    ///  获取活码列表
    pub async fn live_code_list(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.get("/api/v1/user/livecode/list", opt).await?;
        return Ok(result.json().await?);
    }
    /// 创建活码
    pub async fn live_code_create(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.post("/api/v1/user/livecode/create", &opt).await?;
        return Ok(result);
    }
    /// 更新活码信息
    pub async fn live_code_update(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/livecode/update", &query_params)
            .await?;
        return Ok(result);
    }
    /// 删除活码
    pub async fn live_code_delete(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/livecode/delete", &query_params)
            .await?;
        return Ok(result);
    }
    /// 查询活码信息
    pub async fn live_code_info(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/livecode/info", &query_params)
            .await?;
        return Ok(result);
    }
    /// 活码文件
    /// 获取活码文件列表
    pub async fn live_code_file_url_list(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.get("/api/v1/user/livecode/file/list", opt).await?;
        return Ok(result.json().await?);
    }
    /// 获取活码文件url
    pub async fn live_code_file_url(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self.get("/api/v1/user/livecode/file", query_params).await?;
        return Ok(result.json().await?);
    }
    /// 上传文件
    pub async fn live_code_file_upload(
        &self,
        file: Vec<u8>,
        name: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let engine = engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD);
        let file_base64 = engine.encode(file);
        let req = UpdateFileReq {
            file: format!("base64:{}", file_base64),
            name: name.to_owned(),
        };
        let result = self.post("/api/v1/user/livecode/file/update", &req).await?;
        return Ok(result);
    }

    /// 修改活码名称
    pub async fn live_code_file_name_update(
        &self,
        id: &str,
        name: &str,
    ) -> Result<serde_json::Value, VxwkError> {
        let req = UpdateLiveCodeNameReq {
            fid: id.to_string(),
            name: name.to_owned(),
        };
        let result = self
            .post("/api/v1/user/livecode/file/name/update", &req)
            .await?;
        return Ok(result);
    }

    //删除活码
    pub async fn live_code_file_delete(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/livecode/file/delete", &query_params)
            .await?;
        return Ok(result);
    }
    ///外链
    /// 查询外联显示logo
    pub async fn external_logo_url(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<String, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("projectid", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self.get("/api/v1/admin/external/img", query_params).await?;
        let file_url = &result.headers().get("Location");
        if let Some(file_url) = file_url {
            return Ok(file_url.to_str()?.to_string());
        }
        Err(VxwkError::InvalidRequest("get url fail".into()))
    }

    /// 外链列表
    pub async fn external_url_list(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.get("/api/v1/user/external/list", opt).await?;
        return Ok(result.json().await?);
    }

    /// 获取外链详情
    pub async fn external_url_info(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self.get("/api/v1/user/external", query_params).await?;
        return Ok(result.json().await?);
    }

    /// 添加外链
    /// ```
    /// {
    ///   "domainID": "some-uuid-string",
    ///   "title": "ShortLinkTitle",
    ///   "describe": "ShortLinkDescription",
    ///   "tips": "OptionalTips",
    ///   "img": null,
    ///   "type": 1,
    ///   "startAt": 0,
    ///   "stopAt": 0,
    ///   "link": [],
    ///   "hash": "HashValue",
    ///   "testMode": true,
    ///   "style": "SomeStyle"
    /// }
    /// ```
    // 请注意：
    // - "domainID" 是一个 UUID 字符串，所以需要按照 UUID 的格式提供。
    // - "title" 最大长度为 20。
    // - "describe" 最大长度为 100。
    // - "tips" 最大长度为 100，是可选的。
    // - "img" 是可选的，这里设置为 `null`。
    // - "type" 是一个整数。
    // - "startAt" 和 "stopAt" 是可选的，设置为 0。
    // - "link" 是一个数组，这里为空数组。
    // - "hash" 最大长度为 100，是可选的。
    // - "testMode" 是一个布尔值。
    // - "style" 需要符合 "Style" 的格式。
    pub async fn external_url_create(
        &self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.post("/api/v1/user/external/create", &opt).await?;
        return Ok(result);
    }

    /// 修改外联
    pub async fn external_url_update(&self,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let result = self.post("/api/v1/user/external/update", &opt).await?;
        return Ok(result);
    }

    ///外链删除
    pub async fn external_url_logo_delete(
        &self,
        id: &str,
        opt: HashMap<&str, &str>,
    ) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/external/delete", &query_params)
            .await?;
        return Ok(result);
    }

    /// 以下部分为短链相关api
    /// 生成短连接
    pub async fn short_link_list(&self,opt: HashMap<&str, &str>)-> Result<serde_json::Value, VxwkError>{
        let result = self.get("/api/v1/user/shortlink/list", opt).await?;
        return Ok(result.json().await?);
    }
    
    /// 获取短连接详情
    pub async fn short_link_detail(&self, id: &str, opt: HashMap<&str, &str>) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .get("/api/v1/user/shortlink", query_params)
            .await?;
        return Ok(result.json().await?);
    }
    /// 创建新的短链
    pub async fn short_link_create(&self, opt: HashMap<&str, &str>) -> Result<serde_json::Value, VxwkError> {
        let result = self.post("/api/v1/user/shortlink/create", &opt).await?;
        return Ok(result);
    }

    /// 更新短链
    pub async fn short_link_update(&self, id: &str, opt: HashMap<&str, &str>) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        query_params.extend(opt.iter().map(|(k, v)| (k, v)));
        let result = self
            .post("/api/v1/user/shortlink/update", &query_params)
            .await?;
        return Ok(result);
    }


    /// 删除短链
    /// 
    pub async fn short_link_delete(&self, id: &str) -> Result<serde_json::Value, VxwkError> {
        let mut query_params = HashMap::new();
        query_params.insert("id", id);
        let result = self
            .post("/api/v1/user/shortlink/delete", &query_params)
            .await?;
        return Ok(result);
    }
}
