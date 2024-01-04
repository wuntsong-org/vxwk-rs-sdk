use std::collections::HashMap;

use reqwest::Request;
use serde::Serialize;
use thiserror::Error;
use tokio::signal;
use urand::generate_unique_number;
use url::ParseError;
use url::Url;
//模块
mod timestamp;
mod uhmac;
mod urand;
use url::form_urlencoded;

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

pub struct VxwkAPI {
    client: reqwest::Client,
    config: VxwkConfig,
    accept_header: Option<HashMap<String, String>>,
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
    ) -> Result<serde_json::Value, VxwkError> {
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
            Ok(_) => Ok(response.json().await?),
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


}
