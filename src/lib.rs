use std::collections::HashMap;

use reqwest::Request;
use tokio::signal;
use urand::generate_unique_number;

//模块
mod urand;
mod timestamp;
mod uhmac;
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
pub struct VxwkConfig{
    pub access_key:String,
    pub access_secret:String,
    pub endpoint:String
}

pub enum  VxwkError {
    ReqwestError(reqwest::Error),
    OtherError(String),
    InvalidResponse(String),
    InvalidRequest(String),
    InvalidSignature(String),
    InvalidTimestamp(String),
    InvalidAccessKey(String),
    InvalidAccessSecret(String),
    InvalidEndpoint(String),
    InvalidQuery(String),
    InvalidBody(String),
    InvalidHeader(String),
    InvalidContentType(String),
    InvalidContentLength(String),
    InvalidContentMD5(String),
}

impl VxwkConfig{
    pub fn new( access_key:String,access_secret:String, endpoint:String)->Self{
        Self { access_key, access_secret, endpoint }
    }
}



pub struct  VxwkAPI {
    client: reqwest::Client,
    config: VxwkConfig,
    accept_header: Option<HashMap<String,String>>,
}

// fn get_auth_header(config:&VxwkConfig)->HashMap<String,String>{
//     let mut header = HashMap::new();
//     header.insert(String::from("Authorization"),format!("Bearer {}
// }



impl VxwkAPI {
    pub fn new(config:VxwkConfig)->Self{
        let client = reqwest::Client::new();
        let accept_header = Some(HashMap::from([(String::from("Accept"),String::from("application/json"))]));
        Self { client, config, accept_header }
    }
    fn gen_signature(&self, timestamp:&str, n:&str, path:&str, query:HashMap<&str,&str>)->String{
         format!("{}\n{}\n{}\n{}\n{}\n{}\n", reqwest::Method::GET, &self.config.access_key, timestamp, n, path, get_query(query))
    }

    /// 用于发送get请求到
    async fn get(&self, path:&str,query_params:HashMap<&str,&str>) -> Result<serde_json::Value, reqwest::Error>{
        let mut url = self.config.endpoint.clone();
        url.push_str(path);

        let timestamp = format!("{}",timestamp::get_timestamp());

        let unique_number = generate_unique_number(18);

        let mut  query_build = query_params;
        query_build.insert("xaccesskey",self.config.access_key.as_str());
        query_build.insert("xn",&unique_number);
        query_build.insert("xtimestamp",timestamp.as_str());
        query_build.insert("xrunmode","release");
        
        let signature = self.gen_signature(timestamp.as_str(),unique_number.as_str(),path,query_build.clone());
       
        query_build.insert("xsignature",signature.as_str());

        let sign = uhmac::calculate_hmac(&self.config.access_secret, &signature);

        query_build.insert("xsign", sign.as_str());
    
        //发起get请求
        let response = self.client.get(url)
        .query(&query_build)
        .send().await?;

        //获取响应体
        match response.error_for_status_ref() {
            Ok(_) => Ok(response.json().await?),
            Err(err) => {
                log::error!("Error: {}", err);
                Err(err)
            }
        }
    }

}