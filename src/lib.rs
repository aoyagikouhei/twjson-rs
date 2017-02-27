extern crate hyper;
extern crate oauthcli;
extern crate url;
extern crate json;
extern crate hyper_native_tls;

use std::fmt;
use std::io::Read;
use url::{percent_encoding, Url};
use oauthcli::{OAuthAuthorizationHeaderBuilder, SignatureMethod};
use std::borrow::Cow;
use hyper::Client;
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;

#[derive(Debug)]
pub enum TwitterError {
    Json(json::Error),
    Hyper(hyper::error::Error),
    Io(std::io::Error)
}

impl fmt::Display for TwitterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TwitterError::Json(ref err) => err.fmt(f),
            TwitterError::Hyper(ref err) => err.fmt(f),
            TwitterError::Io(ref err) => err.fmt(f),
        }
    }
}

impl std::error::Error for TwitterError {
    fn description(&self) -> &str {
        match *self {
            TwitterError::Json(ref err) => err.description(),
            TwitterError::Hyper(ref err) => err.description(),
            TwitterError::Io(ref err) => err.description(),
        }
    }
}

impl From<json::Error> for TwitterError {
    fn from(err: json::Error) -> TwitterError {
        TwitterError::Json(err)
    }
}

impl From<hyper::error::Error> for TwitterError {
    fn from(err: hyper::error::Error) -> TwitterError {
        TwitterError::Hyper(err)
    }
}

impl From<std::io::Error> for TwitterError {
    fn from(err: std::io::Error) -> TwitterError {
        TwitterError::Io(err)
    }
}

pub type TwitterResult = Result<json::JsonValue, TwitterError>;

pub const SEARCH_TWEETS: &'static str = "https://api.twitter.com/1.1/search/tweets.json";
pub const STATUSES_UPDATE: &'static str = "https://api.twitter.com/1.1/statuses/update.json";

pub struct TwitterClient<'a>
{
    consumer_key: Cow<'a, str>,
    consumer_secret: Cow<'a, str>,
    access_key: Cow<'a, str>,
    access_secret: Cow<'a, str>,
}

impl<'a> TwitterClient<'a>
{
    pub fn new(
        consumer_key: &'a str,
        consumer_secret: &'a str,
        access_key: &'a str,
        access_secret: &'a str
    ) -> TwitterClient<'a> 
    {
        TwitterClient {
            consumer_key: consumer_key.into(),
            consumer_secret: consumer_secret.into(),
            access_key: access_key.into(),
            access_secret: access_secret.into()
        }
    }

    pub fn get(
        &self,
        url: &str, 
        parameters: Option<&Vec<(&str, &str)>>,
    )
        -> TwitterResult 
    {
        let url = format!("{}{}", url, create_query(parameters, Some('?')));
        let url = Url::parse(&url).unwrap();
    
        let auth_header = OAuthAuthorizationHeaderBuilder::new(
            "GET", 
            &url, 
            self.consumer_key.clone(),
            self.consumer_secret.clone(), 
            SignatureMethod::HmacSha1)
            .token(
                self.access_key.clone(),
                self.access_secret.clone())
            .finish_for_twitter();
        let mut auth_header_str = String::from("Authorization: OAuth ");
        auth_header_str.push_str(&auth_header.to_string());
        
        let mut res = String::new();
        make_client().get(url)
            .header(hyper::header::Authorization(auth_header_str))
            .send()
            .unwrap()
            .read_to_string(&mut res)?;
        Ok(json::parse(&res)?)
    }

    pub fn post(
        &self,
        url: &str, 
        parameters: Vec<(&str, &str)>,
    )
        -> TwitterResult 
    {
        let url = Url::parse(url).unwrap();
        let body = create_query(Some(&parameters), None);
        let auth_header = OAuthAuthorizationHeaderBuilder::new(
            "POST", 
            &url, 
            self.consumer_key.clone(), 
            self.consumer_secret.clone(), 
            SignatureMethod::HmacSha1)
            .token(
                self.access_key.clone(), 
                self.access_secret.clone())
            .request_parameters(parameters.into_iter())
            .finish_for_twitter();
        let mut auth_header_str = String::from("Authorization: OAuth ");
        auth_header_str.push_str(&auth_header.to_string());
        
        let content: hyper::mime::Mime = "application/x-www-form-urlencoded".parse().unwrap();
        let mut res = String::new();
        let _ = make_client().post(url)
            .header(hyper::header::Authorization(auth_header_str))
            .header(hyper::header::ContentType(content))
            .body(body.as_bytes())
            .send()
            .unwrap()
            .read_to_string(&mut res)?;
        Ok(json::parse(&res)?)
    }
}

fn make_client() -> Client {
    let ssl = NativeTlsClient::new().unwrap();
    let connector = HttpsConnector::new(ssl);
    Client::with_connector(connector)
}

fn create_query(
    parameters: Option<&Vec<(&str, &str)>>,
    first_char: Option<char>
) -> String
{
    let prms = match parameters {
        None => return String::from(""),
        Some(p) => p
    };

    use std::fmt::Write;

    let es = oauthcli::OAUTH_ENCODE_SET;
    let mut s = String::new();
    for pairs in prms {
        if s.len() > 0 {
            s.push('&');
        }
        write!(
            &mut s,
            "{}={}",
            percent_encoding::utf8_percent_encode(pairs.0, es),
            percent_encoding::utf8_percent_encode(pairs.1, es)
        ).unwrap();
    }
    if s.len() > 0 {
        match first_char {
            None => {},
            Some(ch) => s.insert(0, ch),
        };
    }
    s
}