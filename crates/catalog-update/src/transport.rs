use crate::{Error, Result};
use std::{io::Read, time::Duration};

pub trait Source {
    fn download(&self, limit: usize) -> Result<Vec<u8>>;
}
/// Build-owned exact HTTPS URL. No cookies, proxy credentials, redirects or machine metadata.
pub struct HttpsSource {
    url: reqwest::Url,
}
impl HttpsSource {
    pub fn new(url: &str) -> Result<Self> {
        let url = reqwest::Url::parse(url).map_err(|_| Error::Unconfigured)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Unconfigured);
        }
        Ok(Self { url })
    }
}
impl Source for HttpsSource {
    fn download(&self, limit: usize) -> Result<Vec<u8>> {
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Transport)?;
        let response = client
            .get(self.url.clone())
            .send()
            .map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Transport);
        }
        if response
            .content_length()
            .is_some_and(|size| size > limit as u64)
        {
            return Err(Error::Bounds);
        }
        let mut bytes = Vec::new();
        response
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Transport)?;
        if bytes.len() > limit {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }
}
