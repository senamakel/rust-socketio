use adler32::adler32;
use async_stream::try_stream;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use http::HeaderMap;
use native_tls::TlsConnector;
use reqwest::{redirect::Policy, Client, ClientBuilder, Method, Response};
use std::fmt::Debug;
use std::time::SystemTime;
use std::{
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::RwLock;
use url::Url;

use crate::asynchronous::generator::StreamGenerator;
use crate::asynchronous::RedirectMetadata;
use crate::asynchronous::{ensure_query_param, redirect_target_error};
use crate::{asynchronous::transport::AsyncTransport, error::Result, Error};

/// An asynchronous polling type. Makes use of the nonblocking reqwest types and
/// methods.
#[derive(Clone)]
pub struct PollingTransport {
    client: Client,
    base_url: Arc<RwLock<Url>>,
    redirects: Arc<StdMutex<Vec<RedirectMetadata>>>,
    generator: StreamGenerator<Bytes>,
    opening_headers: Option<HeaderMap>,
    credential_origin: Url,
    credentials_present: bool,
    redirect_budget: usize,
}

#[derive(Clone)]
struct RedirectContext {
    opening_headers: Option<HeaderMap>,
    credential_origin: Url,
    credentials_present: bool,
    redirects: Arc<StdMutex<Vec<RedirectMetadata>>>,
    budget: usize,
}

fn credential_bearing_headers(headers: &Option<HeaderMap>) -> bool {
    headers.as_ref().is_some_and(|headers| {
        headers.contains_key(http::header::AUTHORIZATION)
            || headers.contains_key(http::header::COOKIE)
            || headers.contains_key(http::header::PROXY_AUTHORIZATION)
    })
}

impl PollingTransport {
    pub fn new(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        opening_headers: Option<HeaderMap>,
    ) -> Self {
        Self::new_with_redirect_budget(base_url, tls_config, opening_headers, 3)
    }

    pub(crate) fn new_with_credentials(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        opening_headers: Option<HeaderMap>,
        credentials_present: bool,
    ) -> Self {
        Self::new_with_redirect_budget_and_credentials(
            base_url,
            tls_config,
            opening_headers,
            3,
            credentials_present,
        )
    }

    pub(crate) fn new_with_redirect_budget(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        opening_headers: Option<HeaderMap>,
        redirect_budget: usize,
    ) -> Self {
        Self::new_with_redirect_budget_and_credentials(
            base_url,
            tls_config,
            opening_headers,
            redirect_budget,
            false,
        )
    }

    pub(crate) fn new_with_redirect_budget_and_credentials(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        opening_headers: Option<HeaderMap>,
        redirect_budget: usize,
        credentials_present: bool,
    ) -> Self {
        let mut url = base_url;
        ensure_query_param(&mut url, "transport", "polling");
        let original_url = url.clone();
        let redirect_log = Arc::new(StdMutex::new(Vec::<RedirectMetadata>::new()));
        let mut client_builder = ClientBuilder::new().redirect(Policy::none());
        if let Some(config) = tls_config {
            client_builder = client_builder.use_preconfigured_tls(config);
        }
        let client = client_builder.build().unwrap();
        let base_url = Arc::new(RwLock::new(url.clone()));
        let redirect_context = RedirectContext {
            opening_headers: opening_headers.clone(),
            credential_origin: original_url.clone(),
            credentials_present,
            redirects: redirect_log.clone(),
            budget: redirect_budget,
        };

        PollingTransport {
            client: client.clone(),
            base_url: base_url.clone(),
            redirects: redirect_log.clone(),
            generator: StreamGenerator::new(Self::stream(url, client, base_url, redirect_context)),
            opening_headers,
            credential_origin: original_url,
            credentials_present,
            redirect_budget,
        }
    }

    fn address(mut url: Url) -> Result<Url> {
        let reader = format!("{:#?}", SystemTime::now());
        let hash = adler32(reader.as_bytes()).unwrap();
        url.query_pairs_mut().append_pair("t", &hash.to_string());
        Ok(url)
    }

    // Keep the existing public Error type intact; this internal request helper
    // can produce its established, relatively large tungstenite error variant.
    #[allow(clippy::result_large_err)]
    async fn send_request(
        mut url: Url,
        client: Client,
        redirect_context: RedirectContext,
        mut method: Method,
        mut body: Option<Bytes>,
    ) -> Result<Response> {
        let mut hops = 0;
        loop {
            let mut request = client.request(method.clone(), url.clone());
            if let Some(mut headers) = redirect_context.opening_headers.clone() {
                if url.origin() != redirect_context.credential_origin.origin() {
                    headers.remove(http::header::AUTHORIZATION);
                    headers.remove(http::header::COOKIE);
                    headers.remove(http::header::PROXY_AUTHORIZATION);
                }
                request = request.headers(headers);
            }
            if let Some(payload) = body.clone() {
                request = request.body(payload);
            }
            let response = request.send().await?;
            if !matches!(response.status().as_u16(), 301 | 302 | 307 | 308) {
                return Ok(response);
            }
            if hops >= redirect_context.budget {
                return Err(Error::InvalidHandshake(
                    "redirect hop limit exceeded".into(),
                ));
            }
            let location = response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| Error::InvalidHandshake("redirect missing Location".into()))?;
            let from = response.url().clone();
            let to = from.join(location)?;
            if !matches!(to.scheme(), "http" | "https") {
                return Err(Error::InvalidUrlScheme(to.scheme().to_owned()));
            }
            if (redirect_context.credentials_present
                || credential_bearing_headers(&redirect_context.opening_headers)
                || !redirect_context.credential_origin.username().is_empty()
                || redirect_context.credential_origin.password().is_some())
                && redirect_target_error(&from, &to, true).is_some()
            {
                return Err(Error::InvalidHandshake(
                    "refusing credential-bearing TLS downgrade".into(),
                ));
            }
            if let Ok(mut items) = redirect_context.redirects.lock() {
                items.push(RedirectMetadata {
                    status: response.status().as_u16(),
                    from,
                    to: to.clone(),
                });
            }
            hops += 1;
            if matches!(response.status().as_u16(), 301 | 302) && method == Method::POST {
                method = Method::GET;
                body = None;
            }
            url = to;
        }
    }

    fn send_request_stream(
        url: Url,
        client: Client,
        redirect_context: RedirectContext,
    ) -> impl Stream<Item = Result<Response>> {
        try_stream! {
            let address = Self::address(url);
            yield Self::send_request(address?, client, redirect_context, Method::GET, None).await?
        }
    }

    fn stream(
        mut url: Url,
        client: Client,
        base_url: Arc<RwLock<Url>>,
        redirect_context: RedirectContext,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + 'static + Send>> {
        Box::pin(try_stream! {
            loop {
                for await elem in Self::send_request_stream(url.clone(), client.clone(), redirect_context.clone()) {
                let response = elem?;
                if !response.status().is_success() {
                    Err(Error::IncompleteHttp(response.status().as_u16()))?;
                }
                let query = response
                    .url()
                    .query_pairs()
                    .filter(|(key, _)| key != "t")
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>();
                url = response.url().clone();
                url.set_query(None);
                url.query_pairs_mut().extend_pairs(query);
                *base_url.write().await = url.clone();
                for await bytes in response.bytes_stream() {
                        yield bytes?;
                    }
                }
            }
        })
    }
}

impl Stream for PollingTransport {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.generator.poll_next_unpin(cx)
    }
}

#[async_trait]
impl AsyncTransport for PollingTransport {
    async fn emit(&self, data: Bytes, is_binary_att: bool) -> Result<()> {
        let data_to_send = if is_binary_att {
            // the binary attachment gets `base64` encoded
            let mut packet_bytes = BytesMut::with_capacity(data.len() + 1);
            packet_bytes.put_u8(b'b');

            let encoded_data = general_purpose::STANDARD.encode(data);
            packet_bytes.put(encoded_data.as_bytes());

            packet_bytes.freeze()
        } else {
            data
        };

        let status = Self::send_request(
            self.address().await?,
            self.client.clone(),
            RedirectContext {
                opening_headers: self.opening_headers.clone(),
                credential_origin: self.credential_origin.clone(),
                credentials_present: self.credentials_present,
                redirects: self.redirects.clone(),
                budget: self.redirect_budget,
            },
            Method::POST,
            Some(data_to_send),
        )
        .await?
        .status()
        .as_u16();

        if status != 200 {
            let error = Error::IncompleteHttp(status);
            return Err(error);
        }

        Ok(())
    }

    async fn base_url(&self) -> Result<Url> {
        Ok(self.base_url.read().await.clone())
    }

    async fn set_base_url(&self, base_url: Url) -> Result<()> {
        let mut url = base_url;
        if !url
            .query_pairs()
            .any(|(k, v)| k == "transport" && v == "polling")
        {
            url.query_pairs_mut().append_pair("transport", "polling");
        }
        *self.base_url.write().await = url;
        Ok(())
    }

    fn redirect_metadata(&self) -> Vec<RedirectMetadata> {
        self.redirects
            .lock()
            .map(|redirects| redirects.clone())
            .unwrap_or_default()
    }
}

impl Debug for PollingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PollingTransport")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use crate::asynchronous::transport::AsyncTransport;

    use super::*;
    use futures_util::StreamExt;
    use std::str::FromStr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn polling_transport_base_url() -> Result<()> {
        let url = crate::test::engine_io_server()?.to_string();
        let transport = PollingTransport::new(Url::from_str(&url[..]).unwrap(), None, None);
        assert_eq!(
            transport.base_url().await?.to_string(),
            url.clone() + "?transport=polling"
        );
        transport
            .set_base_url(Url::parse("https://127.0.0.1")?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "https://127.0.0.1/?transport=polling"
        );
        assert_ne!(transport.base_url().await?.to_string(), url);

        transport
            .set_base_url(Url::parse("http://127.0.0.1/?transport=polling")?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "http://127.0.0.1/?transport=polling"
        );
        assert_ne!(transport.base_url().await?.to_string(), url);
        Ok(())
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        let mut chunk = [0; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(
                count, 0,
                "fixture peer closed before sending request headers"
            );
            request.extend_from_slice(&chunk[..count]);
        }
    }

    #[tokio::test]
    async fn follows_relative_redirects_with_supported_statuses_and_reports_metadata() {
        for status in [301, 302, 307, 308] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut redirect_stream, _) = listener.accept().await.unwrap();
                read_request(&mut redirect_stream).await;
                let redirect = format!(
                    "HTTP/1.1 {status} Redirect\r\nLocation: /resolved/socket.io/?EIO=4&transport=polling&keep=yes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                redirect_stream
                    .write_all(redirect.as_bytes())
                    .await
                    .unwrap();
                drop(redirect_stream);

                let (mut final_stream, _) = listener.accept().await.unwrap();
                read_request(&mut final_stream).await;
                let body = "0{\"sid\":\"redirected\",\"upgrades\":[],\"pingInterval\":60000,\"pingTimeout\":60000,\"maxPayload\":1000000}";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                final_stream.write_all(response.as_bytes()).await.unwrap();
            });

            let original = Url::parse(&format!(
                "http://{address}/initial/socket.io/?EIO=4&transport=polling"
            ))
            .unwrap();
            let mut transport = PollingTransport::new(original, None, None);
            let payload = transport.next().await.unwrap().unwrap();
            assert!(String::from_utf8_lossy(&payload).contains("redirected"));
            let final_url = transport.base_url().await.unwrap();
            assert_eq!(final_url.path(), "/resolved/socket.io/");
            assert!(final_url
                .query_pairs()
                .any(|(key, value)| key == "keep" && value == "yes"));
            let redirects = transport.redirect_metadata();
            assert_eq!(redirects.len(), 1);
            assert_eq!(redirects[0].status, status);
            assert_eq!(redirects[0].from.path(), "/initial/socket.io/");
            assert_eq!(redirects[0].to.path(), "/resolved/socket.io/");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn polling_redirect_chain_stops_after_three_hops() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for hop in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: /hop{}/socket.io/?EIO=4&transport=polling\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    hop + 1
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let url = Url::parse(&format!("http://{address}/start/socket.io/")).unwrap();
        let mut transport = PollingTransport::new(url, None, None);
        assert!(transport.next().await.unwrap().is_err());
        assert_eq!(transport.redirect_metadata().len(), 3);
        server.await.unwrap();
    }

    #[test]
    fn redirect_validation_rejects_local_tls_downgrade_to_remote_plaintext() {
        let remote = Url::parse("http://remote.example/socket.io/").unwrap();
        for local_tls in [
            "https://localhost/socket.io/",
            "https://127.0.0.1/socket.io/",
            "https://[::1]/socket.io/",
        ] {
            let local_tls = Url::parse(local_tls).unwrap();
            assert_eq!(
                redirect_target_error(&local_tls, &remote, true),
                Some("refusing credential-bearing TLS downgrade"),
                "credential-bearing redirect from {local_tls} to remote plaintext must be rejected"
            );
        }
    }

    #[test]
    fn redirect_validation_rejects_unsupported_schemes_and_remote_credential_downgrade() {
        let from = Url::parse("https://service.example/socket.io/").unwrap();
        let plaintext = Url::parse("http://service.example/socket.io/").unwrap();
        let unsupported = Url::parse("file:///tmp/socket.io/").unwrap();
        assert_eq!(
            redirect_target_error(&from, &unsupported, false),
            Some("unsupported redirect scheme")
        );
        assert_eq!(
            redirect_target_error(&from, &plaintext, true),
            Some("refusing credential-bearing TLS downgrade")
        );
        assert_eq!(redirect_target_error(&from, &plaintext, false), None);
    }
}
