use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};

use crate::asynchronous::transport::AsyncTransport;
use crate::asynchronous::{redirect_target_error, set_query_param, RedirectMetadata};
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::StreamExt;
use futures_util::Stream;
use http::HeaderMap;
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Error as WsError};
use tungstenite::client::IntoClientRequest;
use url::Url;

use super::websocket_general::AsyncWebsocketGeneralTransport;

/// An asynchronous websocket transport type.
/// This type only allows for plain websocket
/// connections ("ws://").
#[derive(Clone)]
pub struct WebsocketTransport {
    inner: AsyncWebsocketGeneralTransport,
    base_url: Arc<RwLock<Url>>,
    redirects: Arc<StdMutex<Vec<RedirectMetadata>>>,
}

impl WebsocketTransport {
    /// Creates a new instance over a request that might hold additional headers and an URL.
    pub async fn new(base_url: Url, headers: Option<HeaderMap>) -> Result<Self> {
        Self::new_with_redirect_budget(base_url, headers, 3).await
    }

    // Preserve the existing public Error representation for this additive
    // internal constructor.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn new_with_redirect_budget(
        base_url: Url,
        headers: Option<HeaderMap>,
        redirect_budget: usize,
    ) -> Result<Self> {
        Self::new_with_credentials_and_redirect_budget(base_url, headers, redirect_budget, false)
            .await
    }

    #[allow(clippy::result_large_err)]
    pub(crate) async fn new_with_credentials_and_redirect_budget(
        base_url: Url,
        headers: Option<HeaderMap>,
        redirect_budget: usize,
        credentials_present: bool,
    ) -> Result<Self> {
        let mut url = base_url;
        set_query_param(&mut url, "transport", "websocket");
        match url.scheme() {
            "http" => url.set_scheme("ws").unwrap(),
            "https" => url.set_scheme("wss").unwrap(),
            "ws" | "wss" => {}
            scheme => return Err(crate::Error::InvalidUrlScheme(scheme.to_owned())),
        }
        let original_url = url.clone();
        let credential_bearing = credentials_present
            || url.username() != ""
            || url.password().is_some()
            || headers.as_ref().is_some_and(|headers| {
                headers.contains_key(http::header::AUTHORIZATION)
                    || headers.contains_key(http::header::COOKIE)
                    || headers.contains_key(http::header::PROXY_AUTHORIZATION)
            });
        let mut redirects = Vec::new();
        let (ws_stream, _) = loop {
            let mut req = url.clone().into_client_request()?;
            if let Some(mut map) = headers.clone() {
                if url.origin() != original_url.origin() {
                    map.remove(http::header::AUTHORIZATION);
                    map.remove(http::header::COOKIE);
                    map.remove(http::header::PROXY_AUTHORIZATION);
                }
                req.headers_mut().extend(map);
            }
            match connect_async_tls_with_config(req, None, false, None).await {
                Ok(connection) => break connection,
                Err(WsError::Http(response))
                    if matches!(response.status().as_u16(), 301 | 302 | 307 | 308) =>
                {
                    if redirects.len() >= redirect_budget {
                        return Err(WsError::Http(response).into());
                    }
                    let location = response
                        .headers()
                        .get(http::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .ok_or_else(|| {
                            crate::Error::InvalidHandshake("redirect missing Location".into())
                        })?;
                    let from = url.clone();
                    let mut to = url.join(location)?;
                    if let Some(reason) = redirect_target_error(&from, &to, credential_bearing) {
                        return Err(crate::Error::InvalidHandshake(reason.into()));
                    }
                    match to.scheme() {
                        "http" => to.set_scheme("ws").unwrap(),
                        "https" => to.set_scheme("wss").unwrap(),
                        "ws" | "wss" => {}
                        scheme => return Err(crate::Error::InvalidUrlScheme(scheme.to_owned())),
                    }
                    redirects.push(RedirectMetadata {
                        status: response.status().as_u16(),
                        from,
                        to: to.clone(),
                    });
                    url = to;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let (sen, rec) = ws_stream.split();

        let inner = AsyncWebsocketGeneralTransport::new(sen, rec).await;
        Ok(WebsocketTransport {
            inner,
            base_url: Arc::new(RwLock::new(url)),
            redirects: Arc::new(StdMutex::new(redirects)),
        })
    }

    /// Sends probe packet to ensure connection is valid, then sends upgrade
    /// request
    pub(crate) async fn upgrade(&self) -> Result<()> {
        self.inner.upgrade().await
    }

    pub(crate) async fn poll_next(&self) -> Result<Option<Bytes>> {
        self.inner.poll_next().await
    }
}

#[async_trait]
impl AsyncTransport for WebsocketTransport {
    async fn emit(&self, data: Bytes, is_binary_att: bool) -> Result<()> {
        self.inner.emit(data, is_binary_att).await
    }

    async fn base_url(&self) -> Result<Url> {
        Ok(self.base_url.read().await.clone())
    }

    async fn set_base_url(&self, base_url: Url) -> Result<()> {
        let mut url = base_url;
        set_query_param(&mut url, "transport", "websocket");
        if matches!(url.scheme(), "http" | "https" | "wss") {
            url.set_scheme("ws").unwrap();
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

impl Stream for WebsocketTransport {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl Debug for WebsocketTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncWebsocketTransport")
            .field(
                "base_url",
                &self
                    .base_url
                    .try_read()
                    .map_or("Currently not available".to_owned(), |url| url.to_string()),
            )
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ENGINE_IO_VERSION;
    use std::str::FromStr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_tungstenite::accept_async;

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

    async fn new() -> Result<WebsocketTransport> {
        let url = crate::test::engine_io_server()?.to_string()
            + "engine.io/?EIO="
            + &ENGINE_IO_VERSION.to_string();
        WebsocketTransport::new(Url::from_str(&url[..])?, None).await
    }

    #[tokio::test]
    async fn websocket_transport_base_url() -> Result<()> {
        let transport = new().await?;
        let mut url = crate::test::engine_io_server()?;
        url.set_path("/engine.io/");
        url.query_pairs_mut()
            .append_pair("EIO", &ENGINE_IO_VERSION.to_string())
            .append_pair("transport", "websocket");
        url.set_scheme("ws").unwrap();
        assert_eq!(transport.base_url().await?.to_string(), url.to_string());
        transport
            .set_base_url(reqwest::Url::parse("https://127.0.0.1")?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "ws://127.0.0.1/?transport=websocket"
        );
        assert_ne!(transport.base_url().await?.to_string(), url.to_string());

        transport
            .set_base_url(reqwest::Url::parse(
                "http://127.0.0.1/?transport=websocket",
            )?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "ws://127.0.0.1/?transport=websocket"
        );
        assert_ne!(transport.base_url().await?.to_string(), url.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn follows_relative_websocket_redirects_and_preserves_endpoint_metadata() {
        for status in [301, 302, 307, 308] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut redirect_stream, _) = listener.accept().await.unwrap();
                read_request(&mut redirect_stream).await;
                let response = format!(
                    "HTTP/1.1 {status} Redirect\r\nLocation: /resolved/socket.io/?EIO=4&transport=websocket&keep=yes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                redirect_stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
                drop(redirect_stream);

                let (stream, _) = listener.accept().await.unwrap();
                let websocket = accept_async(stream).await.unwrap();
                drop(websocket);
            });
            let original = Url::parse(&format!(
                "http://{address}/original/socket.io/?EIO=4&transport=websocket"
            ))
            .unwrap();
            let transport = WebsocketTransport::new(original, None).await.unwrap();
            let final_url = transport.base_url().await.unwrap();
            assert_eq!(final_url.path(), "/resolved/socket.io/");
            assert!(final_url
                .query_pairs()
                .any(|(key, value)| key == "keep" && value == "yes"));
            let redirects = transport.redirect_metadata();
            assert_eq!(redirects.len(), 1);
            assert_eq!(redirects[0].status, status);
            assert_eq!(redirects[0].from.path(), "/original/socket.io/");
            assert_eq!(redirects[0].to.path(), "/resolved/socket.io/");
            drop(transport);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn websocket_redirect_chain_stops_after_three_hops() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for hop in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: /hop{}/socket.io/?EIO=4&transport=websocket\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    hop + 1
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let url = Url::parse(&format!("http://{address}/start/socket.io/")).unwrap();
        assert!(WebsocketTransport::new(url, None).await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_secure_debug() -> Result<()> {
        let mut transport = new().await?;
        assert_eq!(
            format!("{:?}", transport),
            format!(
                "AsyncWebsocketTransport {{ base_url: {:?} }}",
                transport.base_url().await?.to_string()
            )
        );
        println!("{:?}", transport.next().await.unwrap());
        println!("{:?}", transport.next().await.unwrap());
        Ok(())
    }
}
