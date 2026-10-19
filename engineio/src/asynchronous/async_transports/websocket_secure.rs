use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};

use crate::asynchronous::{
    redirect_target_error, set_query_param, transport::AsyncTransport, RedirectMetadata,
};
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::Stream;
use futures_util::StreamExt;
use http::HeaderMap;
use native_tls::TlsConnector;
use tokio::sync::RwLock;
use tokio_tungstenite::Connector;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Error as WsError};
use tungstenite::client::IntoClientRequest;
use url::Url;

use super::websocket_general::AsyncWebsocketGeneralTransport;

/// An asynchronous websocket transport type.
/// This type only allows for secure websocket
/// connections ("wss://").
#[derive(Clone)]
pub struct WebsocketSecureTransport {
    inner: AsyncWebsocketGeneralTransport,
    base_url: Arc<RwLock<Url>>,
    redirects: Arc<StdMutex<Vec<RedirectMetadata>>>,
}

impl WebsocketSecureTransport {
    /// Creates a new instance over a request that might hold additional headers, a possible
    /// Tls connector and an URL.
    pub(crate) async fn new(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        headers: Option<HeaderMap>,
    ) -> Result<Self> {
        Self::new_with_redirect_budget(base_url, tls_config, headers, 3).await
    }

    // Preserve the existing public Error representation for this additive
    // internal constructor.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn new_with_redirect_budget(
        base_url: Url,
        tls_config: Option<TlsConnector>,
        headers: Option<HeaderMap>,
        redirect_budget: usize,
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
        let credential_bearing = url.username() != ""
            || url.password().is_some()
            || headers.as_ref().is_some_and(|headers| {
                headers.contains_key(http::header::AUTHORIZATION)
                    || headers.contains_key(http::header::COOKIE)
                    || headers.contains_key(http::header::PROXY_AUTHORIZATION)
            });
        let mut redirects = Vec::new();

        // `disable_nagle` Sets the value of the TCP_NODELAY option on this socket.
        //
        // If set to `true`, this option disables the Nagle algorithm.
        // This means that segments are always sent as soon as possible, even if there is only a small amount of data.
        // When `false`, data is buffered until there is a sufficient amount to send out, thereby avoiding the frequent sending of small packets.
        //
        // See the docs: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.set_nodelay
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
            match connect_async_tls_with_config(
                req,
                None,
                /*disable_nagle=*/ false,
                tls_config.clone().map(Connector::NativeTls),
            )
            .await
            {
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

        Ok(WebsocketSecureTransport {
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

impl Stream for WebsocketSecureTransport {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

#[async_trait]
impl AsyncTransport for WebsocketSecureTransport {
    async fn emit(&self, data: Bytes, is_binary_att: bool) -> Result<()> {
        self.inner.emit(data, is_binary_att).await
    }

    async fn base_url(&self) -> Result<Url> {
        Ok(self.base_url.read().await.clone())
    }

    async fn set_base_url(&self, base_url: Url) -> Result<()> {
        let mut url = base_url;
        set_query_param(&mut url, "transport", "websocket");
        if matches!(url.scheme(), "http" | "https" | "ws") {
            url.set_scheme("wss").unwrap();
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

impl Debug for WebsocketSecureTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncWebsocketSecureTransport")
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

    async fn new() -> Result<WebsocketSecureTransport> {
        let url = crate::test::engine_io_server_secure()?.to_string()
            + "engine.io/?EIO="
            + &ENGINE_IO_VERSION.to_string();
        WebsocketSecureTransport::new(
            Url::from_str(&url[..])?,
            Some(crate::test::tls_connector()?),
            None,
        )
        .await
    }

    #[tokio::test]
    async fn websocket_secure_transport_base_url() -> Result<()> {
        let transport = new().await?;
        let mut url = crate::test::engine_io_server_secure()?;
        url.set_path("/engine.io/");
        url.query_pairs_mut()
            .append_pair("EIO", &ENGINE_IO_VERSION.to_string())
            .append_pair("transport", "websocket");
        url.set_scheme("wss").unwrap();
        assert_eq!(transport.base_url().await?.to_string(), url.to_string());
        transport
            .set_base_url(reqwest::Url::parse("https://127.0.0.1")?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "wss://127.0.0.1/?transport=websocket"
        );
        assert_ne!(transport.base_url().await?.to_string(), url.to_string());

        transport
            .set_base_url(reqwest::Url::parse(
                "http://127.0.0.1/?transport=websocket",
            )?)
            .await?;
        assert_eq!(
            transport.base_url().await?.to_string(),
            "wss://127.0.0.1/?transport=websocket"
        );
        assert_ne!(transport.base_url().await?.to_string(), url.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn websocket_secure_debug() -> Result<()> {
        let transport = new().await?;
        assert_eq!(
            format!("{:?}", transport),
            format!(
                "AsyncWebsocketSecureTransport {{ base_url: {:?} }}",
                transport.base_url().await?.to_string()
            )
        );
        Ok(())
    }
}
