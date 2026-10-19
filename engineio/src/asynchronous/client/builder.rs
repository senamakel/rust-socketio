use crate::{
    asynchronous::{
        async_socket::Socket as InnerSocket,
        async_transports::{PollingTransport, WebsocketSecureTransport, WebsocketTransport},
        callback::OptionalCallback,
        ensure_query_param,
        transport::AsyncTransport,
        ConnectionMetadata,
    },
    error::Result,
    header::HeaderMap,
    packet::HandshakePacket,
    Error, Packet, ENGINE_IO_VERSION,
};
use bytes::Bytes;
use futures_util::{future::BoxFuture, StreamExt};
use native_tls::TlsConnector;
use url::Url;

use super::Client;

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    url: Url,
    connection_metadata: ConnectionMetadata,
    tls_config: Option<TlsConnector>,
    headers: Option<HeaderMap>,
    handshake: Option<HandshakePacket>,
    on_error: OptionalCallback<String>,
    on_open: OptionalCallback<()>,
    on_close: OptionalCallback<()>,
    on_data: OptionalCallback<Bytes>,
    on_packet: OptionalCallback<Packet>,
}

impl ClientBuilder {
    pub fn new(url: Url) -> Self {
        let mut url = url;
        let original_endpoint = url.clone();
        ensure_query_param(&mut url, "EIO", &ENGINE_IO_VERSION.to_string());

        // No path add engine.io
        if url.path() == "/" {
            url.set_path("/engine.io/");
        }
        ClientBuilder {
            connection_metadata: ConnectionMetadata {
                original_endpoint,
                final_endpoint: url.clone(),
                redirects: Vec::new(),
            },
            url,
            headers: None,
            tls_config: None,
            handshake: None,
            on_close: OptionalCallback::default(),
            on_data: OptionalCallback::default(),
            on_error: OptionalCallback::default(),
            on_open: OptionalCallback::default(),
            on_packet: OptionalCallback::default(),
        }
    }

    /// Specify transport's tls config
    pub fn tls_config(mut self, tls_config: TlsConnector) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Specify transport's HTTP headers
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Registers the `on_close` callback.
    #[cfg(feature = "async-callbacks")]
    pub fn on_close<T>(mut self, callback: T) -> Self
    where
        T: 'static + Send + Sync + Fn(()) -> BoxFuture<'static, ()>,
    {
        self.on_close = OptionalCallback::new(callback);
        self
    }

    /// Registers the `on_data` callback.
    #[cfg(feature = "async-callbacks")]
    pub fn on_data<T>(mut self, callback: T) -> Self
    where
        T: 'static + Send + Sync + Fn(Bytes) -> BoxFuture<'static, ()>,
    {
        self.on_data = OptionalCallback::new(callback);
        self
    }

    /// Registers the `on_error` callback.
    #[cfg(feature = "async-callbacks")]
    pub fn on_error<T>(mut self, callback: T) -> Self
    where
        T: 'static + Send + Sync + Fn(String) -> BoxFuture<'static, ()>,
    {
        self.on_error = OptionalCallback::new(callback);
        self
    }

    /// Registers the `on_open` callback.
    #[cfg(feature = "async-callbacks")]
    pub fn on_open<T>(mut self, callback: T) -> Self
    where
        T: 'static + Send + Sync + Fn(()) -> BoxFuture<'static, ()>,
    {
        self.on_open = OptionalCallback::new(callback);
        self
    }

    /// Registers the `on_packet` callback.
    #[cfg(feature = "async-callbacks")]
    pub fn on_packet<T>(mut self, callback: T) -> Self
    where
        T: 'static + Send + Sync + Fn(Packet) -> BoxFuture<'static, ()>,
    {
        self.on_packet = OptionalCallback::new(callback);
        self
    }

    /// Performs the handshake
    async fn handshake_with_transport<T: AsyncTransport + Unpin>(
        &mut self,
        transport: &mut T,
    ) -> Result<()> {
        // No need to handshake twice
        if self.handshake.is_some() {
            return Ok(());
        }

        let handshake: HandshakePacket =
            Packet::try_from(transport.next().await.ok_or(Error::IncompletePacket())??)?
                .try_into()?;

        let mut url = transport.base_url().await?;
        let redirects = transport.redirect_metadata();
        let initial_origin = self.connection_metadata.original_endpoint.origin();
        if redirects.iter().any(|redirect| {
            redirect.from.origin() != initial_origin || redirect.to.origin() != initial_origin
        }) {
            self.headers = self.headers.take().map(strip_redirect_credentials);
        }
        self.record_transport_metadata(transport).await?;

        // update the base_url with the new sid
        url.query_pairs_mut().append_pair("sid", &handshake.sid[..]);

        self.handshake = Some(handshake);

        self.url = url;

        Ok(())
    }

    // Keep the established Engine.IO error type, which includes the unboxed
    // tungstenite error variant, unchanged for this metadata helper.
    #[allow(clippy::result_large_err)]
    async fn record_transport_metadata<T: AsyncTransport + Unpin>(
        &mut self,
        transport: &T,
    ) -> Result<()> {
        self.connection_metadata.final_endpoint = transport.base_url().await?;
        self.connection_metadata
            .redirects
            .extend(transport.redirect_metadata());
        Ok(())
    }

    fn remaining_redirect_budget(&self) -> usize {
        3usize.saturating_sub(self.connection_metadata.redirects.len())
    }

    async fn handshake(&mut self) -> Result<()> {
        if self.handshake.is_some() {
            return Ok(());
        }

        let headers = if let Some(map) = self.headers.clone() {
            Some(map.try_into()?)
        } else {
            None
        };

        // Start with polling transport
        let mut transport =
            PollingTransport::new(self.url.clone(), self.tls_config.clone(), headers);

        self.handshake_with_transport(&mut transport).await
    }

    /// Build websocket if allowed, if not fall back to polling
    pub async fn build(mut self) -> Result<Client> {
        self.handshake().await?;

        if self.websocket_upgrade()? {
            self.build_websocket_with_upgrade().await
        } else {
            self.build_polling().await
        }
    }

    /// Build socket with polling transport
    pub async fn build_polling(mut self) -> Result<Client> {
        self.handshake().await?;
        let redirect_budget = self.remaining_redirect_budget();

        // Make a polling transport with new sid
        let transport = PollingTransport::new_with_redirect_budget(
            self.url,
            self.tls_config,
            self.headers.map(|v| v.try_into().unwrap()),
            redirect_budget,
        );

        // SAFETY: handshake function called previously.
        Ok(Client::new(
            InnerSocket::new(
                transport.into(),
                self.handshake.unwrap(),
                self.on_close,
                self.on_data,
                self.on_error,
                self.on_open,
                self.on_packet,
            ),
            self.connection_metadata.clone(),
        ))
    }

    /// Build socket with a polling transport then upgrade to websocket transport
    pub async fn build_websocket_with_upgrade(mut self) -> Result<Client> {
        self.handshake().await?;

        if self.websocket_upgrade()? {
            self.build_websocket().await
        } else {
            Err(Error::IllegalWebsocketUpgrade())
        }
    }

    /// Build socket with only a websocket transport
    pub async fn build_websocket(mut self) -> Result<Client> {
        let redirect_budget = self.remaining_redirect_budget();
        let headers = if let Some(map) = self.headers.clone() {
            Some(map.try_into()?)
        } else {
            None
        };

        match self.url.scheme() {
            "http" | "ws" => {
                let mut transport = WebsocketTransport::new_with_redirect_budget(
                    self.url.clone(),
                    headers,
                    redirect_budget,
                )
                .await?;

                if self.handshake.is_some() {
                    transport.upgrade().await?;
                    self.record_transport_metadata(&transport).await?;
                } else {
                    self.handshake_with_transport(&mut transport).await?;
                }
                // NOTE: Although self.url contains the sid, it does not propagate to the transport
                // SAFETY: handshake function called previously.
                Ok(Client::new(
                    InnerSocket::new(
                        transport.into(),
                        self.handshake.unwrap(),
                        self.on_close,
                        self.on_data,
                        self.on_error,
                        self.on_open,
                        self.on_packet,
                    ),
                    self.connection_metadata.clone(),
                ))
            }
            "https" | "wss" => {
                let mut transport = WebsocketSecureTransport::new_with_redirect_budget(
                    self.url.clone(),
                    self.tls_config.clone(),
                    headers,
                    redirect_budget,
                )
                .await?;

                if self.handshake.is_some() {
                    transport.upgrade().await?;
                    self.record_transport_metadata(&transport).await?;
                } else {
                    self.handshake_with_transport(&mut transport).await?;
                }
                // NOTE: Although self.url contains the sid, it does not propagate to the transport
                // SAFETY: handshake function called previously.
                Ok(Client::new(
                    InnerSocket::new(
                        transport.into(),
                        self.handshake.unwrap(),
                        self.on_close,
                        self.on_data,
                        self.on_error,
                        self.on_open,
                        self.on_packet,
                    ),
                    self.connection_metadata.clone(),
                ))
            }
            _ => Err(Error::InvalidUrlScheme(self.url.scheme().to_string())),
        }
    }

    /// Build websocket if allowed, if not allowed or errored fall back to polling.
    /// WARNING: websocket errors suppressed, no indication of websocket success or failure.
    pub async fn build_with_fallback(self) -> Result<Client> {
        let result = self.clone().build().await;
        if result.is_err() {
            self.build_polling().await
        } else {
            result
        }
    }

    /// Checks the handshake to see if websocket upgrades are allowed
    fn websocket_upgrade(&mut self) -> Result<bool> {
        if self.handshake.is_none() {
            return Ok(false);
        }

        Ok(self
            .handshake
            .as_ref()
            .unwrap()
            .upgrades
            .iter()
            .any(|upgrade| upgrade.to_lowercase() == *"websocket"))
    }
}

fn strip_redirect_credentials(headers: crate::header::HeaderMap) -> crate::header::HeaderMap {
    let mut sanitized = crate::header::HeaderMap::new();
    for (name, value) in headers {
        if !matches!(
            name.to_string().as_str(),
            "authorization" | "cookie" | "proxy-authorization"
        ) {
            sanitized.insert(name, value);
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{timeout, Duration},
    };

    #[test]
    fn resolved_endpoint_query_is_preserved_without_duplicate_engine_version() {
        let url = Url::parse("https://example.test/socket.io/?EIO=4&transport=websocket&token=a")
            .unwrap();
        let builder = ClientBuilder::new(url);
        assert_eq!(
            builder.url.as_str(),
            "https://example.test/socket.io/?EIO=4&transport=websocket&token=a"
        );
    }

    async fn read_headers(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut chunk = [0; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0, "peer closed before request headers arrived");
            request.extend_from_slice(&chunk[..count]);
        }
        String::from_utf8(request).unwrap()
    }

    async fn write_response(stream: &mut tokio::net::TcpStream, status: &str, body: &str) {
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    async fn redirect_request(listener: TcpListener, next_port: u16) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_headers(&mut stream).await;
        let path = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{next_port}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn redirected_polling_never_reuses_credentials_at_new_origin() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let destination_server = tokio::spawn(async move {
            let (mut handshake_stream, _) = destination.accept().await.unwrap();
            let handshake_request = read_headers(&mut handshake_stream).await;
            write_response(
                &mut handshake_stream,
                "200 OK",
                "0{\"sid\":\"redirected\",\"upgrades\":[],\"pingInterval\":60000,\"pingTimeout\":60000}",
            )
            .await;

            let (mut polling_stream, _) = destination.accept().await.unwrap();
            let polling_request = read_headers(&mut polling_stream).await;
            write_response(&mut polling_stream, "200 OK", "6").await;
            (handshake_request, polling_request)
        });
        let redirect_server = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let _ = read_headers(&mut stream).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{destination_address}/socket.io/?EIO=4&transport=polling\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization".to_owned(),
            "Bearer fixture-secret".to_owned(),
        );
        headers.insert("cookie".to_owned(), "session=fixture-secret".to_owned());
        headers.insert(
            "proxy-authorization".to_owned(),
            "Basic fixture-secret".to_owned(),
        );
        let builder =
            ClientBuilder::new(Url::parse(&format!("http://{origin_address}/socket.io/")).unwrap())
                .headers(headers);
        let mut client = builder.build_polling().await.unwrap();
        let _ = timeout(Duration::from_secs(2), client.next())
            .await
            .expect("follow-up polling GET should finish");
        redirect_server.await.unwrap();
        let (handshake_request, polling_request) =
            timeout(Duration::from_secs(2), destination_server)
                .await
                .expect("destination should finish both requests")
                .unwrap();

        for request in [&handshake_request, &polling_request] {
            let request = request.to_ascii_lowercase();
            assert!(!request.contains("authorization: bearer fixture-secret"));
            assert!(!request.contains("cookie: session=fixture-secret"));
            assert!(!request.contains("proxy-authorization: basic fixture-secret"));
        }
    }

    #[tokio::test]
    async fn polling_and_websocket_upgrade_share_the_three_redirect_budget() {
        use futures_util::SinkExt;
        use tokio_tungstenite::{accept_async, tungstenite::Message};
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let polling_endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_upgrade_redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_upgrade_redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        let polling_port = polling_endpoint.local_addr().unwrap().port();
        let first_upgrade_port = first_upgrade_redirect.local_addr().unwrap().port();
        let second_upgrade_port = second_upgrade_redirect.local_addr().unwrap().port();
        let first_task = tokio::spawn(redirect_request(first, second_port));
        let second_task = tokio::spawn(redirect_request(second, polling_port));
        let polling_task = tokio::spawn(async move {
            let (mut handshake_stream, _) = polling_endpoint.accept().await.unwrap();
            let _ = read_headers(&mut handshake_stream).await;
            write_response(
                &mut handshake_stream,
                "200 OK",
                "0{\"sid\":\"combined\",\"upgrades\":[\"websocket\"],\"pingInterval\":60000,\"pingTimeout\":60000}",
            )
            .await;
            let (mut upgrade_stream, _) = polling_endpoint.accept().await.unwrap();
            let request = read_headers(&mut upgrade_stream).await;
            let path = request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            upgrade_stream
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{first_upgrade_port}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let first_upgrade_task = tokio::spawn(redirect_request(
            first_upgrade_redirect,
            second_upgrade_port,
        ));
        let second_upgrade_task = tokio::spawn(async move {
            let (stream, _) = second_upgrade_redirect.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                if matches!(message, Message::Text(ref text) if text == "2probe") {
                    socket.send(Message::Text("3probe".into())).await.unwrap();
                } else if matches!(message, Message::Text(ref text) if text == "1") {
                    break;
                }
            }
        });

        let result = ClientBuilder::new(
            Url::parse(&format!("http://127.0.0.1:{first_port}/socket.io/?EIO=4")).unwrap(),
        )
        .build()
        .await;
        assert!(result.is_err(), "connection followed four redirects");
        first_task.await.unwrap();
        second_task.await.unwrap();
        polling_task.await.unwrap();
        first_upgrade_task.await.unwrap();
        second_upgrade_task.abort();
    }

    #[tokio::test]
    async fn connection_metadata_includes_redirects_followed_during_upgrade() {
        use futures_util::SinkExt;
        use tokio_tungstenite::{accept_async, tungstenite::Message};
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let polling_endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let websocket_endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let polling_port = polling_endpoint.local_addr().unwrap().port();
        let websocket_port = websocket_endpoint.local_addr().unwrap().port();
        let origin_task = tokio::spawn(redirect_request(origin, polling_port));
        let polling_task = tokio::spawn(async move {
            let (mut handshake_stream, _) = polling_endpoint.accept().await.unwrap();
            let _ = read_headers(&mut handshake_stream).await;
            write_response(
                &mut handshake_stream,
                "200 OK",
                "0{\"sid\":\"metadata\",\"upgrades\":[\"websocket\"],\"pingInterval\":60000,\"pingTimeout\":60000}",
            )
            .await;
            let (mut upgrade_stream, _) = polling_endpoint.accept().await.unwrap();
            let request = read_headers(&mut upgrade_stream).await;
            let path = request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            upgrade_stream
                .write_all(
                    format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{websocket_port}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let websocket_task = tokio::spawn(async move {
            let (stream, _) = websocket_endpoint.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                if matches!(message, Message::Text(ref text) if text == "2probe") {
                    socket.send(Message::Text("3probe".into())).await.unwrap();
                } else if matches!(message, Message::Text(ref text) if text == "1") {
                    break;
                }
            }
        });

        let client = ClientBuilder::new(
            Url::parse(&format!("http://127.0.0.1:{origin_port}/socket.io/?EIO=4")).unwrap(),
        )
        .build()
        .await
        .unwrap();
        client.connect().await.unwrap();
        let metadata = client.connection_metadata();
        assert_eq!(metadata.redirects.len(), 2);
        assert_eq!(metadata.redirects[0].status, 302);
        assert_eq!(metadata.redirects[1].status, 307);
        assert_eq!(metadata.final_endpoint.port(), Some(websocket_port));
        client.disconnect().await.unwrap();
        origin_task.await.unwrap();
        polling_task.await.unwrap();
        timeout(Duration::from_secs(2), websocket_task)
            .await
            .expect("upgraded fixture should observe close")
            .unwrap();
    }
}
