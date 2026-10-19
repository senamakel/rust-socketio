pub mod async_transports;
pub mod transport;

/// One redirect followed while establishing an Engine.IO connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectMetadata {
    pub status: u16,
    pub from: url::Url,
    pub to: url::Url,
}

/// The resolved endpoint and redirects followed during Engine.IO setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionMetadata {
    pub original_endpoint: url::Url,
    pub final_endpoint: url::Url,
    pub redirects: Vec<RedirectMetadata>,
}

pub(crate) fn ensure_query_param(url: &mut url::Url, key: &str, value: &str) {
    if !url.query_pairs().any(|(existing, _)| existing == key) {
        url.query_pairs_mut().append_pair(key, value);
    }
}

pub(crate) fn set_query_param(url: &mut url::Url, key: &str, value: &str) {
    let retained = url
        .query_pairs()
        .filter(|(existing, _)| existing != key)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    let mut query = url.query_pairs_mut();
    for (name, value) in retained {
        query.append_pair(&name, &value);
    }
    query.append_pair(key, value);
}

pub(crate) fn redirect_target_error(
    from: &url::Url,
    to: &url::Url,
    credential_bearing: bool,
) -> Option<&'static str> {
    if !matches!(to.scheme(), "http" | "https" | "ws" | "wss") {
        return Some("unsupported redirect scheme");
    }
    let is_remote = |url: &url::Url| {
        !url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    };
    let from_tls = matches!(from.scheme(), "https" | "wss");
    let to_plaintext = matches!(to.scheme(), "http" | "ws");
    if credential_bearing && (is_remote(from) || is_remote(to)) && from_tls && to_plaintext {
        return Some("refusing credential-bearing TLS downgrade");
    }
    None
}

pub(self) mod async_socket;
#[cfg(feature = "async-callbacks")]
mod callback;
#[cfg(feature = "async")]
pub mod client;
mod generator;

#[cfg(feature = "async")]
pub use async_socket::CallbackTaskControl;
#[cfg(feature = "async")]
pub use client::Client;

#[cfg(feature = "async")]
pub use client::ClientBuilder;
