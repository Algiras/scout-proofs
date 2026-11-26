// SPDX-License-Identifier: Apache-2.0

//! The broker's client for the upstream OAuth provider. The client secret is
//! used only here.
use scout_core::teardown::Outcome;
use scout_wire::http::{urlencode, Transport};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tokens {
    pub access: String,
    pub refresh: Option<String>,
    pub expires_in: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProvErr {
    /// The provider answered with an error.
    Rejected(u16),
    /// No usable answer (transport failure, bad body): the provider may have acted.
    Unknown(String),
}

/// What the renewal path needs from a provider.
pub trait Refresher: Send + Sync {
    fn refresh(&self, refresh_token: &str) -> Result<Tokens, ProvErr>;
    /// Called with tokens minted for a reply that can no longer be committed.
    fn discard(&self, _t: &Tokens) {}
}

pub struct Provider {
    pub auth_url: String,
    pub token_url: String,
    pub revoke_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub scope: String,
    pub transport: Arc<dyn Transport>,
}

impl Provider {
    fn form(&self, fields: &[(&str, &str)]) -> Vec<u8> {
        let mut all = vec![("client_id", self.client_id.as_str()), ("client_secret", self.client_secret.as_str())];
        all.extend_from_slice(fields);
        all.iter().map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v))).collect::<Vec<_>>().join("&").into_bytes()
    }

    fn token_call(&self, fields: &[(&str, &str)]) -> Result<Tokens, ProvErr> {
        let hdr = [("Content-Type", "application/x-www-form-urlencoded")];
        let (status, body) = self.transport.call("POST", &self.token_url, &hdr, &self.form(fields)).map_err(|e| ProvErr::Unknown(e.0))?;
        if status != 200 {
            return Err(ProvErr::Rejected(status));
        }
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| ProvErr::Unknown(e.to_string()))?;
        let access = v["access_token"].as_str().ok_or_else(|| ProvErr::Unknown("no access_token".into()))?.to_string();
        Ok(Tokens {
            access,
            refresh: v["refresh_token"].as_str().map(str::to_string),
            expires_in: v["expires_in"].as_u64().unwrap_or(3600),
        })
    }

    pub fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<Tokens, ProvErr> {
        self.token_call(&[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri)])
    }

    pub fn authorize_url(&self, redirect_uri: &str, state: &str) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
            self.auth_url,
            urlencode(&self.client_id),
            urlencode(redirect_uri),
            urlencode(state),
            urlencode(&self.scope)
        )
    }

    /// RFC 7009 revocation; only a 200 counts as acknowledged.
    pub fn revoke(&self, token: &str, hint: &str) -> Outcome {
        let Some(url) = &self.revoke_url else { return Outcome::Unsupported };
        let hdr = [("Content-Type", "application/x-www-form-urlencoded")];
        match self.transport.call("POST", url, &hdr, &self.form(&[("token", token), ("token_type_hint", hint)])) {
            Ok((200, _)) => Outcome::Ack,
            Ok((404 | 405 | 501, _)) => Outcome::Unsupported,
            Ok(_) => Outcome::Failed,
            Err(_) => Outcome::Unknown,
        }
    }
}

impl Refresher for Provider {
    fn refresh(&self, refresh_token: &str) -> Result<Tokens, ProvErr> {
        self.token_call(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token)])
    }

    fn discard(&self, t: &Tokens) {
        self.revoke(&t.access, "access_token");
        if let Some(r) = &t.refresh {
            self.revoke(r, "refresh_token");
        }
    }
}
