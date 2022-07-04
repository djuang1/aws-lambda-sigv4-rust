use chrono::{DateTime, Utc};
use http::header;
use serde::{Deserialize, Serialize};
use std::{iter, str};

pub const HMAC_256: &str = "AWS4-HMAC-SHA256";
pub const DATE_FORMAT: &str = "%Y%m%dT%H%M%SZ";
pub const X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";
pub const X_AMZ_DATE: &str = "x-amz-date";
pub const X_AMZ_TARGET: &str = "x-amz-target";

pub mod sign;
pub mod types;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

use crate::UriEncoding::Double;
use http::header::HeaderName;
use sign::{calculate_signature, encode_with_hex, generate_signing_key};
use std::time::SystemTime;
use types::{AsSigV4, CanonicalRequest, DateTimeExt, StringToSign};

pub fn sign<B>(
    req: &mut http::Request<B>,
    credential: &Credentials,
    region: &str,
    svc: &str,
) -> Result<(), Error>
where
    B: AsRef<[u8]>,
{
    for (header_name, header_value) in sign_core(
        &req,
        Config {
            access_key: &credential.access_key,
            secret_key: &credential.secret_key,
            security_token: credential.security_token.as_deref(),
            region,
            svc,
            date: SystemTime::now(),
            settings: Default::default(),
        },
    ) {
        req.headers_mut()
            .append(header_name.header_name(), header_value.parse()?);
    }

    Ok(())
}

/// SignatureKey is the key portion of the key-value pair of a generated SigV4 signature.
///
/// When signing with SigV4, the algorithm produces multiple components of a signature that MUST
/// be applied to a request.
pub enum SignatureKey {
    Authorization,
    AmzDate,
    AmzSecurityToken,
}

impl SignatureKey {
    pub fn header_name(&self) -> HeaderName {
        match self {
            SignatureKey::Authorization => header::AUTHORIZATION,
            SignatureKey::AmzDate => HeaderName::from_static(X_AMZ_DATE),
            SignatureKey::AmzSecurityToken => HeaderName::from_static(X_AMZ_SECURITY_TOKEN),
        }
    }
}

pub struct Config<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub security_token: Option<&'a str>,

    pub region: &'a str,
    pub svc: &'a str,

    pub date: SystemTime,

    pub settings: SigningSettings,
}

#[derive(Debug, PartialEq)]
pub struct SigningSettings {
    /// We assume the URI will be encoded _once_ prior to transmission. Some services
    /// do not decode the path prior to checking the signature, requiring clients to actually
    /// _double-encode_ the URI in creating the canonical request in order to pass a signature check.
    pub uri_encoding: UriEncoding,
}

#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum UriEncoding {
    /// Re-encode the resulting URL (eg. %30 becomes `%2530)
    Double,

    /// Take the resulting URL as-is
    Single,
}

impl Default for SigningSettings {
    fn default() -> Self {
        Self {
            uri_encoding: Double,
        }
    }
}

pub fn sign_core<'a, B>(
    req: &'a http::Request<B>,
    config: Config<'a>,
) -> impl Iterator<Item = (SignatureKey, String)>
where
    B: AsRef<[u8]>,
{
    let Config {
        access_key,
        secret_key,
        security_token,
        region,
        svc,
        date,
        settings,
    } = config;
    // Step 1: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-create-canonical-request.html.
    let creq = CanonicalRequest::from(req, &settings).unwrap();

    // Step 2: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-create-string-to-sign.html.
    let encoded_creq = &encode_with_hex(creq.fmt());
    let date = DateTime::<Utc>::from(date);
    let sts = StringToSign::new(date, region, svc, encoded_creq);

    // Step 3: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-calculate-signature.html
    let signing_key = generate_signing_key(secret_key, date.date(), region, svc);
    let signature = calculate_signature(signing_key, &sts.fmt().as_bytes());

    // Step 4: https://docs.aws.amazon.com/en_pv/general/latest/gr/sigv4-add-signature-to-request.html
    let authorization = build_authorization_header(access_key, creq, sts, &signature);
    let x_azn_date = date.fmt_aws();


    let mut tok = security_token.map(|it| it.to_string());
    iter::once((SignatureKey::Authorization, authorization))
        .chain(iter::once((SignatureKey::AmzDate, x_azn_date)))
        .chain(iter::from_fn(move || {
            tok.take().map(|tok| (SignatureKey::AmzSecurityToken, tok))
        }))
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
pub struct Credentials<'a> {
    #[serde(rename = "aws_access_key_id")]
    pub access_key: &'a str,
    #[serde(rename = "aws_secret_access_key")]
    pub secret_key: &'a str,
    #[serde(rename = "aws_session_token")]
    pub security_token: Option<&'a str>,
}

impl<'a> Credentials<'a> {
    pub fn new(access_key: &'a str, secret_key: &'a str, security_token: Option<&'a str>) -> Self {
        Self {
            access_key,
            secret_key,
            security_token,
        }
    }
}

// add signature to authorization header
// Authorization: algorithm Credential=access key ID/credential scope, SignedHeaders=SignedHeaders, Signature=signature
fn build_authorization_header(
    access_key: &str,
    creq: CanonicalRequest,
    sts: StringToSign,
    signature: &str,
) -> String {
    format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        HMAC_256,
        access_key,
        sts.scope.fmt(),
        creq.signed_headers,
        signature
    )
}