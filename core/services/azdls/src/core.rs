// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::HeaderName;
use http::HeaderValue;
use http::Request;
use http::Response;
use http::StatusCode;
use http::header::CONTENT_DISPOSITION;
use http::header::CONTENT_LENGTH;
use http::header::CONTENT_TYPE;
use http::header::IF_NONE_MATCH;
use reqsign_azure_storage::Credential;
use reqsign_core::Signer;

use super::error::parse_error;
use opendal_core::raw::*;
use opendal_core::*;

const X_MS_RENAME_SOURCE: &str = "x-ms-rename-source";
const X_MS_VERSION: &str = "x-ms-version";
pub const X_MS_VERSION_ID: &str = "x-ms-version-id";
const X_MS_CONTINUATION: &str = "x-ms-continuation";
const X_MS_PROPERTIES: &str = "x-ms-properties";
pub const DIRECTORY: &str = "directory";
pub const FILE: &str = "file";

/// Encode user metadata into the `x-ms-properties` header format.
///
/// ADLS Gen2 uses a comma-separated list of `name=base64(value)` pairs.
/// Ref: <https://learn.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/create>
pub fn encode_properties(metadata: &HashMap<String, String>) -> String {
    metadata
        .iter()
        .map(|(k, v)| format!("{}={}", k, BASE64.encode(v)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Decode the `x-ms-properties` response header into a `HashMap`.
///
/// The header value is a comma-separated list of `name=base64(value)` pairs.
/// Ref: <https://learn.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/get-properties>
pub fn decode_properties(header: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    if header.is_empty() {
        return result;
    }
    for pair in header.split(',') {
        let pair = pair.trim();
        if let Some((key, encoded_value)) = pair.split_once('=') {
            if let Ok(decoded) = BASE64.decode(encoded_value) {
                if let Ok(value) = String::from_utf8(decoded) {
                    result.insert(key.to_string(), value);
                }
            }
        }
    }
    result
}

pub struct AzdlsCore {
    pub info: Arc<AccessorInfo>,
    pub filesystem: String,
    pub root: String,
    pub endpoint: String,
    pub enable_hns: bool,

    pub signer: Signer<Credential>,
}

impl Debug for AzdlsCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzdlsCore")
            .field("filesystem", &self.filesystem)
            .field("root", &self.root)
            .field("endpoint", &self.endpoint)
            .field("enable_hns", &self.enable_hns)
            .finish_non_exhaustive()
    }
}

impl AzdlsCore {
    pub async fn sign<T>(&self, req: Request<T>) -> Result<Request<T>> {
        let (mut parts, body) = req.into_parts();

        // Insert x-ms-version header for normal requests.
        parts.headers.insert(
            HeaderName::from_static(X_MS_VERSION),
            // 2022-11-02 is the version supported by Azurite V3 and
            // used by Azure Portal, We use this version to make
            // sure most our developer happy.
            //
            // In the future, we could allow users to configure this value.
            HeaderValue::from_static("2022-11-02"),
        );

        self.signer
            .sign(&mut parts, None)
            .await
            .map_err(|e| new_request_sign_error(e.into()))?;

        Ok(Request::from_parts(parts, body))
    }

    #[inline]
    pub async fn send(&self, req: Request<Buffer>) -> Result<Response<Buffer>> {
        self.info.http_client().send(req).await
    }
}

impl AzdlsCore {
    pub async fn azdls_read(&self, path: &str, range: BytesRange) -> Result<Response<HttpBody>> {
        let p = build_abs_path(&self.root, path);

        let url = format!(
            "{}/{}/{}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p)
        );

        let mut req = Request::get(&url);

        if !range.is_full() {
            req = req.header(http::header::RANGE, range.to_header());
        }

        let req = req
            .extension(Operation::Read)
            .extension(ServiceOperation("ReadFile"))
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.info.http_client().fetch(req).await
    }

    /// resource should be one of `file` or `directory`
    ///
    /// ref: https://learn.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/create
    pub async fn azdls_create(
        &self,
        path: &str,
        resource: &str,
        args: &OpWrite,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path)
            .trim_end_matches('/')
            .to_string();

        let url = format!(
            "{}/{}/{}?resource={resource}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p)
        );

        let mut req = Request::put(&url);

        // Content length must be 0 for create request.
        req = req.header(CONTENT_LENGTH, 0);

        if let Some(ty) = args.content_type() {
            req = req.header(CONTENT_TYPE, ty)
        }

        if let Some(pos) = args.content_disposition() {
            req = req.header(CONTENT_DISPOSITION, pos)
        }

        if args.if_not_exists() {
            req = req.header(IF_NONE_MATCH, "*")
        }

        if let Some(v) = args.if_none_match() {
            req = req.header(IF_NONE_MATCH, v)
        }

        if let Some(user_metadata) = args.user_metadata() {
            if !user_metadata.is_empty() {
                req = req.header(X_MS_PROPERTIES, encode_properties(user_metadata));
            }
        }

        let operation = if resource == DIRECTORY {
            Operation::CreateDir
        } else {
            Operation::Write
        };
        let service_operation = if resource == DIRECTORY {
            ServiceOperation("CreateDirectory")
        } else {
            ServiceOperation("CreateFile")
        };

        let req = req
            .extension(operation)
            .extension(service_operation)
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    pub async fn azdls_rename(&self, from: &str, to: &str) -> Result<Response<Buffer>> {
        let source = build_abs_path(&self.root, from);
        let target = build_abs_path(&self.root, to);

        let url = format!(
            "{}/{}/{}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&target)
        );

        let source_path = format!("/{}/{}", self.filesystem, percent_encode_path(&source));

        let req = Request::put(&url)
            .header(X_MS_RENAME_SOURCE, source_path)
            .header(CONTENT_LENGTH, 0)
            .extension(Operation::Rename)
            .extension(ServiceOperation("RenamePath"))
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    /// ref: https://learn.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/update
    pub async fn azdls_append(
        &self,
        path: &str,
        size: Option<u64>,
        position: u64,
        flush: bool,
        close: bool,
        body: Buffer,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let mut url = format!(
            "{}/{}/{}?action=append&position={}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p),
            position
        );

        if flush {
            url.push_str("&flush=true");
        }
        if close {
            url.push_str("&close=true");
        }

        let mut req = Request::patch(&url);

        if let Some(size) = size {
            req = req.header(CONTENT_LENGTH, size)
        }

        let req = req
            .extension(Operation::Write)
            .extension(ServiceOperation("AppendData"))
            .body(body)
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    /// Flush pending data appended by [`azdls_append`].
    pub async fn azdls_flush(
        &self,
        path: &str,
        position: u64,
        close: bool,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let mut url = format!(
            "{}/{}/{}?action=flush&position={}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p),
            position
        );

        if close {
            url.push_str("&close=true");
        }

        let req = Request::patch(&url)
            .header(CONTENT_LENGTH, 0)
            .extension(Operation::Write)
            .extension(ServiceOperation("FlushData"))
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    pub async fn azdls_get_properties(&self, path: &str) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path)
            .trim_end_matches('/')
            .to_string();

        // Use Get Properties without `action=getStatus` to retrieve both
        // system-defined and user-defined properties (x-ms-properties header).
        let url = format!(
            "{}/{}/{}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p)
        );

        let req = Request::head(&url);

        let req = req
            .extension(Operation::Stat)
            .extension(ServiceOperation("GetPathProperties"))
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    pub async fn azdls_stat_metadata(&self, path: &str) -> Result<Metadata> {
        let resp = self.azdls_get_properties(path).await?;

        if resp.status() != StatusCode::OK {
            return Err(parse_error(resp));
        }

        let headers = resp.headers();
        let mut meta = parse_into_metadata(path, headers)?;

        if let Some(version_id) = parse_header_to_str(headers, X_MS_VERSION_ID)? {
            meta.set_version(version_id);
        }

        if let Some(properties) = parse_header_to_str(headers, X_MS_PROPERTIES)? {
            let user_metadata = decode_properties(properties);
            if !user_metadata.is_empty() {
                meta = meta.with_user_metadata(user_metadata);
            }
        }

        let resource = resp
            .headers()
            .get("x-ms-resource-type")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "azdls should return x-ms-resource-type header, but it's missing",
                )
            })?
            .to_str()
            .map_err(|err| {
                Error::new(
                    ErrorKind::Unexpected,
                    "azdls should return x-ms-resource-type header, but it's not a valid string",
                )
                .set_source(err)
            })?;

        match resource {
            FILE => Ok(meta.with_mode(EntryMode::FILE)),
            DIRECTORY => Ok(meta.with_mode(EntryMode::DIR)),
            v => Err(Error::new(
                ErrorKind::Unexpected,
                "azdls returns an unknown x-ms-resource-type",
            )
            .with_context("resource", v)),
        }
    }

    pub async fn azdls_delete(&self, path: &str) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path)
            .trim_end_matches('/')
            .to_string();

        let url = format!(
            "{}/{}/{}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p)
        );

        let req = Request::delete(&url)
            .extension(Operation::Delete)
            .extension(ServiceOperation("DeletePath"))
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    pub async fn azdls_recursive_delete(&self, path: &str) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path)
            .trim_end_matches('/')
            .to_string();

        let base = format!(
            "{}/{}/{}",
            self.endpoint,
            self.filesystem,
            percent_encode_path(&p)
        );

        let mut continuation = String::new();

        loop {
            let mut url = QueryPairsWriter::new(&base).push("recursive", "true");

            if self.enable_hns {
                url = url.push("paginated", "true");
            }

            if !continuation.is_empty() {
                url = url.push("continuation", &percent_encode_path(&continuation));
            }

            let req = Request::delete(url.finish())
                .extension(Operation::Delete)
                .extension(ServiceOperation("RecursiveDeletePath"))
                .body(Buffer::new())
                .map_err(new_request_build_error)?;

            let req = self.sign(req).await?;
            let resp = self.send(req).await?;

            let status = resp.status();
            match status {
                StatusCode::OK | StatusCode::ACCEPTED | StatusCode::NOT_FOUND => {}
                _ => return Err(parse_error(resp)),
            }

            let next = resp
                .headers()
                .get(X_MS_CONTINUATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .trim();

            if next.is_empty() {
                return Ok(resp);
            }

            continuation = next.to_string();
        }
    }

    pub async fn azdls_list(
        &self,
        path: &str,
        continuation: &str,
        limit: Option<usize>,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path)
            .trim_end_matches('/')
            .to_string();

        let mut url = QueryPairsWriter::new(&format!("{}/{}", self.endpoint, self.filesystem))
            .push("resource", "filesystem")
            .push("recursive", "false");
        if !p.is_empty() {
            url = url.push("directory", &percent_encode_path(&p));
        }
        if let Some(limit) = limit {
            url = url.push("maxResults", &limit.to_string());
        }
        if !continuation.is_empty() {
            url = url.push("continuation", &percent_encode_path(continuation));
        }

        let req = Request::get(url.finish())
            .extension(Operation::List)
            .extension(ServiceOperation("ListPaths"))
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        let req = self.sign(req).await?;
        self.send(req).await
    }

    pub async fn azdls_ensure_parent_path(&self, path: &str) -> Result<Option<Response<Buffer>>> {
        let abs_target_path = path.trim_end_matches('/').to_string();
        let abs_target_path = abs_target_path.as_str();
        let mut parts: Vec<&str> = abs_target_path
            .split('/')
            .filter(|x| !x.is_empty())
            .collect();

        if !parts.is_empty() {
            parts.pop();
        }

        if !parts.is_empty() {
            let parent_path = parts.join("/");
            let resp = self
                .azdls_create(&parent_path, DIRECTORY, &OpWrite::default())
                .await?;

            Ok(Some(resp))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());

        let encoded = encode_properties(&metadata);
        let decoded = decode_properties(&encoded);
        assert_eq!(metadata, decoded);
    }

    #[test]
    fn test_decode_standard_pair() {
        // "value" base64-encoded is "dmFsdWU="
        let decoded = decode_properties("key=dmFsdWU=");
        assert_eq!(decoded.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_encode_decode_unicode_value() {
        let mut metadata = HashMap::new();
        metadata.insert("name".to_string(), "hello world".to_string());

        let encoded = encode_properties(&metadata);
        let decoded = decode_properties(&encoded);
        assert_eq!(decoded.get("name"), Some(&"hello world".to_string()));
    }

    #[test]
    fn test_encode_decode_value_with_comma_and_equals() {
        let mut metadata = HashMap::new();
        metadata.insert("data".to_string(), "a=1,b=2".to_string());

        let encoded = encode_properties(&metadata);
        let decoded = decode_properties(&encoded);
        assert_eq!(decoded.get("data"), Some(&"a=1,b=2".to_string()));
    }

    #[test]
    fn test_decode_empty_header() {
        let decoded = decode_properties("");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_malformed_base64_skipped() {
        // Malformed base64 is silently skipped, consistent with other services'
        // best-effort metadata parsing.
        let decoded = decode_properties("key=!!!invalid!!!");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_no_equals_skipped() {
        let decoded = decode_properties("keyonly");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_encode_empty_metadata() {
        let metadata = HashMap::new();
        let encoded = encode_properties(&metadata);
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_decode_multiple_pairs() {
        let mut expected = HashMap::new();
        expected.insert("a".to_string(), "1".to_string());
        expected.insert("b".to_string(), "2".to_string());

        let encoded = encode_properties(&expected);
        let decoded = decode_properties(&encoded);
        assert_eq!(expected, decoded);
    }
}
