#!/usr/bin/env python3
"""Credential-safe S3 version listing and exact version deletion helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

S3_NAMESPACE = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}


class S3BackupApiError(RuntimeError):
    """Raised for credential discovery, listing, signing, or deletion failures."""


@dataclass(frozen=True)
class S3Version:
    key: str
    version_id: str
    kind: str
    is_latest: bool
    last_modified: str
    size: int
    etag: str

    def identity(self) -> tuple[str, str, str]:
        return (self.key, self.version_id, self.kind)


@dataclass(frozen=True)
class S3BackupClient:
    bucket: str
    region: str
    access_key: str
    secret_key: str
    session_token: str = ""

    @classmethod
    def from_container(cls, container: str = "weekly-remote-backup") -> S3BackupClient:
        environment = container_environment(container)
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_S3_BUCKET_NAME"):
            if not environment.get(name):
                raise S3BackupApiError(f"missing_{name.lower()}")
        bucket = environment["AWS_S3_BUCKET_NAME"]
        region = discover_region(
            bucket,
            environment.get("AWS_REGION")
            or environment.get("AWS_DEFAULT_REGION")
            or "us-east-1",
        )
        return cls(
            bucket=bucket,
            region=region,
            access_key=environment["AWS_ACCESS_KEY_ID"],
            secret_key=environment["AWS_SECRET_ACCESS_KEY"],
            session_token=environment.get("AWS_SESSION_TOKEN", ""),
        )

    def request(
        self,
        method: str,
        query_values: dict[str, str],
        *,
        body: bytes = b"",
        extra_headers: dict[str, str] | None = None,
    ) -> bytes:
        host = "s3.amazonaws.com" if self.region == "us-east-1" else f"s3.{self.region}.amazonaws.com"
        canonical_uri = "/" + urllib.parse.quote(self.bucket, safe="")
        canonical_query = urllib.parse.urlencode(
            sorted(query_values.items()), quote_via=urllib.parse.quote
        )
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if self.session_token:
            headers["x-amz-security-token"] = self.session_token
        for name, value in (extra_headers or {}).items():
            headers[name.lower()] = value.strip()
        canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
        signed_headers = ";".join(sorted(headers))
        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n"
            f"{signed_headers}\n{payload_hash}"
        )
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        signature = hmac.new(
            derive_signing_key(self.secret_key, date_stamp, self.region),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        request_headers = {name: value for name, value in headers.items() if name != "host"}
        request_headers["Authorization"] = authorization
        url = f"https://{host}{canonical_uri}?{canonical_query}"
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, data=body if method != "GET" else None, headers=request_headers, method=method),
                timeout=60,
            ) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise S3BackupApiError(f"s3_http_{error.code}") from None
        except Exception as error:
            raise S3BackupApiError("s3_request_error") from error

    def list_versions(self) -> list[S3Version]:
        versions: list[S3Version] = []
        key_marker = ""
        version_marker = ""
        while True:
            query = {"max-keys": "1000", "versions": ""}
            if key_marker:
                query["key-marker"] = key_marker
            if version_marker:
                query["version-id-marker"] = version_marker
            try:
                root = ET.fromstring(self.request("GET", query))
            except ET.ParseError as error:
                raise S3BackupApiError("version_listing_xml_invalid") from error
            for kind in ("Version", "DeleteMarker"):
                for item in root.findall(f"s3:{kind}", S3_NAMESPACE):
                    versions.append(
                        S3Version(
                            key=item.findtext("s3:Key", default="", namespaces=S3_NAMESPACE),
                            version_id=item.findtext("s3:VersionId", default="", namespaces=S3_NAMESPACE),
                            kind=kind,
                            is_latest=item.findtext(
                                "s3:IsLatest", default="false", namespaces=S3_NAMESPACE
                            )
                            == "true",
                            last_modified=item.findtext(
                                "s3:LastModified", default="", namespaces=S3_NAMESPACE
                            ),
                            size=int(item.findtext("s3:Size", default="0", namespaces=S3_NAMESPACE)),
                            etag=item.findtext("s3:ETag", default="", namespaces=S3_NAMESPACE).strip('"'),
                        )
                    )
            if root.findtext("s3:IsTruncated", default="false", namespaces=S3_NAMESPACE) != "true":
                break
            key_marker = root.findtext("s3:NextKeyMarker", default="", namespaces=S3_NAMESPACE)
            version_marker = root.findtext(
                "s3:NextVersionIdMarker", default="", namespaces=S3_NAMESPACE
            )
            if not key_marker:
                raise S3BackupApiError("version_listing_marker_missing")
        versions.sort(key=lambda item: (item.last_modified, item.key, item.version_id), reverse=True)
        return versions

    def delete_versions(self, versions: list[S3Version]) -> int:
        deleted = 0
        for offset in range(0, len(versions), 1000):
            batch = versions[offset : offset + 1000]
            root = ET.Element("Delete")
            for version in batch:
                item = ET.SubElement(root, "Object")
                ET.SubElement(item, "Key").text = version.key
                ET.SubElement(item, "VersionId").text = version.version_id
            ET.SubElement(root, "Quiet").text = "false"
            body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            content_md5 = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()
            try:
                response = ET.fromstring(
                    self.request(
                        "POST",
                        {"delete": ""},
                        body=body,
                        extra_headers={"content-md5": content_md5, "content-type": "application/xml"},
                    )
                )
            except ET.ParseError as error:
                raise S3BackupApiError("delete_response_xml_invalid") from error
            errors = response.findall("s3:Error", S3_NAMESPACE)
            if errors:
                raise S3BackupApiError("delete_response_contains_error")
            deleted += len(response.findall("s3:Deleted", S3_NAMESPACE))
            if deleted < offset + len(batch):
                raise S3BackupApiError("delete_response_incomplete")
        return deleted


def container_environment(container: str) -> dict[str, str]:
    try:
        result = subprocess.run(
            ["docker", "inspect", container],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        inspected: Any = json.loads(result.stdout)[0]
    except (subprocess.SubprocessError, json.JSONDecodeError, IndexError, KeyError) as error:
        raise S3BackupApiError("container_inspection_error") from error
    return {
        item.split("=", 1)[0]: item.split("=", 1)[1]
        for item in inspected["Config"].get("Env", [])
        if "=" in item
    }


def discover_region(bucket: str, default_region: str) -> str:
    url = "https://s3.amazonaws.com/" + urllib.parse.quote(bucket, safe="")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=20) as response:
            return response.headers.get("x-amz-bucket-region") or default_region
    except urllib.error.HTTPError as error:
        return error.headers.get("x-amz-bucket-region") or default_region
    except Exception as error:
        raise S3BackupApiError("region_discovery_error") from error


def derive_signing_key(secret: str, date: str, region: str) -> bytes:
    date_key = hmac.new(("AWS4" + secret).encode(), date.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
