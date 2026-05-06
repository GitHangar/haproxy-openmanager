"""
Audit Tur 5 / Commit 8c-2: CertificateRequest input validation tests.
"""
import pytest
import sys
import os
from pydantic import ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from routers.letsencrypt import CertificateRequest


class TestCertificateRequestDomains:
    def test_valid_single_domain(self):
        body = CertificateRequest(domains=["example.com"])
        assert body.domains == ["example.com"]

    def test_valid_multi_domain(self):
        body = CertificateRequest(domains=["example.com", "www.example.com"])
        assert body.domains == ["example.com", "www.example.com"]

    def test_empty_domains_list_rejected(self):
        with pytest.raises(ValidationError):
            CertificateRequest(domains=[])

    def test_empty_string_rejected(self):
        with pytest.raises(ValidationError):
            CertificateRequest(domains=[""])

    def test_invalid_chars_rejected(self):
        with pytest.raises(ValidationError):
            CertificateRequest(domains=["bad..domain"])
        with pytest.raises(ValidationError):
            CertificateRequest(domains=["bad domain.com"])
        with pytest.raises(ValidationError):
            CertificateRequest(domains=[".starts-with-dot.com"])

    def test_too_long_domain_rejected(self):
        with pytest.raises(ValidationError):
            CertificateRequest(domains=["a" * 254 + ".com"])

    def test_wildcard_accepted(self):
        body = CertificateRequest(domains=["*.example.com"])
        assert body.domains == ["*.example.com"]

    def test_too_many_domains_rejected(self):
        with pytest.raises(ValidationError):
            CertificateRequest(domains=[f"d{i}.example.com" for i in range(101)])

    def test_normalization_lowercases(self):
        body = CertificateRequest(domains=["Example.COM"])
        assert body.domains == ["example.com"]


class TestCertificateRequestClusterIds:
    def test_default_is_empty_list_not_none(self):
        body = CertificateRequest(domains=["example.com"])
        assert body.cluster_ids == []
        assert isinstance(body.cluster_ids, list)

    def test_provided_cluster_ids_kept(self):
        body = CertificateRequest(domains=["example.com"], cluster_ids=[1, 2, 3])
        assert body.cluster_ids == [1, 2, 3]
