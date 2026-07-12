"""Tests for the trust store module."""

##############################################################################
# Python imports.
import asyncio
import tempfile
from pathlib import Path

# Local imports.
from wasat import Client, FileTrustStore


##############################################################################
class TestFileTrustStore:
    """Test suite for the FileTrustStore class."""

    def test_empty_store(self) -> None:
        """Test that an empty trust store returns no hosts or fingerprints."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                hosts_file = Path(tmpdir) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                hosts = await trust_store.get_hosts()
                assert hosts == []

                fingerprint = await trust_store.get_fingerprint("example.com", 1965)
                assert fingerprint is None

        asyncio.run(run())

    def test_save_and_retrieve_hosts(self) -> None:
        """Test saving certificate fingerprints and retrieving hosts."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                hosts_file = Path(tmpdir) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                cert_der1 = b"cert_one"
                cert_der2 = b"cert_two"

                await trust_store.save("example.com", 1965, cert_der1)
                await trust_store.save("another.com", 1966, cert_der2)

                hosts = await trust_store.get_hosts()
                assert len(hosts) == 2
                assert ("example.com", 1965) in hosts
                assert ("another.com", 1966) in hosts

                # Test persistence/re-loading
                new_trust_store = FileTrustStore(hosts_file)
                loaded_hosts = await new_trust_store.get_hosts()
                assert len(loaded_hosts) == 2
                assert ("example.com", 1965) in loaded_hosts
                assert ("another.com", 1966) in loaded_hosts

        asyncio.run(run())

    def test_verify_known_hosts(self) -> None:
        """Test verifying certificates against stored fingerprints."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                hosts_file = Path(tmpdir) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                cert_der = b"my_certificate"
                await trust_store.save("example.com", 1965, cert_der)

                # Verification succeeds with matching certificate
                assert await trust_store.verify("example.com", 1965, cert_der) is True

                # Verification fails with different certificate
                assert (
                    await trust_store.verify("example.com", 1965, b"other_cert")
                    is False
                )

                # Verification fails for untrusted host
                assert (
                    await trust_store.verify("untrusted.com", 1965, cert_der) is False
                )

        asyncio.run(run())

    def test_client_trust_store_property(self) -> None:
        """Test that the trust_store property is correctly exposed on the Client."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                hosts_file = Path(tmpdir) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                # Client with TOFU mode and custom trust store
                client_tofu = Client(verify_mode="tofu", trust_store=trust_store)
                assert client_tofu.trust_store is trust_store

                # Client with default TOFU mode
                client_default = Client(verify_mode="tofu")
                assert isinstance(client_default.trust_store, FileTrustStore)

                # Client with CA verification mode should have None trust store
                client_ca = Client(verify_mode="ca")
                assert client_ca.trust_store is None

        asyncio.run(run())


### test_trust.py ends here
