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
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                hosts = await trust_store.get_hosts()
                assert hosts == []

                fingerprint = await trust_store.get_fingerprint("example.com", 1965)
                assert fingerprint is None

        asyncio.run(run())

    def test_save_and_retrieve_hosts(self) -> None:
        """Test saving certificate fingerprints and retrieving hosts."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
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
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
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
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
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

    def test_forget_existing_host(self) -> None:
        """Test forgetting an existing host from the trust store."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                cert_der1 = b"cert_one"
                cert_der2 = b"cert_two"

                await trust_store.save("example.com", 1965, cert_der1)
                await trust_store.save("another.com", 1966, cert_der2)

                assert len(await trust_store.get_hosts()) == 2

                # Forget example.com:1965
                assert await trust_store.forget("example.com", 1965) is True

                hosts = await trust_store.get_hosts()
                assert len(hosts) == 1
                assert ("another.com", 1966) in hosts
                assert ("example.com", 1965) not in hosts

                assert await trust_store.get_fingerprint("example.com", 1965) is None
                assert await trust_store.verify("example.com", 1965, cert_der1) is False

                # Test persistence
                new_trust_store = FileTrustStore(hosts_file)
                loaded_hosts = await new_trust_store.get_hosts()
                assert len(loaded_hosts) == 1
                assert ("another.com", 1966) in loaded_hosts

        asyncio.run(run())

    def test_forget_non_existent_host(self) -> None:
        """Test forgetting a non-existent host returns False."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                assert await trust_store.forget("nonexistent.com", 1965) is False

                await trust_store.save("example.com", 1965, b"cert_data")
                assert await trust_store.forget("nonexistent.com", 1965) is False
                assert await trust_store.forget("example.com", 1966) is False

        asyncio.run(run())

    def test_forget_default_port(self) -> None:
        """Test forgetting a host using the default Gemini port."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                await trust_store.save("example.com", 1965, b"cert_data")
                assert await trust_store.forget("example.com") is True
                assert await trust_store.get_fingerprint("example.com", 1965) is None

        asyncio.run(run())

    def test_forget_case_insensitive(self) -> None:
        """Test forgetting a host is case-insensitive."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                await trust_store.save("Example.Com", 1965, b"cert_data")
                assert await trust_store.forget("EXAMPLE.COM", 1965) is True
                assert await trust_store.get_fingerprint("example.com", 1965) is None

        asyncio.run(run())


### test_trust.py ends here
