"""Trust models and certificate verification for Gemini connections."""

import asyncio
import hashlib
import pathlib
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable


def get_cert_fingerprint(cert_der: bytes) -> str:
    """Calculate the SHA-256 fingerprint of a DER-encoded certificate.

    Args:
        cert_der: The raw DER-encoded certificate bytes.

    Returns:
        The hex-encoded SHA-256 fingerprint.
    """
    return hashlib.sha256(cert_der).hexdigest().lower()


@runtime_checkable
class TrustStore(Protocol):
    """Protocol defining the interface for certificate fingerprint stores."""

    async def verify(self, host: str, port: int, cert_der: bytes) -> bool:
        """Verify the peer certificate against the stored fingerprint.

        Args:
            host: The remote hostname.
            port: The remote port.
            cert_der: The DER-encoded certificate.

        Returns:
            True if the certificate is trusted, False otherwise.
        """
        ...

    async def save(self, host: str, port: int, cert_der: bytes) -> None:
        """Save a peer certificate fingerprint to the trust store.

        Args:
            host: The remote hostname.
            port: The remote port.
            cert_der: The DER-encoded certificate.
        """
        ...

    async def get_fingerprint(self, host: str, port: int) -> str | None:
        """Retrieve the stored fingerprint for a host/port, if any.

        Args:
            host: The remote hostname.
            port: The remote port.

        Returns:
            The SHA-256 fingerprint string (hex) or None.
        """
        ...


class FileTrustStore(TrustStore):
    """A standard file-based TOFU (Trust On First Use) store.

    Stores fingerprints in a simple text file format similar to known_hosts.
    """

    def __init__(self, filepath: str | pathlib.Path) -> None:
        """Initialise the file-based trust store.

        Args:
            filepath: The path to the file storing fingerprints.
        """
        self.filepath = pathlib.Path(filepath)
        self._lock = asyncio.Lock()
        self._cache: dict[tuple[str, int], str] = {}
        self._loaded = False

    def _load_sync(self) -> None:
        """Load the known hosts from file synchronously."""
        if not self.filepath.exists():
            return
        try:
            with open(self.filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        host_port, fingerprint = parts[0], parts[1]
                        if ":" in host_port:
                            host, port_str = host_port.rsplit(":", 1)
                            try:
                                port = int(port_str)
                            except ValueError:
                                continue
                        else:
                            host = host_port
                            port = 1965

                        if fingerprint.startswith("sha256:"):
                            fingerprint = fingerprint[7:]
                        self._cache[(host.lower(), port)] = fingerprint.lower()
        except Exception:
            # Fail silently on load errors during initialisation
            pass

    def _save_sync(self) -> None:
        """Save the known hosts to file synchronously."""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write("# Wasat Gemini Known Hosts\n")
                f.write(f"# Generated at {datetime.now(UTC).isoformat()}\n")
                for (host, port), fingerprint in self._cache.items():
                    f.write(
                        f"{host}:{port} sha256:{fingerprint} {datetime.now(UTC).isoformat()}\n"
                    )
        except Exception as e:
            raise RuntimeError(
                f"Failed to write to trust store file {self.filepath}: {e}"
            ) from e

    async def _ensure_loaded(self) -> None:
        """Ensure the store is loaded from disk."""
        if not self._loaded:
            await asyncio.to_thread(self._load_sync)
            self._loaded = True

    async def get_fingerprint(self, host: str, port: int) -> str | None:
        """Retrieve the stored fingerprint for a host/port.

        Args:
            host: The remote hostname.
            port: The remote port.

        Returns:
            The SHA-256 fingerprint string (hex) or None.
        """
        async with self._lock:
            await self._ensure_loaded()
            return self._cache.get((host.lower(), port))

    async def verify(self, host: str, port: int, cert_der: bytes) -> bool:
        """Verify the peer certificate against the stored fingerprint.

        Args:
            host: The remote hostname.
            port: The remote port.
            cert_der: The DER-encoded certificate.

        Returns:
            True if the fingerprint matches the stored one, False otherwise.
        """
        fingerprint = get_cert_fingerprint(cert_der)
        stored_fingerprint = await self.get_fingerprint(host, port)
        if stored_fingerprint is None:
            return False
        return stored_fingerprint == fingerprint

    async def save(self, host: str, port: int, cert_der: bytes) -> None:
        """Save the peer certificate fingerprint to the store.

        Args:
            host: The remote hostname.
            port: The remote port.
            cert_der: The DER-encoded certificate.
        """
        fingerprint = get_cert_fingerprint(cert_der)
        async with self._lock:
            await self._ensure_loaded()
            self._cache[(host.lower(), port)] = fingerprint
            await asyncio.to_thread(self._save_sync)


### trust.py ends here
