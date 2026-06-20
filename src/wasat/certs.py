"""Client certificate generation and storage management for Gemini connections."""

##############################################################################
# Python imports.
import asyncio
import atexit
import json
import re
import shutil
import tempfile
from collections.abc import Callable, Coroutine
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

##############################################################################
# Cryptography imports.
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

##############################################################################
# Local imports.
from .uri import GeminiURI

##############################################################################
type ClientCertCallback = Callable[
    [GeminiURI, ClientCertificateStore],
    Coroutine[None, None, Literal["transient", "persistent", "ignore"]],
]
"""Async callback function signature for resolving a client certificate requirement."""

_transient_dirs: list[Path] = []
"""Global registry of transient certificate directories to clean up at process exit."""


##############################################################################
def _cleanup_transient_dirs() -> None:
    """Clean up all registered transient directories."""
    for path in _transient_dirs:
        with suppress(Exception):
            if path.exists():
                shutil.rmtree(path)


atexit.register(_cleanup_transient_dirs)


##############################################################################
def _safe_filename(scope: str) -> str:
    """Convert a scope string into a safe base filename.

    Args:
        scope: The scope string.

    Returns:
        A safe filename prefix with invalid characters replaced.
    """
    safe = re.sub(r"[^a-zA-Z0-9.-]", "_", scope)
    safe = re.sub(r"_+", "_", safe)
    return safe.strip("_")


##############################################################################
def get_candidate_scopes(uri: GeminiURI) -> list[str]:
    """Get candidate certificate scopes for a URI, sorted by specificity.

    Args:
        uri: The GeminiURI to generate scopes for.

    Returns:
        A list of scope strings in descending order of specificity.
    """
    host = uri.host.lower()
    port = uri.port
    path = uri.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    parts = path.split("/")
    path_prefixes: list[str] = []
    for i in range(len(parts), 0, -1):
        prefix = "/".join(parts[:i])
        if prefix == "":
            prefix = "/"
        else:
            if i < len(parts) and not prefix.endswith("/"):
                prefix += "/"
        path_prefixes.append(prefix)

    seen: set[str] = set()
    unique_prefixes: list[str] = []
    for p in path_prefixes:
        if p not in seen:
            seen.add(p)
            unique_prefixes.append(p)

    candidates: list[str] = []
    for prefix in unique_prefixes:
        candidates.append(f"{host}:{port}{prefix}")
    for prefix in unique_prefixes:
        candidates.append(f"{host}{prefix}")

    return candidates


##############################################################################
def generate_self_signed_cert(
    common_name: str,
    *,
    key_type: Literal["ecdsa", "rsa"] = "ecdsa",
    rsa_key_size: int = 2048,
    ecdsa_curve: str = "secp256r1",
    valid_days: int = 365,
    email: str | None = None,
    user_id: str | None = None,
    domain: str | None = None,
    organisation: str | None = None,
    country: str | None = None,
) -> tuple[bytes, bytes]:
    """Generate a self-signed client certificate and private key.

    Args:
        common_name: The Common Name (CN) for the certificate.
        key_type: The key type to generate ('ecdsa' or 'rsa').
        rsa_key_size: RSA key size in bits.
        ecdsa_curve: ECDSA curve name.
        valid_days: Certificate validity in days.
        email: Optional email address.
        user_id: Optional user identifier.
        domain: Optional domain name for Subject Alternative Name.
        organisation: Optional organisation name.
        country: Optional two-letter country code.

    Returns:
        A tuple containing (cert_pem, key_pem) as bytes.

    Raises:
        ValueError: If key_type, key size, curve, or country code is unsupported.
    """
    private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    if key_type == "ecdsa":
        curve: ec.EllipticCurve
        curve_name = ecdsa_curve.lower()
        if curve_name == "secp256r1":
            curve = ec.SECP256R1()
        elif curve_name == "secp384r1":
            curve = ec.SECP384R1()
        else:
            raise ValueError(f"Unsupported ECDSA curve: {ecdsa_curve}")
        private_key = ec.generate_private_key(curve)
    elif key_type == "rsa":
        if rsa_key_size not in (2048, 3072, 4096):
            raise ValueError(f"Unsupported RSA key size: {rsa_key_size}")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_key_size,
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if email is not None:
        subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    if user_id is not None:
        subject_attrs.append(x509.NameAttribute(NameOID.USER_ID, user_id))
    if organisation is not None:
        subject_attrs.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation)
        )
    if country is not None:
        if len(country) != 2:
            raise ValueError("Country code must be exactly 2 characters (e.g. 'GB')")
        subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))

    subject = issuer = x509.Name(subject_attrs)

    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    if domain is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )

    cert = builder.sign(private_key, hashes.SHA256())

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    return cert_pem, key_pem


##############################################################################
@runtime_checkable
class ClientCertificateStore(Protocol):
    """Protocol defining the interface for client certificate storage and retrieval."""

    async def get_credentials(self, uri: GeminiURI) -> tuple[Path, Path] | None:
        """Retrieve the certificate and private key paths matching the given URI.

        This should perform path prefix matching to find the most specific
        matching certificate for the requested host, port, and path.

        Args:
            uri: The target GeminiURI.

        Returns:
            A tuple of (cert_path, key_path) or None if no certificate is stored
            for this URI's scope.
        """
        ...

    async def create_credentials(
        self,
        uri: GeminiURI,
        *,
        transient: bool = False,
        common_name: str | None = None,
        valid_days: int = 365,
        key_type: Literal["ecdsa", "rsa"] = "ecdsa",
        rsa_key_size: int = 2048,
        ecdsa_curve: str = "secp256r1",
        email: str | None = None,
        user_id: str | None = None,
        domain: str | None = None,
        organisation: str | None = None,
        country: str | None = None,
    ) -> tuple[Path, Path]:
        """Generate and save a new self-signed client certificate and private key.

        Args:
            uri: The target GeminiURI.
            transient: If True, the certificate is generated in a temporary
                directory and not registered in the persistent store.
            common_name: The Common Name (CN) for the certificate. Defaults to the host.
            valid_days: Number of days the certificate should be valid.
            key_type: The key type to generate ('ecdsa' or 'rsa').
            rsa_key_size: RSA key size in bits.
            ecdsa_curve: ECDSA curve name.
            email: Optional email address.
            user_id: Optional user identifier.
            domain: Optional domain name for Subject Alternative Name.
            organisation: Optional organisation name.
            country: Optional two-letter country code.

        Returns:
            A tuple of (cert_path, key_path) representing the generated certificate and key.
        """
        ...

    async def delete_credentials(self, uri: GeminiURI) -> bool:
        """Delete the certificate and key associated with the matching scope.

        Args:
            uri: The target GeminiURI.

        Returns:
            True if deleted, False if no matching scope was found.
        """
        ...

    async def close(self) -> None:
        """Close the store, cleaning up transient resources if necessary."""
        ...


##############################################################################
class FileClientCertificateStore(ClientCertificateStore):
    """File-based client certificate and key store.

    Saves certificate files as PEM pairs and maintains a `certs.json` registry file
    mapping Gemini scopes (host[:port]/path) to certificate filenames.
    """

    def __init__(self, store_dir: str | Path) -> None:
        """Initialise the file-based certificate store.

        Args:
            store_dir: The directory where certificates, keys, and the index are stored.
        """
        self.store_dir = Path(store_dir)
        """The directory path for storing certificates and index."""
        self._lock = asyncio.Lock()
        """Lock to synchronise file access and cache operations."""
        self._index: dict[str, dict[str, str]] = {}
        """In-memory cache of the loaded certs.json index."""
        self._transient_index: dict[str, tuple[Path, Path]] = {}
        """In-memory index mapping scopes to transient certificate files."""
        self._temp_dir: Path | None = None
        """Temporary directory for transient certificates, if any are created."""
        self._loaded = False
        """Flag indicating whether the persistent index has been loaded."""

    def _load_sync(self) -> None:
        """Load the certificate index from disk synchronously."""
        index_path = self.store_dir / "certs.json"
        if not index_path.exists():
            return
        with suppress(Exception), open(index_path, encoding="utf-8") as f:
            self._index = json.load(f)

    def _save_sync(self) -> None:
        """Save the certificate index to disk synchronously."""
        self.store_dir.mkdir(parents=True, exist_ok=True)
        index_path = self.store_dir / "certs.json"
        try:
            with open(index_path, "w", encoding="utf-8") as f:
                json.dump(self._index, f, indent=4)
        except Exception as e:
            raise RuntimeError(
                f"Failed to write to certificate store file {index_path}: {e}"
            ) from e

    async def _ensure_loaded(self) -> None:
        """Ensure the persistent index is loaded from disk."""
        if not self._loaded:
            await asyncio.to_thread(self._load_sync)
            self._loaded = True

    async def get_credentials(self, uri: GeminiURI) -> tuple[Path, Path] | None:
        """Retrieve the certificate and private key paths matching the given URI.

        Args:
            uri: The target GeminiURI.

        Returns:
            A tuple of (cert_path, key_path) or None if no certificate is stored
            for this URI's scope.
        """
        async with self._lock:
            candidates = get_candidate_scopes(uri)

            # Check transient index first
            for candidate in candidates:
                if candidate in self._transient_index:
                    cert_path, key_path = self._transient_index[candidate]
                    if cert_path.exists() and key_path.exists():
                        return cert_path, key_path

            # Check persistent index
            await self._ensure_loaded()
            for candidate in candidates:
                if candidate in self._index:
                    entry = self._index[candidate]
                    cert_rel = entry.get("cert")
                    key_rel = entry.get("key")
                    if cert_rel and key_rel:
                        cert_path = self.store_dir / cert_rel
                        key_path = self.store_dir / key_rel
                        if cert_path.exists() and key_path.exists():
                            return cert_path, key_path
            return None

    async def create_credentials(
        self,
        uri: GeminiURI,
        *,
        transient: bool = False,
        common_name: str | None = None,
        valid_days: int = 365,
        key_type: Literal["ecdsa", "rsa"] = "ecdsa",
        rsa_key_size: int = 2048,
        ecdsa_curve: str = "secp256r1",
        email: str | None = None,
        user_id: str | None = None,
        domain: str | None = None,
        organisation: str | None = None,
        country: str | None = None,
    ) -> tuple[Path, Path]:
        """Generate and save a new self-signed client certificate and private key.

        Args:
            uri: The target GeminiURI.
            transient: If True, the certificate is generated in a temporary
                directory and not registered in the persistent store.
            common_name: The Common Name (CN) for the certificate. Defaults to the host.
            valid_days: Number of days the certificate should be valid.
            key_type: The key type to generate ('ecdsa' or 'rsa').
            rsa_key_size: RSA key size in bits.
            ecdsa_curve: ECDSA curve name.
            email: Optional email address.
            user_id: Optional user identifier.
            domain: Optional domain name for Subject Alternative Name.
            organisation: Optional organisation name.
            country: Optional two-letter country code.

        Returns:
            A tuple of (cert_path, key_path) representing the generated certificate and key.
        """
        host = uri.host
        cn = common_name or host
        cert_pem, key_pem = await asyncio.to_thread(
            generate_self_signed_cert,
            cn,
            key_type=key_type,
            rsa_key_size=rsa_key_size,
            ecdsa_curve=ecdsa_curve,
            valid_days=valid_days,
            email=email,
            user_id=user_id,
            domain=domain,
            organisation=organisation,
            country=country,
        )

        port = uri.port
        path = uri.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        scope = f"{host.lower()}:{port}{path}"

        async with self._lock:
            if transient:
                if self._temp_dir is None:
                    temp_dir_path = await asyncio.to_thread(
                        tempfile.mkdtemp, prefix="wasat_transient_"
                    )
                    self._temp_dir = Path(temp_dir_path)
                    _transient_dirs.append(self._temp_dir)

                safe_base = _safe_filename(scope)
                cert_path = self._temp_dir / f"{safe_base}.crt"
                key_path = self._temp_dir / f"{safe_base}.key"

                await asyncio.to_thread(cert_path.write_bytes, cert_pem)
                await asyncio.to_thread(key_path.write_bytes, key_pem)

                self._transient_index[scope] = (cert_path, key_path)
                return cert_path, key_path
            else:
                await self._ensure_loaded()
                self.store_dir.mkdir(parents=True, exist_ok=True)
                safe_base = _safe_filename(scope)
                cert_file = f"{safe_base}.crt"
                key_file = f"{safe_base}.key"

                cert_path = self.store_dir / cert_file
                key_path = self.store_dir / key_file

                await asyncio.to_thread(cert_path.write_bytes, cert_pem)
                await asyncio.to_thread(key_path.write_bytes, key_pem)

                self._index[scope] = {
                    "cert": cert_file,
                    "key": key_file,
                }
                await asyncio.to_thread(self._save_sync)
                return cert_path, key_path

    async def delete_credentials(self, uri: GeminiURI) -> bool:
        """Delete the certificate and key associated with the matching scope.

        Args:
            uri: The target GeminiURI.

        Returns:
            True if deleted, False if no matching scope was found.
        """
        async with self._lock:
            candidates = get_candidate_scopes(uri)

            # Check transient index
            for candidate in candidates:
                if candidate in self._transient_index:
                    cert_path, key_path = self._transient_index.pop(candidate)
                    for p in (cert_path, key_path):
                        with suppress(Exception):
                            if p.exists():
                                p.unlink()
                    return True

            # Check persistent index
            await self._ensure_loaded()
            for candidate in candidates:
                if candidate in self._index:
                    entry = self._index.pop(candidate)
                    cert_rel = entry.get("cert")
                    key_rel = entry.get("key")
                    if cert_rel:
                        with suppress(Exception):
                            (self.store_dir / cert_rel).unlink(missing_ok=True)
                    if key_rel:
                        with suppress(Exception):
                            (self.store_dir / key_rel).unlink(missing_ok=True)
                    await asyncio.to_thread(self._save_sync)
                    return True
            return False

    async def close(self) -> None:
        """Close the store, cleaning up transient directories if any were created."""
        async with self._lock:
            if self._temp_dir is not None:
                with suppress(Exception):
                    if self._temp_dir.exists():
                        await asyncio.to_thread(shutil.rmtree, self._temp_dir)
                    if self._temp_dir in _transient_dirs:
                        _transient_dirs.remove(self._temp_dir)
                self._temp_dir = None
                self._transient_index.clear()


### certs.py ends here
