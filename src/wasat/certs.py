"""Client certificate generation and storage management for Gemini connections."""

from __future__ import annotations

##############################################################################
# Python imports.
import asyncio
import atexit
import json
import re
import shutil
import tempfile
from collections.abc import Callable, Coroutine, Sequence
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
from .trust import get_cert_fingerprint
from .uri import GEMINI_DEFAULT_PORT, GeminiURI

##############################################################################
type ClientCertCallback = Callable[
    [GeminiURI, ClientCertificateStore],
    Coroutine[None, None, Literal["transient", "persistent", "ignore"]],
]
"""Async callback function signature for resolving a client certificate requirement.

This callback is invoked when a client certificate is required. It receives the
requested [GeminiURI][wasat.uri.GeminiURI] and the [ClientCertificateStore][wasat.certs.ClientCertificateStore]
instance to query or update.
"""

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
def normalize_scope(scope_or_uri: str | GeminiURI) -> str:
    """Normalise a GeminiURI or scope string into a canonical scope string.

    Args:
        scope_or_uri: A GeminiURI instance or a scope string (e.g. 'example.com/path'
            or 'gemini://example.com:1965/path').

    Returns:
        The canonical scope string in 'host:port/path' format.
    """
    if isinstance(scope_or_uri, GeminiURI):
        host = scope_or_uri.host.lower()
        port = scope_or_uri.port
        path = scope_or_uri.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"{host}:{port}{path}"

    s = str(scope_or_uri).strip()
    if s.startswith("gemini://") or "://" in s:
        uri = GeminiURI(s)
        return normalize_scope(uri)

    if "/" in s:
        host_port, path = s.split("/", 1)
        path = "/" + path
    else:
        host_port, path = s, "/"

    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host = host_port
            port = GEMINI_DEFAULT_PORT
    else:
        host = host_port
        port = GEMINI_DEFAULT_PORT

    return f"{host.lower()}:{port}{path}"


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
        path_prefixes.append(prefix)
        if prefix != "/" and not prefix.endswith("/"):
            path_prefixes.append(prefix + "/")

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
    valid_days: int | None = 365,
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
        valid_days: Certificate validity in days. If None, the certificate
            will expire on 9999-12-31.
        email: Optional email address.
        user_id: Optional user identifier.
        domain: Optional domain name for Subject Alternative Name.
        organisation: Optional organisation name.
        country: Optional two-letter country code.

    Returns:
        A tuple containing (cert_pem, key_pem) as bytes.

    Raises:
        ValueError: If the key type is unsupported, the RSA key size is not
            one of 2048, 3072, or 4096, the ECDSA curve is not 'secp256r1'
            or 'secp384r1', or the country code is not exactly two characters.
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
    expiry = (
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
        if valid_days is None
        else now + timedelta(days=valid_days)
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(expiry)
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
class ClientCertificate:
    """Representation of a client TLS X.509 certificate and private key pair."""

    def __init__(
        self,
        cert_pem: bytes,
        *,
        key_pem: bytes | None = None,
        cert_path: Path | None = None,
        key_path: Path | None = None,
        scopes: tuple[str, ...] | list[str] = (),
    ) -> None:
        """Initialise the ClientCertificate object.

        Args:
            cert_pem: The raw PEM-encoded certificate bytes.
            key_pem: Optional raw PEM-encoded private key bytes.
            cert_path: Optional filesystem path to the certificate PEM file.
            key_path: Optional filesystem path to the private key PEM file.
            scopes: Tuple or list of Gemini scopes associated with this certificate.
        """
        self._cert_pem = cert_pem
        """The raw PEM-encoded certificate bytes."""
        self._key_pem = key_pem
        """The raw PEM-encoded private key bytes."""
        self._cert_path = cert_path
        """The filesystem path to the certificate file, if saved on disk."""
        self._key_path = key_path
        """The filesystem path to the private key file, if saved on disk."""
        self._scopes = tuple(scopes)
        """The scopes associated with this certificate."""
        self._cert = x509.load_pem_x509_certificate(cert_pem)
        """The parsed cryptography X.509 Certificate object."""

    @classmethod
    def from_file(
        cls,
        cert_path: str | Path,
        key_path: str | Path | None = None,
        scopes: Sequence[str] = (),
    ) -> ClientCertificate:
        """Construct a ClientCertificate instance from PEM files on disk.

        Args:
            cert_path: Path to the certificate PEM file.
            key_path: Optional path to the private key PEM file.
            scopes: Sequence of Gemini scopes associated with this certificate.

        Returns:
            A new ClientCertificate instance.
        """
        c_path = Path(cert_path)
        cert_pem = c_path.read_bytes()
        k_path = Path(key_path) if key_path is not None else None
        key_pem = (
            k_path.read_bytes() if k_path is not None and k_path.exists() else None
        )
        return cls(
            cert_pem=cert_pem,
            key_pem=key_pem,
            cert_path=c_path,
            key_path=k_path,
            scopes=tuple(scopes),
        )

    @property
    def cert_path(self) -> Path | None:
        """The filesystem path to the certificate PEM file, or None if in-memory."""
        return self._cert_path

    @property
    def key_path(self) -> Path | None:
        """The filesystem path to the private key PEM file, or None if in-memory."""
        return self._key_path

    @property
    def cert_pem(self) -> bytes:
        """The raw PEM-encoded certificate bytes."""
        return self._cert_pem

    @property
    def raw_pem(self) -> bytes:
        """The raw PEM-encoded certificate bytes."""
        return self._cert_pem

    @property
    def key_pem(self) -> bytes | None:
        """The raw PEM-encoded private key bytes, or None if not available."""
        return self._key_pem

    @property
    def scopes(self) -> tuple[str, ...]:
        """The tuple of Gemini scopes associated with this certificate."""
        return self._scopes

    @property
    def raw_x509(self) -> x509.Certificate:
        """The underlying cryptography X.509 Certificate instance."""
        return self._cert

    @property
    def subject_common_name(self) -> str | None:
        """The Common Name (CN) from the certificate subject, or None if not present."""
        attributes = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def issuer_common_name(self) -> str | None:
        """The Common Name (CN) from the certificate issuer, or None if not present."""
        attributes = self._cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def email(self) -> str | None:
        """The email address from the certificate subject, or None if not present."""
        attributes = self._cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def user_id(self) -> str | None:
        """The user ID from the certificate subject, or None if not present."""
        attributes = self._cert.subject.get_attributes_for_oid(NameOID.USER_ID)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def organisation(self) -> str | None:
        """The organisation name from the certificate subject, or None if not present."""
        attributes = self._cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def country(self) -> str | None:
        """The two-letter country code from the certificate subject, or None."""
        attributes = self._cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def subject(self) -> str:
        """The certificate subject formatted as an RFC 4514 string."""
        return self._cert.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        """The certificate issuer formatted as an RFC 4514 string."""
        return self._cert.issuer.rfc4514_string()

    @property
    def not_before(self) -> datetime:
        """The UTC timestamp from which the certificate is valid."""
        return self._cert.not_valid_before_utc

    @property
    def not_after(self) -> datetime:
        """The UTC timestamp at which the certificate expires."""
        return self._cert.not_valid_after_utc

    @property
    def is_expired(self) -> bool:
        """Whether the certificate is currently expired."""
        return datetime.now(UTC) > self.not_after

    @property
    def is_self_signed(self) -> bool:
        """Whether the certificate is self-signed (subject equals issuer)."""
        return self._cert.subject == self._cert.issuer

    @property
    def subject_alternative_names(self) -> tuple[str, ...]:
        """Tuple of Subject Alternative Names (DNS names) in the certificate."""
        try:
            extension = self._cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            return tuple(extension.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            return ()

    @property
    def serial_number(self) -> int:
        """The certificate serial number."""
        return self._cert.serial_number

    @property
    def fingerprint(self) -> str:
        """The hex-encoded SHA-256 fingerprint of the certificate."""
        return get_cert_fingerprint(self._cert.public_bytes(serialization.Encoding.DER))

    @property
    def key_type(self) -> str:
        """The type of public key in the certificate ('ecdsa', 'rsa', or 'unknown')."""
        public_key = self._cert.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "ecdsa"
        if isinstance(public_key, rsa.RSAPublicKey):
            return "rsa"
        return "unknown"

    @property
    def key_size(self) -> int | None:
        """The key size in bits (for RSA) or curve size (for ECDSA), or None."""
        public_key = self._cert.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.curve.key_size
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size
        return None

    def __repr__(self) -> str:
        """Representation of the ClientCertificate instance."""
        cn = self.subject_common_name or ""
        return f"<ClientCertificate cn={cn!r} fingerprint={self.fingerprint[:8]!r} scopes={self.scopes!r}>"


##############################################################################
@runtime_checkable
class ClientCertificateStore(Protocol):
    """Protocol defining the interface for client certificate storage and retrieval."""

    async def list_certificates(self) -> list[ClientCertificate]:
        """List all client certificates stored in this certificate store.

        Returns:
            A list of ClientCertificate instances.
        """
        ...

    async def get_certificate(
        self, identifier: str | Path | GeminiURI
    ) -> ClientCertificate | None:
        """Retrieve a client certificate by scope, URI, fingerprint, or filename.

        Args:
            identifier: A GeminiURI, scope string, SHA-256 fingerprint, or
                certificate file path/name.

        Returns:
            The matching ClientCertificate instance, or None if not found.
        """
        ...

    async def create_certificate(
        self,
        name: str,
        *,
        scopes: Sequence[str | GeminiURI] = (),
        transient: bool = False,
        common_name: str | None = None,
        valid_days: int | None = 365,
        key_type: Literal["ecdsa", "rsa"] = "ecdsa",
        rsa_key_size: int = 2048,
        ecdsa_curve: str = "secp256r1",
        email: str | None = None,
        user_id: str | None = None,
        domain: str | None = None,
        organisation: str | None = None,
        country: str | None = None,
    ) -> ClientCertificate:
        """Generate and save a new client certificate and private key.

        Args:
            name: Base name for the certificate file.
            scopes: Sequence of Gemini scopes or URIs to associate with the certificate.
            transient: If True, the certificate is generated in a temporary
                directory and not registered in the persistent store.
            common_name: The Common Name (CN) for the certificate. Defaults to `name`.
            valid_days: Number of days the certificate should be valid. If None, the
                certificate will expire on 9999-12-31.
            key_type: The key type to generate ('ecdsa' or 'rsa').
            rsa_key_size: RSA key size in bits.
            ecdsa_curve: ECDSA curve name.
            email: Optional email address.
            user_id: Optional user identifier.
            domain: Optional domain name for Subject Alternative Name.
            organisation: Optional organisation name.
            country: Optional two-letter country code.

        Returns:
            The created ClientCertificate instance.

        Raises:
            ValueError: If the key type is unsupported, the RSA key size is not
                one of 2048, 3072, or 4096, the ECDSA curve is not 'secp256r1'
                or 'secp384r1', or the country code is not exactly two characters.
            OSError: If creating directories or writing the certificate or key file
                to disk fails.
            RuntimeError: If saving the credentials or updating the store index fails.
        """
        ...

    async def associate_scope(
        self,
        identifier: str | Path | GeminiURI | ClientCertificate,
        scope_or_uri: str | GeminiURI,
    ) -> None:
        """Associate an existing certificate in the store with an additional scope or URI.

        Args:
            identifier: Target certificate reference (ClientCertificate, GeminiURI,
                fingerprint, or file path/name).
            scope_or_uri: The scope string or GeminiURI to associate.

        Raises:
            ValueError: If the certificate cannot be identified in the store.
            RuntimeError: If updating the store index fails.
        """
        ...

    async def disassociate_scope(self, scope_or_uri: str | GeminiURI) -> bool:
        """Disassociate a scope or URI without deleting the certificate files.

        Args:
            scope_or_uri: The scope string or GeminiURI to disassociate.

        Returns:
            True if an association was removed, False if no matching scope was registered.

        Raises:
            RuntimeError: If updating the store index fails.
        """
        ...

    async def delete_certificate(
        self, identifier: str | Path | GeminiURI | ClientCertificate
    ) -> bool:
        """Delete a client certificate and its private key, removing all associated scopes.

        Args:
            identifier: Target certificate reference (ClientCertificate, GeminiURI,
                fingerprint, or file path/name).

        Returns:
            True if the certificate was found and deleted, False otherwise.

        Raises:
            RuntimeError: If updating the store index fails.
        """
        ...

    async def delete_exact_scope(self, scope_or_uri: str | GeminiURI) -> bool:
        """Delete the exact scope association, removing the certificate files if unused.

        Args:
            scope_or_uri: The scope string or GeminiURI to delete.

        Returns:
            True if the scope was found and deleted, False otherwise.

        Raises:
            RuntimeError: If updating the store index fails.
        """
        ...

    async def has_exact_credentials(self, uri: GeminiURI) -> bool:
        """Check if a certificate exists for the exact scope of the URI.

        This checks if a certificate has been registered specifically for the
        exact host, port, and path of the given URI (without traversing parent
        scopes).

        Args:
            uri: The target GeminiURI.

        Returns:
            True if a certificate is registered for this exact scope, False otherwise.
        """
        ...

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
        valid_days: int | None = 365,
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
            valid_days: Number of days the certificate should be valid. If None, the
                certificate will expire on 9999-12-31.
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

        Raises:
            ValueError: If the key type is unsupported, the RSA key size is not
                one of 2048, 3072, or 4096, the ECDSA curve is not 'secp256r1'
                or 'secp384r1', or the country code is not exactly two characters.
            OSError: If creating directories or writing the certificate or key file
                to disk fails.
            RuntimeError: If saving the credentials or updating the store index fails.
        """
        ...

    async def register_credentials(
        self,
        uri: GeminiURI,
        cert_path: str | Path,
        key_path: str | Path,
        *,
        transient: bool = False,
    ) -> None:
        """Register existing certificate and private key paths for the URI's scope.

        Args:
            uri: The target GeminiURI.
            cert_path: Path to the existing client certificate.
            key_path: Path to the existing private key.
            transient: If True, registers as transient.

        Raises:
            FileNotFoundError: If the registry is persistent, and the source files do
                not exist at the specified paths.
            OSError: If copying the certificate or private key files fails, or if creating
                the persistent store directory fails.
            RuntimeError: If registering or persisting the credentials in the store index fails.
        """
        ...

    async def delete_credentials(self, uri: GeminiURI) -> bool:
        """Delete the certificate and key associated with the matching scope.

        Args:
            uri: The target GeminiURI.

        Returns:
            True if deleted, False if no matching scope was found.

        Raises:
            RuntimeError: If updating the store index fails.
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

    def _list_certificates_sync(self) -> list[ClientCertificate]:
        """Synchronously scan the store index and directory to list all certificates."""
        cert_to_scopes: dict[str, list[str]] = {}
        cert_to_key: dict[str, str] = {}

        for scope, entry in self._index.items():
            cert_rel = entry.get("cert")
            key_rel = entry.get("key")
            if cert_rel:
                cert_to_scopes.setdefault(cert_rel, []).append(scope)
                if key_rel:
                    cert_to_key[cert_rel] = key_rel

        if self.store_dir.exists():
            for p in self.store_dir.glob("*.crt"):
                cert_rel = p.name
                if cert_rel not in cert_to_scopes:
                    cert_to_scopes[cert_rel] = []
                if cert_rel not in cert_to_key:
                    key_p = p.with_suffix(".key")
                    if key_p.exists():
                        cert_to_key[cert_rel] = key_p.name

        results: list[ClientCertificate] = []
        for cert_rel, scopes in cert_to_scopes.items():
            cert_path = self.store_dir / cert_rel
            if not cert_path.exists():
                continue
            key_rel = cert_to_key.get(cert_rel)
            key_path = (
                (self.store_dir / key_rel)
                if key_rel and (self.store_dir / key_rel).exists()
                else None
            )
            try:
                cert_pem = cert_path.read_bytes()
                key_pem = key_path.read_bytes() if key_path is not None else None
                results.append(
                    ClientCertificate(
                        cert_pem=cert_pem,
                        key_pem=key_pem,
                        cert_path=cert_path,
                        key_path=key_path,
                        scopes=tuple(sorted(scopes)),
                    )
                )
            except Exception:
                continue

        # Add transient certificates
        transient_to_scopes: dict[Path, list[str]] = {}
        transient_to_key: dict[Path, Path] = {}
        for scope, (c_p, k_p) in self._transient_index.items():
            if c_p.exists():
                transient_to_scopes.setdefault(c_p, []).append(scope)
                transient_to_key[c_p] = k_p

        if self._temp_dir is not None and self._temp_dir.exists():
            for p in self._temp_dir.glob("*.crt"):
                if p not in transient_to_scopes:
                    transient_to_scopes[p] = []
                if p not in transient_to_key:
                    key_p = p.with_suffix(".key")
                    if key_p.exists():
                        transient_to_key[p] = key_p

        for c_p, scopes in transient_to_scopes.items():
            transient_key_path = transient_to_key.get(c_p)
            try:
                cert_pem = c_p.read_bytes()
                key_pem = (
                    transient_key_path.read_bytes()
                    if transient_key_path is not None and transient_key_path.exists()
                    else None
                )
                results.append(
                    ClientCertificate(
                        cert_pem=cert_pem,
                        key_pem=key_pem,
                        cert_path=c_p,
                        key_path=transient_key_path,
                        scopes=tuple(sorted(scopes)),
                    )
                )
            except Exception:
                continue

        return results

    async def list_certificates(self) -> list[ClientCertificate]:
        """List all client certificates stored in this certificate store.

        Returns:
            A list of ClientCertificate instances.
        """
        async with self._lock:
            await self._ensure_loaded()
            return await asyncio.to_thread(self._list_certificates_sync)

    async def get_certificate(
        self, identifier: str | Path | GeminiURI
    ) -> ClientCertificate | None:
        """Retrieve a client certificate by scope, URI, fingerprint, or filename.

        Args:
            identifier: A GeminiURI, scope string, SHA-256 fingerprint, or
                certificate file path/name.

        Returns:
            The matching ClientCertificate instance, or None if not found.
        """
        all_certs = await self.list_certificates()

        if isinstance(identifier, GeminiURI):
            creds = await self.get_credentials(identifier)
            if creds is None:
                return None
            cert_path = creds[0]
            for cert in all_certs:
                if cert.cert_path and cert.cert_path.resolve() == cert_path.resolve():
                    return cert
            return None

        if isinstance(identifier, Path):
            resolved = identifier.resolve()
            for cert in all_certs:
                if cert.cert_path and cert.cert_path.resolve() == resolved:
                    return cert
            return None

        ident_str = str(identifier).strip()

        # Check if ident_str is a fingerprint (64 hex characters)
        if len(ident_str) == 64 and all(
            c in "0123456789abcdefABCDEF" for c in ident_str
        ):
            for cert in all_certs:
                if cert.fingerprint.lower() == ident_str.lower():
                    return cert

        # Check by filename / path
        for cert in all_certs:
            if cert.cert_path and (
                cert.cert_path.name == ident_str or str(cert.cert_path) == ident_str
            ):
                return cert

        # Check by exact scope match in certs scopes
        norm_scope = normalize_scope(ident_str)
        for cert in all_certs:
            if norm_scope in cert.scopes or ident_str in cert.scopes:
                return cert

        # Fallback to candidate scope lookup using GeminiURI
        try:
            uri = (
                GeminiURI(ident_str)
                if "://" in ident_str
                else GeminiURI(f"gemini://{ident_str}")
            )
            creds = await self.get_credentials(uri)
            if creds is not None:
                cert_path = creds[0]
                for cert in all_certs:
                    if (
                        cert.cert_path
                        and cert.cert_path.resolve() == cert_path.resolve()
                    ):
                        return cert
        except Exception:
            pass

        return None

    async def create_certificate(
        self,
        name: str,
        *,
        scopes: Sequence[str | GeminiURI] = (),
        transient: bool = False,
        common_name: str | None = None,
        valid_days: int | None = 365,
        key_type: Literal["ecdsa", "rsa"] = "ecdsa",
        rsa_key_size: int = 2048,
        ecdsa_curve: str = "secp256r1",
        email: str | None = None,
        user_id: str | None = None,
        domain: str | None = None,
        organisation: str | None = None,
        country: str | None = None,
    ) -> ClientCertificate:
        """Generate and save a new client certificate and private key.

        Args:
            name: Base name for the certificate file.
            scopes: Sequence of Gemini scopes or URIs to associate with the certificate.
            transient: If True, the certificate is generated in a temporary
                directory and not registered in the persistent store.
            common_name: The Common Name (CN) for the certificate. Defaults to `name`.
            valid_days: Number of days the certificate should be valid. If None, the
                certificate will expire on 9999-12-31.
            key_type: The key type to generate ('ecdsa' or 'rsa').
            rsa_key_size: RSA key size in bits.
            ecdsa_curve: ECDSA curve name.
            email: Optional email address.
            user_id: Optional user identifier.
            domain: Optional domain name for Subject Alternative Name.
            organisation: Optional organisation name.
            country: Optional two-letter country code.

        Returns:
            The created ClientCertificate instance.

        Raises:
            ValueError: If the key type is unsupported, the RSA key size is not
                one of 2048, 3072, or 4096, the ECDSA curve is not 'secp256r1'
                or 'secp384r1', or the country code is not exactly two characters.
            OSError: If creating directories or writing the certificate or key file
                to disk fails.
            RuntimeError: If saving the credentials or updating the store index fails.
        """
        cn = common_name or name
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

        normalized_scopes = [normalize_scope(s) for s in scopes]
        safe_base = _safe_filename(name)

        async with self._lock:
            if transient:
                if self._temp_dir is None:
                    temp_dir_path = await asyncio.to_thread(
                        tempfile.mkdtemp, prefix="wasat_transient_"
                    )
                    self._temp_dir = Path(temp_dir_path)
                    _transient_dirs.append(self._temp_dir)

                cert_path = self._temp_dir / f"{safe_base}.crt"
                key_path = self._temp_dir / f"{safe_base}.key"

                await asyncio.to_thread(cert_path.write_bytes, cert_pem)
                await asyncio.to_thread(key_path.write_bytes, key_pem)

                for scope in normalized_scopes:
                    self._transient_index[scope] = (cert_path, key_path)

                return ClientCertificate(
                    cert_pem=cert_pem,
                    key_pem=key_pem,
                    cert_path=cert_path,
                    key_path=key_path,
                    scopes=tuple(sorted(normalized_scopes)),
                )
            else:
                await self._ensure_loaded()
                self.store_dir.mkdir(parents=True, exist_ok=True)
                cert_file = f"{safe_base}.crt"
                key_file = f"{safe_base}.key"

                cert_path = self.store_dir / cert_file
                key_path = self.store_dir / key_file

                await asyncio.to_thread(cert_path.write_bytes, cert_pem)
                await asyncio.to_thread(key_path.write_bytes, key_pem)

                for scope in normalized_scopes:
                    self._index[scope] = {
                        "cert": cert_file,
                        "key": key_file,
                    }
                await asyncio.to_thread(self._save_sync)

                return ClientCertificate(
                    cert_pem=cert_pem,
                    key_pem=key_pem,
                    cert_path=cert_path,
                    key_path=key_path,
                    scopes=tuple(sorted(normalized_scopes)),
                )

    async def associate_scope(
        self,
        identifier: str | Path | GeminiURI | ClientCertificate,
        scope_or_uri: str | GeminiURI,
    ) -> None:
        """Associate an existing certificate in the store with an additional scope or URI.

        Args:
            identifier: Target certificate reference (ClientCertificate, GeminiURI,
                fingerprint, or file path/name).
            scope_or_uri: The scope string or GeminiURI to associate.

        Raises:
            ValueError: If the certificate cannot be identified in the store.
            RuntimeError: If updating the store index fails.
        """
        cert: ClientCertificate | None
        if isinstance(identifier, ClientCertificate):
            cert = identifier
        else:
            cert = await self.get_certificate(identifier)

        if cert is None or cert.cert_path is None:
            raise ValueError(f"Certificate not found in store for: {identifier}")

        target_scope = normalize_scope(scope_or_uri)
        cert_path = cert.cert_path
        key_path = cert.key_path

        async with self._lock:
            # Check if transient
            if self._temp_dir is not None and cert_path.is_relative_to(self._temp_dir):
                k_path = key_path or cert_path.with_suffix(".key")
                self._transient_index[target_scope] = (cert_path, k_path)
                return

            await self._ensure_loaded()
            self.store_dir.mkdir(parents=True, exist_ok=True)

            # If the cert is outside store_dir, copy it into store_dir
            if not cert_path.is_relative_to(self.store_dir):
                safe_base = _safe_filename(cert_path.stem)
                dest_cert_file = f"{safe_base}.crt"
                dest_key_file = f"{safe_base}.key"
                dest_cert_path = self.store_dir / dest_cert_file
                dest_key_path = self.store_dir / dest_key_file

                if cert_path.resolve() != dest_cert_path.resolve():
                    await asyncio.to_thread(shutil.copy2, cert_path, dest_cert_path)
                if (
                    key_path
                    and key_path.exists()
                    and key_path.resolve() != dest_key_path.resolve()
                ):
                    await asyncio.to_thread(shutil.copy2, key_path, dest_key_path)

                cert_rel = dest_cert_file
                key_rel = dest_key_file
            else:
                cert_rel = cert_path.name
                key_rel = (
                    key_path.name if key_path else cert_path.with_suffix(".key").name
                )

            self._index[target_scope] = {
                "cert": cert_rel,
                "key": key_rel,
            }
            await asyncio.to_thread(self._save_sync)

    async def disassociate_scope(self, scope_or_uri: str | GeminiURI) -> bool:
        """Disassociate a scope or URI without deleting the certificate files.

        Args:
            scope_or_uri: The scope string or GeminiURI to disassociate.

        Returns:
            True if an association was removed, False if no matching scope was registered.

        Raises:
            RuntimeError: If updating the store index fails.
        """
        target_scope = normalize_scope(scope_or_uri)
        scope_no_port = target_scope.replace(f":{GEMINI_DEFAULT_PORT}", "")

        async with self._lock:
            # Check transient index
            for s in (target_scope, scope_no_port, str(scope_or_uri)):
                if s in self._transient_index:
                    del self._transient_index[s]
                    return True

            # Check persistent index
            await self._ensure_loaded()
            for s in (target_scope, scope_no_port, str(scope_or_uri)):
                if s in self._index:
                    del self._index[s]
                    await asyncio.to_thread(self._save_sync)
                    return True
            return False

    async def delete_certificate(
        self, identifier: str | Path | GeminiURI | ClientCertificate
    ) -> bool:
        """Delete a client certificate and its private key, removing all associated scopes.

        Args:
            identifier: Target certificate reference (ClientCertificate, GeminiURI,
                fingerprint, or file path/name).

        Returns:
            True if the certificate was found and deleted, False otherwise.

        Raises:
            RuntimeError: If updating the store index fails.
        """
        cert: ClientCertificate | None
        if isinstance(identifier, ClientCertificate):
            cert = identifier
        else:
            cert = await self.get_certificate(identifier)

        if cert is None:
            return False

        cert_path = cert.cert_path
        key_path = cert.key_path

        async with self._lock:
            # Transient cleanup
            if (
                cert_path
                and self._temp_dir
                and cert_path.is_relative_to(self._temp_dir)
            ):
                to_delete = [
                    s for s, (cp, _) in self._transient_index.items() if cp == cert_path
                ]
                deleted = bool(to_delete) or cert_path.exists()
                for s in to_delete:
                    del self._transient_index[s]
                with suppress(Exception):
                    cert_path.unlink(missing_ok=True)
                if key_path:
                    with suppress(Exception):
                        key_path.unlink(missing_ok=True)
                return deleted

            # Persistent cleanup
            await self._ensure_loaded()
            if cert_path:
                cert_file = cert_path.name
                to_delete = [
                    s
                    for s, entry in self._index.items()
                    if entry.get("cert") == cert_file
                ]
                deleted = bool(to_delete) or cert_path.exists()
                if to_delete:
                    for s in to_delete:
                        del self._index[s]
                    await asyncio.to_thread(self._save_sync)

                with suppress(Exception):
                    cert_path.unlink(missing_ok=True)
                if key_path:
                    with suppress(Exception):
                        key_path.unlink(missing_ok=True)
                return deleted

            return False

    async def delete_exact_scope(self, scope_or_uri: str | GeminiURI) -> bool:
        """Delete the exact scope association, removing the certificate files if unused.

        Args:
            scope_or_uri: The scope string or GeminiURI to delete.

        Returns:
            True if the scope was found and deleted, False otherwise.

        Raises:
            RuntimeError: If updating the store index fails.
        """
        target_scope = normalize_scope(scope_or_uri)
        scope_no_port = target_scope.replace(f":{GEMINI_DEFAULT_PORT}", "")

        async with self._lock:
            # Check transient index
            for s in (target_scope, scope_no_port, str(scope_or_uri)):
                if s in self._transient_index:
                    cert_path, key_path = self._transient_index.pop(s)
                    other_uses = any(
                        cp == cert_path for cp, _ in self._transient_index.values()
                    )
                    if not other_uses:
                        with suppress(Exception):
                            cert_path.unlink(missing_ok=True)
                            key_path.unlink(missing_ok=True)
                    return True

            # Check persistent index
            await self._ensure_loaded()
            matched_scope: str | None = None
            for s in (target_scope, scope_no_port, str(scope_or_uri)):
                if s in self._index:
                    matched_scope = s
                    break

            if matched_scope is None:
                return False

            entry = self._index.pop(matched_scope)
            cert_rel = entry.get("cert")
            key_rel = entry.get("key")

            # Check if any remaining scopes in self._index use this cert
            other_uses = any(e.get("cert") == cert_rel for e in self._index.values())
            if not other_uses:
                if cert_rel:
                    with suppress(Exception):
                        (self.store_dir / cert_rel).unlink(missing_ok=True)
                if key_rel:
                    with suppress(Exception):
                        (self.store_dir / key_rel).unlink(missing_ok=True)

            await asyncio.to_thread(self._save_sync)
            return True

    async def has_exact_credentials(self, uri: GeminiURI) -> bool:
        """Check if a certificate exists for the exact scope of the URI.

        This checks if a certificate has been registered specifically for the
        exact host, port, and path of the given URI (without traversing parent
        scopes).

        Args:
            uri: The target GeminiURI.

        Returns:
            True if a certificate is registered for this exact scope, False otherwise.
        """
        host = uri.host.lower()
        port = uri.port
        path = uri.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        scope = f"{host}:{port}{path}"
        scope_no_port = f"{host}{path}"

        async with self._lock:
            # Check transient index first
            for s in (scope, scope_no_port):
                if s in self._transient_index:
                    cert_path, key_path = self._transient_index[s]
                    if cert_path.exists() and key_path.exists():
                        return True

            # Check persistent index
            await self._ensure_loaded()
            for s in (scope, scope_no_port):
                if s in self._index:
                    entry = self._index[s]
                    cert_rel = entry.get("cert")
                    key_rel = entry.get("key")
                    if cert_rel and key_rel:
                        cert_path = self.store_dir / cert_rel
                        key_path = self.store_dir / key_rel
                        if cert_path.exists() and key_path.exists():
                            return True
            return False

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
        valid_days: int | None = 365,
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
            valid_days: Number of days the certificate should be valid. If None, the
                certificate will expire on 9999-12-31.
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

        Raises:
            ValueError: If the key type is unsupported, the RSA key size is not
                one of 2048, 3072, or 4096, the ECDSA curve is not 'secp256r1'
                or 'secp384r1', or the country code is not exactly two characters.
            OSError: If creating the persistent store directory or the temporary transient
                directory fails, or if writing the certificate or key file to disk fails.
            RuntimeError: If saving the updated index (`certs.json`) file to disk fails.
        """
        host = uri.host
        port = uri.port
        path = uri.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        scope = f"{host.lower()}:{port}{path}"

        cert = await self.create_certificate(
            name=scope,
            scopes=[uri],
            transient=transient,
            common_name=common_name or host,
            valid_days=valid_days,
            key_type=key_type,
            rsa_key_size=rsa_key_size,
            ecdsa_curve=ecdsa_curve,
            email=email,
            user_id=user_id,
            domain=domain,
            organisation=organisation,
            country=country,
        )

        assert cert.cert_path is not None
        assert cert.key_path is not None
        return cert.cert_path, cert.key_path

    async def register_credentials(
        self,
        uri: GeminiURI,
        cert_path: str | Path,
        key_path: str | Path,
        *,
        transient: bool = False,
    ) -> None:
        """Register existing certificate and private key paths for the URI's scope.

        Args:
            uri: The target GeminiURI.
            cert_path: Path to the existing client certificate.
            key_path: Path to the existing private key.
            transient: If True, registers as transient.

        Raises:
            FileNotFoundError: If `transient` is False, and the source certificate file
                or private key file does not exist at the specified paths.
            OSError: If `transient` is False, and copying the certificate or private key
                files fails, or if creating the persistent store directory fails.
            RuntimeError: If `transient` is False, and saving the updated index (`certs.json`)
                file to disk fails.
        """
        host = uri.host
        port = uri.port
        path = uri.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        scope = f"{host.lower()}:{port}{path}"

        c_path = Path(cert_path)
        k_path = Path(key_path)

        async with self._lock:
            if transient:
                self._transient_index[scope] = (c_path, k_path)
            else:
                await self._ensure_loaded()
                self.store_dir.mkdir(parents=True, exist_ok=True)

                if c_path.parent.resolve() == self.store_dir.resolve():
                    dest_cert_file = c_path.name
                    dest_key_file = k_path.name
                else:
                    safe_base = _safe_filename(scope)
                    dest_cert_file = f"{safe_base}.crt"
                    dest_key_file = f"{safe_base}.key"
                    dest_cert_path = self.store_dir / dest_cert_file
                    dest_key_path = self.store_dir / dest_key_file

                    if c_path.resolve() != dest_cert_path.resolve():
                        await asyncio.to_thread(shutil.copy2, c_path, dest_cert_path)
                    if k_path.resolve() != dest_key_path.resolve():
                        await asyncio.to_thread(shutil.copy2, k_path, dest_key_path)

                self._index[scope] = {
                    "cert": dest_cert_file,
                    "key": dest_key_file,
                }
                await asyncio.to_thread(self._save_sync)

    async def delete_credentials(self, uri: GeminiURI) -> bool:
        """Delete the certificate and key associated with the matching scope.

        Args:
            uri: The target GeminiURI.

        Returns:
            True if deleted, False if no matching scope was found.

        Raises:
            RuntimeError: If saving the updated index (`certs.json`) file to disk fails.
        """
        async with self._lock:
            candidates = get_candidate_scopes(uri)

            # Check transient index
            for candidate in candidates:
                if candidate in self._transient_index:
                    cert_path, key_path = self._transient_index.pop(candidate)
                    other_uses = any(
                        cp == cert_path for cp, _ in self._transient_index.values()
                    )
                    if not other_uses:
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

                    other_uses = any(
                        e.get("cert") == cert_rel for e in self._index.values()
                    )
                    if not other_uses:
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


##############################################################################
class ServerCertificate:
    """Representation of a server TLS X.509 certificate."""

    def __init__(self, raw_der: bytes) -> None:
        """Initialise the ServerCertificate object.

        Args:
            raw_der: The raw DER-encoded certificate bytes.
        """
        self._raw_der = raw_der
        """The raw DER-encoded certificate bytes."""
        self._cert = x509.load_der_x509_certificate(raw_der)
        """The parsed cryptography X.509 Certificate object."""

    @classmethod
    def from_der(cls, cert_der: bytes) -> ServerCertificate:
        """Construct a ServerCertificate instance from raw DER bytes.

        Args:
            cert_der: The raw DER-encoded certificate bytes.

        Returns:
            A new ServerCertificate instance.
        """
        return cls(cert_der)

    @property
    def raw_der(self) -> bytes:
        """The raw DER-encoded certificate bytes."""
        return self._raw_der

    @property
    def subject_common_name(self) -> str | None:
        """The Common Name (CN) from the certificate subject, or None if not present."""
        attributes = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def issuer_common_name(self) -> str | None:
        """The Common Name (CN) from the certificate issuer, or None if not present."""
        attributes = self._cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attributes:
            return None
        value = attributes[0].value
        return str(value) if isinstance(value, str | bytes) else None

    @property
    def subject(self) -> str:
        """The certificate subject formatted as an RFC 4514 string."""
        return self._cert.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        """The certificate issuer formatted as an RFC 4514 string."""
        return self._cert.issuer.rfc4514_string()

    @property
    def not_before(self) -> datetime:
        """The UTC timestamp from which the certificate is valid."""
        return self._cert.not_valid_before_utc

    @property
    def not_after(self) -> datetime:
        """The UTC timestamp at which the certificate expires."""
        return self._cert.not_valid_after_utc

    @property
    def subject_alternative_names(self) -> tuple[str, ...]:
        """Tuple of Subject Alternative Names (DNS names) in the certificate."""
        try:
            extension = self._cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            return tuple(extension.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            return ()

    @property
    def serial_number(self) -> int:
        """The certificate serial number."""
        return self._cert.serial_number

    @property
    def fingerprint(self) -> str:
        """The hex-encoded SHA-256 fingerprint of the certificate."""
        return get_cert_fingerprint(self._raw_der)

    @property
    def is_expired(self) -> bool:
        """Whether the certificate is currently expired."""
        return datetime.now(UTC) > self.not_after

    @property
    def is_self_signed(self) -> bool:
        """Whether the certificate is self-signed (subject equals issuer)."""
        return self._cert.subject == self._cert.issuer

    @property
    def raw_x509(self) -> x509.Certificate:
        """The underlying cryptography X.509 Certificate instance."""
        return self._cert


### certs.py ends here
