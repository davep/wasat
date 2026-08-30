"""Entry point for executing the wasat package directly."""

##############################################################################
# Python imports.
import sys
from argparse import ArgumentParser, Namespace
from asyncio import run, to_thread
from getpass import getpass
from pathlib import Path
from typing import Literal

##############################################################################
# Local imports.
from . import (
    AnyURI,
    Client,
    ClientCertificateStore,
    GeminiURI,
    StatusCode,
    TitanURI,
    WasatError,
    __version__,
)


##############################################################################
def get_args() -> Namespace:
    """Parse command-line arguments.

    Returns:
        Namespace: Parsed command-line arguments.
    """
    parser = ArgumentParser(
        prog="wasat",
        description="An asynchronous client library and CLI for the Gemini and Titan protocols.",
    )
    parser.add_argument(
        "url",
        help="The Gemini or Titan URL to request.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )
    parser.add_argument(
        "--verify-mode",
        choices=["tofu", "ca", "off", "hybrid"],
        default="tofu",
        help="Certificate verification mode: tofu, ca, off, or hybrid (default: tofu).",
    )
    parser.add_argument(
        "--show-cert",
        action="store_true",
        help="Display server and client TLS certificate information.",
    )
    parser.add_argument(
        "-u",
        "--upload",
        type=Path,
        metavar="FILE",
        help="Upload a file using the Titan protocol.",
    )
    parser.add_argument(
        "-d",
        "--data",
        type=str,
        metavar="TEXT",
        help="Upload raw text data using the Titan protocol.",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete a resource using the Titan protocol (size=0).",
    )
    parser.add_argument(
        "-m",
        "--mime",
        type=str,
        metavar="MIME",
        help="MIME type for Titan upload (defaults to inferred or text/gemini).",
    )
    parser.add_argument(
        "-t",
        "--token",
        type=str,
        metavar="TOKEN",
        help="Authorisation token for Titan request or upload.",
    )

    return parser.parse_args()


##############################################################################
async def cli_on_client_certificate_required(
    uri: AnyURI,
    store: ClientCertificateStore,
) -> Literal["transient", "persistent", "ignore"]:
    """Handle a client certificate requirement by prompting the user in the CLI.

    Args:
        uri: The target URI requesting the certificate.
        store: The ClientCertificateStore instance.

    Returns:
        The action to take ('transient', 'persistent', or 'ignore').
    """
    print(f"\nServer at {uri.host} requires a client certificate.", file=sys.stderr)
    try:
        choice = await to_thread(
            input, "Would you like to generate a certificate? [y/N]: "
        )
        if choice.strip().lower() in ("y", "yes"):
            type_choice = await to_thread(
                input,
                "Generate transient (session-only) or persistent certificate? [t/P]: ",
            )
            if type_choice.strip().lower() == "t":
                return "transient"
            else:
                return "persistent"
    except Exception:
        pass
    return "ignore"


##############################################################################
async def run_cli() -> None:
    """Run the Wasat CLI asynchronously."""
    args = get_args()

    client = Client(
        verify_mode=args.verify_mode,
        on_client_certificate_required=cli_on_client_certificate_required,
    )

    try:
        if args.url.startswith("titan://"):
            current_uri: AnyURI = TitanURI(args.url)
        elif args.url.startswith("gemini://"):
            current_uri = GeminiURI(args.url)
        else:
            if args.upload or args.data or args.delete:
                current_uri = TitanURI(f"titan://{args.url}")
            else:
                current_uri = GeminiURI(f"gemini://{args.url}")
    except WasatError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    try:
        async with client:
            if args.upload is not None:
                if not args.upload.exists():
                    print(
                        f"Error: Upload file not found: {args.upload}",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                response = await client.upload(
                    current_uri,
                    args.upload,
                    mime=args.mime,
                    token=args.token,
                )
            elif args.data is not None:
                response = await client.upload(
                    current_uri,
                    args.data,
                    mime=args.mime,
                    token=args.token,
                )
            elif args.delete:
                response = await client.delete(
                    current_uri,
                    token=args.token,
                )
            else:
                response = None

            if response is not None:
                async with response:
                    proto_name = (
                        "Titan"
                        if (
                            (
                                response.uri is not None
                                and response.uri.scheme == "titan"
                            )
                            or (
                                current_uri is not None
                                and current_uri.scheme == "titan"
                            )
                        )
                        else "Gemini"
                    )
                    if args.verbose:
                        print(f"--- {proto_name} Response ---")
                        if (
                            response.requested_uri is not None
                            and response.uri != response.requested_uri
                        ):
                            print(f"Requested URI: {response.requested_uri}")
                        if response.history:
                            print("Redirections:")
                            for redirect_response in response.history:
                                print(
                                    f"  {redirect_response.uri} -> "
                                    f"{redirect_response.meta.strip()}"
                                )
                        print(f"URI: {response.uri}")
                        if response.verification_method is not None:
                            print(
                                f"Verification Method: {response.verification_method}"
                            )
                        if response.server_cert_fingerprint is not None:
                            print(
                                f"Certificate Fingerprint: sha256:{response.server_cert_fingerprint}"
                            )
                        print(
                            f"Status: {response.status.value} ({response.status.name})"
                        )
                        print(f"Meta: {response.meta}")
                        print("-----------------------")

                    if args.show_cert and response.server_cert is not None:
                        cert = response.server_cert
                        print("--- Server Certificate ---")
                        print(f"Subject: {cert.subject}")
                        print(f"Issuer: {cert.issuer}")
                        if cert.subject_common_name:
                            print(f"Subject CN: {cert.subject_common_name}")
                        if cert.issuer_common_name:
                            print(f"Issuer CN: {cert.issuer_common_name}")
                        print(f"Valid From: {cert.not_before}")
                        print(f"Valid Until: {cert.not_after}")
                        sans = (
                            ", ".join(cert.subject_alternative_names)
                            if cert.subject_alternative_names
                            else "None"
                        )
                        print(f"SANs: {sans}")
                        print(f"Serial Number: {cert.serial_number}")
                        print(f"Fingerprint: sha256:{cert.fingerprint}")
                        print(f"Self-Signed: {cert.is_self_signed}")
                        print(f"Expired: {cert.is_expired}")
                        print("--------------------------")

                    if args.show_cert and response.client_cert is not None:
                        client_cert = response.client_cert
                        print("--- Client Certificate ---")
                        print(f"Subject: {client_cert.subject}")
                        print(f"Issuer: {client_cert.issuer}")
                        if client_cert.subject_common_name:
                            print(f"Subject CN: {client_cert.subject_common_name}")
                        if client_cert.issuer_common_name:
                            print(f"Issuer CN: {client_cert.issuer_common_name}")
                        if client_cert.email:
                            print(f"Email: {client_cert.email}")
                        if client_cert.user_id:
                            print(f"User ID: {client_cert.user_id}")
                        print(f"Valid From: {client_cert.not_before}")
                        print(f"Valid Until: {client_cert.not_after}")
                        print(f"Fingerprint: sha256:{client_cert.fingerprint}")
                        print(f"Self-Signed: {client_cert.is_self_signed}")
                        print(f"Expired: {client_cert.is_expired}")
                        if client_cert.scopes:
                            print(f"Scopes: {', '.join(client_cert.scopes)}")
                        print("--------------------------")

                    if not args.verbose and not response.status.is_success:
                        print(f"--- {proto_name} Response ---")
                        print(
                            f"Status: {response.status.value} ({response.status.name})"
                        )
                        print(f"Meta: {response.meta}")
                        print("-----------------------")

                    if response.status.is_success:
                        print(await response.text())
                    else:
                        sys.exit(1)
                return

            while True:
                async with await client.request(current_uri) as response:
                    proto_name = (
                        "Titan"
                        if (
                            (
                                response.uri is not None
                                and response.uri.scheme == "titan"
                            )
                            or (
                                current_uri is not None
                                and current_uri.scheme == "titan"
                            )
                        )
                        else "Gemini"
                    )
                    if args.verbose:
                        print(f"--- {proto_name} Response ---")
                        if (
                            response.requested_uri is not None
                            and response.uri != response.requested_uri
                        ):
                            print(f"Requested URI: {response.requested_uri}")
                        if response.history:
                            print("Redirections:")
                            for redirect_response in response.history:
                                print(
                                    f"  {redirect_response.uri} -> "
                                    f"{redirect_response.meta.strip()}"
                                )
                        print(f"URI: {response.uri}")
                        if response.verification_method is not None:
                            print(
                                f"Verification Method: {response.verification_method}"
                            )
                        if response.server_cert_fingerprint is not None:
                            print(
                                f"Certificate Fingerprint: sha256:{response.server_cert_fingerprint}"
                            )
                        print(
                            f"Status: {response.status.value} ({response.status.name})"
                        )
                        print(f"Meta: {response.meta}")
                        print("-----------------------")

                    if args.show_cert and response.server_cert is not None:
                        cert = response.server_cert
                        print("--- Server Certificate ---")
                        print(f"Subject: {cert.subject}")
                        print(f"Issuer: {cert.issuer}")
                        if cert.subject_common_name:
                            print(f"Subject CN: {cert.subject_common_name}")
                        if cert.issuer_common_name:
                            print(f"Issuer CN: {cert.issuer_common_name}")
                        print(f"Valid From: {cert.not_before}")
                        print(f"Valid Until: {cert.not_after}")
                        sans = (
                            ", ".join(cert.subject_alternative_names)
                            if cert.subject_alternative_names
                            else "None"
                        )
                        print(f"SANs: {sans}")
                        print(f"Serial Number: {cert.serial_number}")
                        print(f"Fingerprint: sha256:{cert.fingerprint}")
                        print(f"Self-Signed: {cert.is_self_signed}")
                        print(f"Expired: {cert.is_expired}")
                        print("--------------------------")

                    if args.show_cert and response.client_cert is not None:
                        client_cert = response.client_cert
                        print("--- Client Certificate ---")
                        print(f"Subject: {client_cert.subject}")
                        print(f"Issuer: {client_cert.issuer}")
                        if client_cert.subject_common_name:
                            print(f"Subject CN: {client_cert.subject_common_name}")
                        if client_cert.issuer_common_name:
                            print(f"Issuer CN: {client_cert.issuer_common_name}")
                        if client_cert.email:
                            print(f"Email: {client_cert.email}")
                        if client_cert.user_id:
                            print(f"User ID: {client_cert.user_id}")
                        print(f"Valid From: {client_cert.not_before}")
                        print(f"Valid Until: {client_cert.not_after}")
                        print(f"Fingerprint: sha256:{client_cert.fingerprint}")
                        print(f"Self-Signed: {client_cert.is_self_signed}")
                        print(f"Expired: {client_cert.is_expired}")
                        if client_cert.scopes:
                            print(f"Scopes: {', '.join(client_cert.scopes)}")
                        print("--------------------------")

                    if response.status.is_input:
                        prompt = f"{response.meta}: " if response.meta else "Input: "
                        try:
                            if response.status == StatusCode.SENSITIVE_INPUT:
                                user_input = await to_thread(getpass, prompt)
                            else:
                                user_input = await to_thread(input, prompt)
                        except (EOFError, KeyboardInterrupt):
                            print()
                            sys.exit(1)
                        current_uri = current_uri.with_query(user_input)
                        continue

                    if not args.verbose and not response.status.is_success:
                        print(f"--- {proto_name} Response ---")
                        print(
                            f"Status: {response.status.value} ({response.status.name})"
                        )
                        print(f"Meta: {response.meta}")
                        print("-----------------------")

                    if response.status.is_success:
                        print(await response.text())
                        break
                    else:
                        sys.exit(1)
    except WasatError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


##############################################################################
def main() -> None:
    """CLI entry point."""
    try:
        run(run_cli())
    except KeyboardInterrupt:
        sys.exit(130)


##############################################################################
if __name__ == "__main__":
    main()

### __main__.py ends here
