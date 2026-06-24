"""Entry point for executing the wasat package directly."""

##############################################################################
# Python imports.
from argparse import ArgumentParser, Namespace
from asyncio import run, to_thread
from getpass import getpass
from sys import exit, stderr
from typing import Literal

##############################################################################
# Local imports.
from . import (
    Client,
    ClientCertificateStore,
    GeminiURI,
    StatusCode,
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
        description="An asynchronous client library and CLI for the Gemini protocol.",
    )
    parser.add_argument(
        "url",
        help="The Gemini URL to request.",
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

    return parser.parse_args()


##############################################################################
async def cli_on_client_certificate_required(
    uri: GeminiURI,
    store: ClientCertificateStore,
) -> Literal["transient", "persistent", "ignore"]:
    """Handle a client certificate requirement by prompting the user in the CLI.

    Args:
        uri: The target GeminiURI requesting the certificate.
        store: The ClientCertificateStore instance.

    Returns:
        The action to take ('transient', 'persistent', or 'ignore').
    """
    print(f"\nServer at {uri.host} requires a client certificate.", file=stderr)
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
        verify_mode="tofu",
        on_client_certificate_required=cli_on_client_certificate_required,
    )

    try:
        current_uri = GeminiURI(args.url)
    except WasatError as e:
        print(f"Error: {e}", file=stderr)
        exit(1)

    try:
        async with client:
            while True:
                async with await client.request(current_uri) as response:
                    if args.verbose:
                        print("--- Gemini Response ---")
                        if (
                            response.requested_uri is not None
                            and response.uri != response.requested_uri
                        ):
                            print(f"Requested URI: {response.requested_uri}")
                        if response.history:
                            print("Redirections:")
                            for redirect_resp in response.history:
                                print(
                                    f"  {redirect_resp.uri} -> "
                                    f"{redirect_resp.meta.strip()}"
                                )
                        print(f"URI: {response.uri}")
                        print(
                            f"Status: {response.status.value} ({response.status.name})"
                        )
                        print(f"Meta: {response.meta}")
                        print("-----------------------")

                    if response.status.is_input:
                        prompt = f"{response.meta}: " if response.meta else "Input: "
                        try:
                            if response.status == StatusCode.SENSITIVE_INPUT:
                                user_input = await to_thread(getpass, prompt)
                            else:
                                user_input = await to_thread(input, prompt)
                        except (EOFError, KeyboardInterrupt):
                            print()
                            exit(1)
                        current_uri = current_uri.with_query(user_input)
                        continue

                    if not args.verbose and not response.status.is_success:
                        print("--- Gemini Response ---")
                        print(
                            f"Status: {response.status.value} ({response.status.name})"
                        )
                        print(f"Meta: {response.meta}")
                        print("-----------------------")

                    if response.status.is_success:
                        print(await response.text())
                        break
                    else:
                        exit(1)
    except WasatError as e:
        print(f"Error: {e}", file=stderr)
        exit(1)


##############################################################################
def main() -> None:
    """CLI entry point."""
    try:
        run(run_cli())
    except KeyboardInterrupt:
        exit(130)


##############################################################################
if __name__ == "__main__":
    main()

### __main__.py ends here
