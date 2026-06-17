"""Entry point for executing the wasat package directly."""

##############################################################################
# Python imports.
from argparse import ArgumentParser, Namespace
from asyncio import run
from sys import exit, stderr

##############################################################################
# Local imports.
from . import Client, WasatError, __version__


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
async def run_cli() -> None:
    """Run the Wasat CLI asynchronously."""
    args = get_args()

    try:
        async with await Client(verify_mode="tofu").request(args.url) as response:
            if args.verbose or not response.status.is_success:
                print("--- Gemini Response ---")
                print(f"Status: {response.status.value} ({response.status.name})")
                print(f"Meta: {response.meta}")
                print("-----------------------")
            if response.status.is_success:
                print(await response.text())
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
