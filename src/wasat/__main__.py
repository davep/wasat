"""Entry point for executing the wasat package directly."""

import asyncio
import sys

from .client import Client
from .exceptions import WasatError


async def run_cli() -> None:
    """Run the Wasat CLI asynchronously."""
    if len(sys.argv) < 2:
        print("Usage: wasat <gemini-url>", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]
    client = Client(verify_mode="tofu")

    try:
        response = await client.request(url)
        print("--- Gemini Response ---")
        print(f"Status: {response.status.value} ({response.status.name})")
        print(f"Meta: {response.meta}")
        print("-----------------------")
        if response.status.is_success:
            body = await response.text()
            print(body)
    except WasatError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """CLI entry point."""
    try:
        asyncio.run(run_cli())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

### __main__.py ends here
