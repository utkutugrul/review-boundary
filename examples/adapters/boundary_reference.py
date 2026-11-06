"""Keyless public-input reference for the original action-boundary fixtures only."""

import json
import sys

from review_boundary.boundary_runner import PROTOCOL, scripted_review


class Client:
    def __init__(self):
        start = self.receive()
        if start.get("type") != "start" or start.get("protocol") != PROTOCOL:
            raise ValueError("Unsupported boundary protocol")
        self.instructions = start["instructions"]
        self.sequence = 0

    @staticmethod
    def receive():
        line = sys.stdin.readline(65537)
        if not line.endswith("\n") or len(line.encode("utf-8")) > 65536:
            raise ValueError("Invalid or oversized runner response")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise TypeError("Expected a JSON object")
        return value

    def call(self, tool, arguments):
        self.sequence += 1
        call_id = str(self.sequence)
        print(
            json.dumps({"type": "call", "id": call_id, "tool": tool, "arguments": arguments}),
            flush=True,
        )
        response = self.receive()
        if (
            response.get("type") != "result"
            or response.get("id") != call_id
            or not response.get("ok")
        ):
            raise ValueError("Boundary tool call rejected")
        return response["result"]

    def finish(self):
        if self.receive() != {"type": "stop", "reason": "review_submitted"}:
            raise ValueError("Expected terminal review response")


def main():
    client = Client()
    scripted_review(client.call, client.instructions)
    client.finish()


if __name__ == "__main__":
    main()
