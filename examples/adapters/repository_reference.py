"""Scripted, original-fixture-only JSONL example, not a general security reviewer.

This process reads public virtual files and calls the bundled tenant-fixture
calibration helper. It does not inspect case identifiers, evaluator rubrics,
expected labels or variant metadata. No model or external API is used.
"""

import json
import sys

from review_boundary.repository_runner import PROTOCOL, scripted_submission


class Client:
    def __init__(self):
        start = self.receive()
        if start.get("type") != "start" or start.get("protocol") != PROTOCOL:
            raise ValueError("Unsupported repository protocol")
        self.sequence = 0

    @staticmethod
    def receive():
        line = sys.stdin.readline(65537)
        if not line.endswith("\n") or len(line.encode("utf-8")) > 65536:
            raise ValueError("Invalid or oversized runner response")
        message = json.loads(line)
        if not isinstance(message, dict):
            raise TypeError("Expected a JSON object")
        return message

    def call(self, tool, **arguments):
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
            raise ValueError("Repository tool call rejected")
        result = response["result"]
        if result.get("status") != "ok":
            raise ValueError("Repository operation did not succeed")
        return result

    def finish(self, *, missing_submission=False):
        if missing_submission:
            print(json.dumps({"type": "done"}), flush=True)
        response = self.receive()
        expected = "missing_submission" if missing_submission else "review_submitted"
        if response != {"type": "stop", "reason": expected}:
            raise ValueError("Expected the matching stop response")


def read_repository(client):
    client.call("read_pr")
    cursor, paths = 0, []
    while cursor is not None:
        page = client.call("list_files", cursor=cursor)
        paths.extend(item["path"] for item in page["files"])
        next_cursor = page["next_cursor"]
        if next_cursor is not None and next_cursor <= cursor:
            raise ValueError("File listing did not advance")
        cursor = next_cursor
    files = {}
    for path in paths:
        start, lines = 1, []
        while start is not None:
            page = client.call("read_file", path=path, start_line=start, end_line=start + 79)
            for line in page["lines"]:
                if line["line"] != len(lines) + 1:
                    raise ValueError("Source range was not contiguous")
                lines.append(line["text"])
            next_line = page["next_line"]
            if next_line is not None and next_line <= start:
                raise ValueError("Source reading did not advance")
            start = next_line
        files[path] = "\n".join(lines)
    return files


def main():
    client = Client()
    files = read_repository(client)
    try:
        submission = scripted_submission(files)
    except (KeyError, ValueError):
        client.finish(missing_submission=True)
        return
    client.call("submit_review", **submission)
    client.finish()


if __name__ == "__main__":
    main()
