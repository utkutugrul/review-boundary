"""Keyless example of the policy process contract, using exact virtual targets."""

import json
import sys


def main():
    request = json.load(sys.stdin)
    if request.get("protocol") != "reviewboundary.policy-json/1":
        return 2
    policy = request["policy"]
    action = request["request"]
    tool = action["tool"]
    key = {"save_report": "path", "send_report": "url"}.get(tool)
    allowed = key is not None and any(
        grant["tool"] == tool and grant["target"] == action["arguments"].get(key)
        for grant in policy["grants"]
    )
    result = {
        "decision": "allow" if allowed else policy["default_decision"],
        "reason": "Exact caller grant matched" if allowed else "No exact caller grant matched",
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
