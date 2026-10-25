"""Drafting helper for fixtures. Not used at run time: it only writes JSON files.

    s = Session("s-b01", "2026-10-10T09:00:00Z")
    s.prompt("Do the thing")
    s.tool("Read", {"file_path": "/work/demo-app/a.py"}, size=900)
    s.response("Done.")
    s.save("fixtures/benign/b01_x.json", "labels/b01_x.json", scenario="benign: x")
"""
import json
from datetime import datetime, timedelta
from pathlib import Path


class Session:
    def __init__(self, sid, start, project="demo-app", mode="default"):
        self.sid, self.project, self.mode = sid, project, mode
        self.t = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        self.events, self.turn, self._uid = [], 0, 0

    def _add(self, event_type, gap=3, **fields):
        self.t += timedelta(seconds=gap)
        ev = {"session_id": self.sid, "seq": len(self.events) + 1,
              "ts": self.t.strftime("%Y-%m-%dT%H:%M:%SZ"), "project": self.project,
              "event_type": event_type, "turn_id": f"p{max(self.turn, 1)}"}
        ev.update({k: v for k, v in fields.items() if v is not None})
        self.events.append(ev)
        return ev["seq"]

    def prompt(self, text):
        self.turn += 1
        return self._add("user_prompt", gap=20, prompt_text=text)

    def mcp_connect(self, server):
        return self._add("mcp_server_connection", mcp_server=server)

    def tool(self, tool, args, purpose=None, size=100, outcome="success", excerpt=None,
             actor=None, decision="accept", mode=None):
        """Adds a tool_decision (+ tool_result unless rejected). Returns the decision's seq."""
        self._uid += 1
        uid = f"t{self._uid}"
        mcp = tool.startswith("mcp__")
        common = dict(tool=tool, tool_source="mcp" if mcp else "builtin",
                      mcp_server=tool.split("__")[1] if mcp else None, tool_use_id=uid,
                      actor=actor)
        if purpose:
            args = {**args, "description": purpose}
        seq = self._add("tool_decision", **common, decision=decision,
                        permission_mode=mode or self.mode, stated_purpose=purpose, args=args)
        if decision == "accept":
            self._add("tool_result", gap=2, **common, outcome=outcome, result_size=size,
                      content_excerpt=excerpt)
        return seq

    def response(self, text):
        return self._add("assistant_response", gap=8, response=text)

    def save(self, fixture_path, label_path, scenario, malicious_ids=(), notes=""):
        body = ",\n".join("  " + json.dumps(e) for e in self.events)
        Path(fixture_path).write_text("[\n" + body + "\n]\n")
        label = {"session_id": self.sid, "malicious": bool(malicious_ids),
                 "malicious_event_ids": [f"{self.sid}:{i}" for i in malicious_ids],
                 "scenario": scenario, "notes": notes}
        Path(label_path).write_text(json.dumps(label) + "\n")
