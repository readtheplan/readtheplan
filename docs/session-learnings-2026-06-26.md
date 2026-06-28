# Session Learnings — 2026-06-26

## readtheplan: Public Typed API

`from readtheplan import analyze` now works as the primary public interface.
Takes a `dict` (plan JSON) or `str | Path` (file path), returns typed `PlanSummary` with `.resource_changes`, `.risk_counts`, `.action_counts`.

```python
from readtheplan import analyze
summary = analyze(plan_dict)
for c in summary.resource_changes:
    print(f"{c.address}: {c.risk}")
```

Backward compat: `analyze_plan_file()` still works. CLI unchanged. All 349 tests pass.

## readtheplan: @register_rule Decorator

Replaced the 50-branch `_rule_candidates()` if/elif chain with a decorator-based registry.

```python
from readtheplan.rules import register_rule, register_cross_cutting, RuleResult

@register_rule("aws_kms_key")
def _kms_candidates(resource_type, action_set, change) -> list[RuleResult]:
    ...
```

- `_RULE_REGISTRY` dict in `_shared.py`: 48 resource types → rule functions
- `_CROSS_CUTTING` list: 3 prefix-matching functions (platform, network, observability)
- Provider modules imported at bottom of `_shared.py` (after all symbols defined) to avoid circular imports
- All rule functions standardized to `(resource_type, action_set, change) -> list[RuleResult]`
- Public API: `from readtheplan.rules import register_rule`

## Desktop Automation: computer_use Coordinate Bug

`computer_use(action="left_click", coordinate=[x,y], target_app="Claude")` has a coordinate transformation bug: supplied coordinates are ignored and the click lands at the cursor's current position.

**Workaround: Use `mouse_move` + `mouse_click` two-step:**
```python
mouse_move(x=120, y=134, duration=0.3)
mouse_click(button="left", clicks=1)
```

**Verified working tools:**
- `computer_use(action="type", text=..., target_app="Claude")` — works via PostMessage WM_CHAR
- `computer_use(action="key", keys="enter", target_app="Claude")` — works via PostMessage
- `mouse_move(x, y)` + `mouse_click()` — reliable two-step click
- `computer_use(action="capture", target_app="Claude")` — works via pyautogui fallback

## Desktop Automation: Virtual Desktop Window Handling

Windows virtual desktops (Win+V / Task View) isolate windows. Tools that send PostMessage (`type`, `key`) work across virtual desktops. Tools that use SendInput (`left_click`, `mouse_click`) only work on the active desktop.

**Fix for off-screen windows:**
```powershell
Add-Type @"
using System; using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr h,
        int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr FindWindow(string lp, string lpName);
}
"@
$hwnd = [Win32]::FindWindow("Chrome_WidgetWin_1", "Claude")
[Win32]::SetWindowPos($hwnd, [IntPtr]::Zero, 0, 0, 0, 0, 0x0004 -bor 0x0001)
```

## Claude: Fable 5 Banner Doesn't Block Responses

The "Claude Fable 5 is currently unavailable" banner is misleading:
- It does NOT block Claude from responding — responses DO come through using Opus 4.8
- The banner only appears on the Home view when Cowork mode tries to use Fable 5
- Inside a project workspace (e.g. "readtheplan" project), messages are processed by Opus 4.8 normally
- The Cowork mode routes through Fable 5 (unavailable), while Chat mode uses Opus 4.8 (working)

## Claude: Cowork Mode Blockage

Claude's Desktop interface has three mode tabs: Chat, Cowork, Code. When in Cowork mode:
- All messages are routed through Fable 5 backend model
- If Fable 5 is down, messages appear in the input box but never process
- Switching to Chat mode uses Opus 4.8 which works reliably

## Claude: safe_send_to_claude_project Fails on Electron

The `safe_send_to_claude_project` tool uses `find_project_by_name()` which searches via pywinauto UIA. Since Claude is an Electron app (`Chrome_WidgetWin_1`), UIA can't see internal canvas elements and can't find projects. Always returns `safe_skip`.

## CI / Test Reliability

- `python -m pytest tests/ -x -q` runs the full suite (349 tests, 84.66% coverage)
- Coverage gate is 78% (`fail_under = 78` in pyproject.toml)
- `__init__.py` is at 100% coverage — any change to it needs a test
