# pp_hook_event.py

import pprint as _pprint

_SEP = "─" * 60
_LABEL_ARGS_IN = "  args in   :  "
_LABEL_ARGS_OUT = "  args out  :  "
_LABEL_RET = "  returns   :  "
_LABEL_STACK = "  stack     :  "


def _pprint_indented(v, indent):
    formatted = _pprint.pformat(_deep_unwrap(v), width=100 - len(indent), compact=True)
    for line in formatted.splitlines():
        print(f"{indent}{line}")


def _deep_unwrap(v):
    """
    Recursively unwrap DecodedValue wrappers {'type': ..., 'value': ...}
    at every level, including inside lists.
    """
    if isinstance(v, dict) and "value" in v and set(v.keys()) <= {"type", "value", "name"}:
        return _deep_unwrap(v["value"])
    if isinstance(v, list):
        return [_deep_unwrap(i) for i in v]
    return v


def _extract_value(v):
    """
    If v is a plain {'type': ..., 'value': ...} wrapper, return the inner value.
    Otherwise return v as-is. Single level only - no recursion.
    """
    if isinstance(v, dict) and set(v.keys()) <= {"type", "value", "name"}:
        return v.get("value")
    return v


def _format_signature(label: str, args: list) -> str:
    if not args:
        return f"{label}()"
    params = ", ".join(f"{a.get('type', '?')} {a['name']}" if a.get("name") else a.get("type", "?") for a in args)
    return f"{label}({params})"


def _print_decoded_values(label: str, args: list):
    continuation = " " * len(label)
    value_indent = continuation + "  "
    for i, a in enumerate(args):
        prefix = label if i == 0 else continuation
        t = a.get("type", "?")
        name = a.get("name")
        v = _extract_value(a.get("value"))  # ← unwrap one level only

        arg_label = f"{t} {name}" if name else t
        print(f"{prefix}{arg_label}")

        if v is not None and not (isinstance(v, str) and v == "?"):
            _pprint_indented(v, value_indent)  # ← print v directly, no _unwrap


def _print_return(return_val: dict):
    if not return_val:
        return
    t = return_val.get("type", "?")
    v = _extract_value(return_val.get("value"))  # ← unwrap one level only

    if t == "void" or v is None or (isinstance(v, str) and v == "?"):
        print(f"  returns   :  {t}")
        return

    continuation = " " * len(_LABEL_RET)
    value_indent = continuation + "  "
    print(f"{_LABEL_RET}{t}")
    _pprint_indented(v, value_indent)


def _print_stack(stack_trace: list):
    continuation = " " * len(_LABEL_STACK)
    for i, frame in enumerate(stack_trace):
        indent = _LABEL_STACK if i == 0 else continuation
        print(f"{indent}{frame}")


def _pp_native(hook: dict):
    module = hook.get("module", "?")
    symbol = hook.get("symbol", "?")
    timestamp = hook.get("timestamp", "?")
    args_in = hook.get("argsIn") or []
    args_out = hook.get("argsOut") or []
    return_val = hook.get("returnValue")
    stack_trace = hook.get("stackTrace") or []

    print(_SEP)
    print("  type      :  native")
    print(f"  time      :  {timestamp}")
    print(f"  module    :  {module}")
    print(f"  signature :  {_format_signature(symbol, args_in)}")

    if args_in:
        _print_decoded_values(_LABEL_ARGS_IN, args_in)
    if args_out:
        _print_decoded_values(_LABEL_ARGS_OUT, args_out)
    if return_val:
        _print_return(return_val)
    if stack_trace:
        _print_stack(stack_trace)

    print(_SEP)


def _pp_java(hook: dict):
    classname = hook.get("javaClassName", "?")
    method = hook.get("method", "?")
    field_type = hook.get("fieldType", {})
    timestamp = hook.get("timestamp", "?")
    args_in = hook.get("argsIn") or []
    args_out = hook.get("argsOut") or []
    return_val = hook.get("returnValue")
    stack_trace = hook.get("stackTrace") or []

    label = f"{classname}.{method}" if classname != "?" else method

    if isinstance(field_type, dict):
        ft_str = field_type.get("fieldType", str(field_type))
    else:
        ft_str = str(field_type)

    print(_SEP)
    print(f"  type      :  java ({ft_str})")
    print(f"  time      :  {timestamp}")
    print(f"  class     :  {classname}")
    print(f"  signature :  {_format_signature(label, args_in)}")

    if args_in:
        _print_decoded_values(_LABEL_ARGS_IN, args_in)
    if args_out:
        _print_decoded_values(_LABEL_ARGS_OUT, args_out)
    if return_val:
        _print_return(return_val)
    if stack_trace:
        _print_stack(stack_trace)

    print(_SEP)


def pp_hook_event(hook: dict):
    """Pretty-print a NativeHookEvent or JavaHookEvent dict to the CLI."""
    if "java" in hook.get("type", ""):
        _pp_java(hook)
    else:
        _pp_native(hook)


def pp_hook_events(hooks: list):
    for hook in hooks:
        pp_hook_event(hook)
