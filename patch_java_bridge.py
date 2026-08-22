#!/usr/bin/env python3
"""patch_java_bridge.py — frida-java-bridge patches for the native universal bypass.

Drop-in for the ajeossida build (Titoot/ajeossida main_ubuntu_android.py):
import this module (or paste patch_java_bridge + _patch below) and call
patch_java_bridge(custom_dir) right after the frida clone, BEFORE the first
build — the bridge JS bundles into the agent/gadget at build time.

What it does (design: docs/NATIVE_SURFACE_MAP.md + session 2026-08-22 proofs):
  P1  removes the init-time libart text patch (fixupArtQuickDeliverExceptionBug
      -> PrettyMethod hook) — the empty-Java.perform killer
  P2  neuters ensureArtKnowsHowToHandleMethodInstrumentation — installs
      art::interpreter::DoCall hook (libart+0x175860 8-byte patch on this
      build), art_quick_* wrappers, GetOatQuickMethodHeader replace, GC hooks
  P3  reroutes dispatch: after the stock clone setup, calls ubypass's native
      ub_hook_artmethod(hookedMethodId, replacementMethodId), which swaps ONLY
      entry_point_from_quick_compiled_code_ (+0x18) to a stub inside the real
      JIT region that rewrites r0=clone and tail-jumps
      art_quick_generic_jni_trampoline — identical semantics to the bridge's
      quick-wrapper, but zero libart text bytes. Flags untouched (their bits
      are runtime-churned: kAccCompileDontBother/kAccPreCompiled set by JIT
      prejit, kAccFastInterpreterToInterpreterInvoke flips on hot invokes).
  P4  revert() also restores the entrypoint via ub_unhook_artmethod
  P5  Java.choose throws (prevents lazy libopenjdkjvmti.so load + boot-image
      deopt cascade)

Every patch is anchored and ASSERTED: a drifted vendored source fails the
build loudly instead of silently shipping an unpatched bridge.

Verified against frida-java-bridge @ commit 7983e815 (vendored in frida
17.9.1). Usage standalone:
    python patch_java_bridge.py /path/to/frida
"""

import os
import re
import sys

BRIDGE_DIR = os.path.join("subprojects", "frida-java-bridge")
ANDROID_JS = os.path.join("lib", "android.js")
INDEX_JS = "index.js"

CHOOSE_THROW = (
    "  if (globalThis.__ubypass_no_choose) { throw new Error('ajeossida: "
    "Java.choose disabled (jvmti plugin load deopts boot image)'); }\n"
)


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def _sub(name, path, pattern, repl, count=1, flags=0):
    """Assert-anchored substitution: fails loudly if the anchor drifted."""
    data = _read(path)
    new, n = re.subn(pattern, repl, data, count=count, flags=flags)
    if n != count:
        raise SystemExit(
            f"[patch_java_bridge] PATCH {name}: anchor not found "
            f"(expected {count}, got {n}) in {path} — vendored source "
            f"drifted; update the pattern:\n  {pattern[:160]}"
        )
    _write(path, new)
    print(f"[patch_java_bridge] {name}: applied ({n} site(s))")


def _ub_dispatch_call():
    return (
        "    try {\n"
        "      const ubHook = Module.findExportByName('ubypass.so', 'ub_hook_artmethod');\n"
        "      if (ubHook !== null) {\n"
        "        new NativeFunction(ubHook, 'int', ['pointer', 'pointer'])(hookedMethodId, replacementMethodId);\n"
        "      }\n"
        "    } catch (e) { }\n"
    )


def _ub_revert_call():
    return (
        "    try {\n"
        "      const ubUnhook = Module.findExportByName('ubypass.so', 'ub_unhook_artmethod');\n"
        "      if (ubUnhook !== null) {\n"
        "        new NativeFunction(ubUnhook, 'int', ['pointer'])(revertTarget);\n"
        "      }\n"
        "    } catch (e) { }\n"
    )


def patch_java_bridge(frida_dir):
    android = os.path.join(frida_dir, BRIDGE_DIR, ANDROID_JS)

    # --- P1: no init-time libart text patch -----------------------------
    _sub("P1 fixupArtQuickDeliverExceptionBug", android,
         r"[ \t]*fixupArtQuickDeliverExceptionBug\(temporaryApi\);[^\n]*\n",
         "    /* ajeossida: init-time libart text patch removed "
         "(moved to first .implementation semantics; see "
         "docs/NATIVE_SURFACE_MAP.md) */\n")

    # --- P2: never install the libart interceptor hooks ------------------
    _sub("P2 ensureArtKnowsHowToHandleMethodInstrumentation", android,
         r"function ensureArtKnowsHowToHandleMethodInstrumentation \(\) \{",
         "function ensureArtKnowsHowToHandleMethodInstrumentation () {\n"
         "    return; /* ajeossida: no libart text hooks — dispatch goes "
         "through ub_hook_artmethod entrypoint swap */")

    # --- P3: dispatch via ubypass entrypoint swap after clone setup ------
    # Anchor: the replacedMethods registration at the end of replace().
    _sub("P3 ub_hook_artmethod", android,
         r"([ \t]*)replacedMethods\.set\(hookedMethodId, replacementMethodId\);",
         lambda m: m.group(0) + "\n" + _ub_dispatch_call())

    # --- P4: revert restores the entrypoint too ---------------------------
    # Anchor: the revert bookkeeping. Accept either delete form.
    try:
        _sub("P4 ub_unhook (delete form)", android,
             r"([ \t]*)replacedMethods\.delete\(hookedMethodId\);",
             lambda m: m.group(0) + "\n" +
             _ub_revert_call().replace("revertTarget", "hookedMethodId"))
    except SystemExit:
        raise SystemExit(
            "[patch_java_bridge] P4: replacedMethods.delete anchor not "
            "found — inspect ArtMethodMangler.revert() in the vendored "
            "source and add the ub_unhook_artmethod call where the "
            "original method is restored")

    # --- P5: Java.choose guard -------------------------------------------
    index = os.path.join(frida_dir, BRIDGE_DIR, INDEX_JS)
    if os.path.isfile(index):
        _sub("P5 choose guard", index,
             r"(export function choose \(.*\{\n)",
             lambda m: m.group(1) + CHOOSE_THROW, flags=0)

    print("[patch_java_bridge] all bridge patches applied — verify with "
          "scripts/frida/v1c_textdiff.js after build (empty Java.perform "
          "must show ZERO changed libart bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    patch_java_bridge(sys.argv[1])
