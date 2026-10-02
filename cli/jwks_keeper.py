"""Keep the registry's Google signing keys current.

  python cli/jwks_keeper.py                 one sync: add new Google kids, remove rotated-out ones
  python cli/jwks_keeper.py --loop 3600     keep running
  python cli/jwks_keeper.py --print-env [--mock]   print KIDS/MODULI env for script/Deploy.s.sol

Google rotates these keys frequently (two are live at any time). Without a running keeper, registerSigner
fails once the on-chain keys are stale; already-registered signers are unaffected. Each rotation costs two
transactions (one set, one remove), about 60k gas each: negligible on an L2, a few dollars on mainnet.
Only kids that look like Google's (40 hex chars) are ever removed, so a dev key survives syncs.
"""

import argparse
import re
import sys
import time

from common import ROOT, env, google_keys, registry, send, w3

ap = argparse.ArgumentParser()
ap.add_argument("--loop", type=int, help="seconds between syncs")
ap.add_argument("--print-env", action="store_true")
ap.add_argument("--mock", action="store_true", help="with --print-env: include the MOCK_TEE dev key and image digest")
a = ap.parse_args()

if a.print_env:
    keys = google_keys()
    digests = []
    if a.mock:
        sys.path.insert(0, str(ROOT))
        from auditor import credential as cred

        keys[cred.MOCK_KID] = cred.mock_modulus()
        digests.append("0x" + cred.MOCK_IMAGE_DIGEST.split(":")[1])
    print("export KIDS=" + ",".join(keys))
    print("export MODULI=" + ",".join("0x" + m.hex() for m in keys.values()))
    if digests:
        print("export IMAGE_DIGESTS=" + ",".join(digests))
    sys.exit(0)


def on_chain_kids(reg) -> dict[str, bytes]:
    current: dict[str, bytes] = {}
    start = int(env("REGISTRY_DEPLOY_BLOCK"))
    for e in sorted(reg.events.GoogleKeySet().get_logs(from_block=start) + reg.events.GoogleKeyRemoved().get_logs(from_block=start),
                    key=lambda e: (e["blockNumber"], e["logIndex"])):
        if e["event"] == "GoogleKeySet":
            current[e["args"]["kid"]] = e["args"]["modulus"]
        else:
            current.pop(e["args"]["kid"], None)
    return current


def sync():
    w = w3()
    reg = registry(w)
    want, have = google_keys(), on_chain_kids(reg)
    for kid, modulus in want.items():
        if have.get(kid) != modulus:
            send(w, reg.functions.setGoogleKey(kid, modulus), f"setGoogleKey {kid}")
    for kid in have:
        if kid not in want and re.fullmatch(r"[0-9a-f]{40}", kid):
            send(w, reg.functions.removeGoogleKey(kid), f"removeGoogleKey {kid}")
    print(f"{time.strftime('%H:%M:%S')} in sync: {sorted(want)}")


while True:
    sync()
    if not a.loop:
        break
    time.sleep(a.loop)
