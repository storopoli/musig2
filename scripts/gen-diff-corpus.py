"""Generate the BIP-327 differential test corpus, test/vectors/diff/corpus.json.

Every expected value in the corpus is computed by the BIP-327 reference
implementation, reference.py from the bitcoin/bips repository, taken at
commit b34d9f751791d4feb22feff4f2ed00bcac83961b (SHA-256 of reference.py
below). test/DiffCorpus.hs replays every session through the library's public
API and compares the results byte for byte.

Regenerate (from the package root, with Python 3.9 or newer; the committed
file was made with Python 3.14):

    git clone https://github.com/bitcoin/bips /path/to/bips
    git -C /path/to/bips checkout b34d9f751791d4feb22feff4f2ed00bcac83961b
    python3 -I scripts/gen-diff-corpus.py /path/to/bips/bip-0327/reference.py \\
        > test/vectors/diff/corpus.json

(about a minute on 16 cores; it uses every core), then update the SHA-256
of corpus.json in test/DiffCorpus.hs and in test/vectors/diff/README.md. The
output depends only on SEED and reference.py: regenerating with the same
inputs gives the same bytes. The script refuses any reference.py whose
SHA-256 differs from REFERENCE_SHA256, because it executes that file.

The corpus has two parts:

* "nonce_gen": standalone NonceGen cases, covering every combination of
  absent, empty and non-empty optional inputs, with the expected secret nonce
  (97-byte encoding) and public nonce.
* "sessions": complete signing sessions with 1 to 8 signers (some with
  duplicate keys, some with every key equal), optionally sorted with KeySort,
  chains of plain, x-only and BIP-341 Taproot tweaks (tweaks 0 and n - 1,
  x-only tweaks of keys with odd y so that gacc = n - 1, and tweaks whose
  result is infinity), empty, 32-byte and longer-than-255-byte messages,
  nonces from NonceGen bound to every combination of the optional inputs,
  DeterministicSign signers, imported secret nonces whose aggregate has a half
  (or both) at infinity, the partial signatures, the final signature, and
  PartialSigVerify cases that must fail.

Field reference (all byte strings are lower-case hex):

  nonce_gen[]: rand, pk, sk (or null), aggpk (or null), msg (or null),
    extra_in (or null), secnonce, pubnonce
  sessions[]:
    id, sks (signer order), key_sort_input (or null: a permutation of the
    public keys whose KeySort is the signer order), q (KeyAgg before the
    tweaks; null without tweaks), tweaks[] ({"plain"/"xonly": tweak} or
    {"taproot": merkle root or null}), tweak_error (null, or
    "TweakResultAtInfinity" from the last tweak, in which case nothing below
    is present), aggpk (Q after the tweaks, 33 bytes), gacc_neg
    (gacc = n - 1), msg,
    signers[]: nonce, pubnonce, psig. The nonce is one of
      {"rand", "bind", "extra_in"}: NonceGen with these random bytes and
        extra input, given the signer's secret key if bind has bit 1 set,
        the session's x-only aggregate key if bit 2, its message if bit 4;
      {"secnonce"}: an imported secret nonce;
      {"det_rand"}: DeterministicSign (always the last signer), with this
        auxiliary randomness (or null), and the other signers' aggregate
        nonce as aggothernonce.
    aggnonce, sig, sig_valid (false only when both halves of the aggregate
    nonce are infinity, so that BIP-327 substitutes G for the final nonce),
    bad_verify[]: {kind, signer, other, expected}, where kind is one of
      plus_one (psig + 1), zero (psig 0), out_of_range (psig = n),
      wrong_signer (signer's psig checked as other's), swapped_nonces (the
      public nonces of signer and other swapped), wrong_msg (msg || 0x00).

Run only with `python3 -I`, so that nothing from the working directory or
the environment is imported.
"""

import functools
import hashlib
import importlib.util
import json
import multiprocessing
import random
import sys

BIPS_COMMIT = "b34d9f751791d4feb22feff4f2ed00bcac83961b"
REFERENCE_SHA256 = "1167993fe159c39c004f74d9046e931ae700a2ce9203c4cf58a51a000c1294e8"
SEED = 327
SESSIONS = 300
NONCE_GEN_CASES = 48


def load_reference(path):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != REFERENCE_SHA256:
        sys.exit(f"{path}: SHA-256 {digest}, expected {REFERENCE_SHA256} (bips commit {BIPS_COMMIT})")
    spec = importlib.util.spec_from_file_location("bip327_reference", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ref = load_reference(sys.argv[1]) if len(sys.argv) == 2 else sys.exit(__doc__)
n = ref.n
G = ref.G

# KeyAgg and the tweaks are recomputed by every Sign and PartialSigVerify call
# of the reference implementation. They are pure, so caching them changes no
# result, only the running time.
_key_agg_and_tweak = ref.key_agg_and_tweak


@functools.lru_cache(maxsize=64)
def _cached_key_agg_and_tweak(pubkeys, tweaks, is_xonly):
    return _key_agg_and_tweak(list(pubkeys), list(tweaks), list(is_xonly))


ref.key_agg_and_tweak = lambda pubkeys, tweaks, is_xonly: _cached_key_agg_and_tweak(
    tuple(pubkeys), tuple(tweaks), tuple(is_xonly))


def h(b):
    return None if b is None else b.hex()


def b32(i):
    return i.to_bytes(32, "big")


def random_scalar(rng):
    return rng.randrange(1, n)


def random_xonly(rng):
    return ref.xbytes(ref.point_mul(G, random_scalar(rng)))


def opt_bytes(rng, state, maxlen):
    """'absent' -> None, 'empty' -> b'', 'bytes' -> 1..maxlen random bytes."""
    if state == "absent":
        return None
    if state == "empty":
        return b""
    return rng.randbytes(rng.randrange(1, maxlen + 1))


# NonceGen ------------------------------------------------------------------------

def nonce_gen_case(rng, i):
    states = ("absent", "empty", "bytes")
    # Cycle through all 2 * 2 * 3 * 3 = 36 combinations, then random ones.
    combo = i if i < 36 else rng.randrange(36)
    use_sk, use_aggpk = combo & 1, (combo >> 1) & 1
    msg_state, extra_state = states[(combo >> 2) % 3], states[(combo >> 2) // 3]
    d = random_scalar(rng)
    sk = b32(d) if use_sk else None
    pk = ref.individual_pk(b32(d))
    aggpk = random_xonly(rng) if use_aggpk else None
    msg = opt_bytes(rng, msg_state, 300)
    extra_in = opt_bytes(rng, extra_state, 16)
    rand = rng.randbytes(32)
    secnonce, pubnonce = ref.nonce_gen_internal(rand, sk, pk, aggpk, msg, extra_in)
    return {
        "rand": h(rand), "pk": h(pk), "sk": h(sk), "aggpk": h(aggpk), "msg": h(msg),
        "extra_in": h(extra_in), "secnonce": h(bytes(secnonce)), "pubnonce": h(pubnonce),
    }


# Sessions --------------------------------------------------------------------------

def tap_tweak(Q, merkle_root):
    t = ref.int_from_bytes(ref.tagged_hash("TapTweak", ref.xbytes(Q) + (merkle_root or b"")))
    assert t < n
    return t


def gen_keys(rng, idx, u):
    if u >= 2 and idx % 23 == 0:
        return [random_scalar(rng)] * u  # every key equal: no second key
    if u >= 2 and idx % 4 == 0:
        pool = [random_scalar(rng) for _ in range(1 if u == 2 else rng.randrange(2, u))]
        keys = [rng.choice(pool) for _ in range(u)]
        keys[rng.randrange(u)] = keys[rng.randrange(u)]
        return keys
    return [random_scalar(rng) for _ in range(u)]


def gen_tweaks(rng, idx, ctx, qd):
    """Tweak specs, the tweaks as ApplyTweak arguments, and the context after
    them (None if the last tweak fails). qd is the discrete log of Q."""
    count = rng.choice([0, 0, 1, 1, 2, 3, 4])
    kill = idx % 50 == 7  # the last tweak makes Q infinity
    if kill:
        count = max(count, 1)
    specs, tweaks, is_xonly = [], [], []
    for k in range(count):
        kind = rng.choice(["plain", "xonly", "xonly", "taproot"])
        if kill and k == count - 1:
            kind = rng.choice(["plain", "xonly"])
        g = n - 1 if kind != "plain" and not ref.has_even_y(ctx.Q) else 1
        if kill and k == count - 1:
            t = (-g * qd) % n
            specs.append({kind: h(b32(t))})
        elif kind == "taproot":
            root = rng.choice([None, rng.randbytes(32)])
            t = tap_tweak(ctx.Q, root)
            specs.append({"taproot": h(root)})
        else:
            t = rng.choice([0, n - 1, rng.randrange(1, 1000), random_scalar(rng), random_scalar(rng)])
            specs.append({kind: h(b32(t))})
        tweaks.append(b32(t))
        is_xonly.append(kind != "plain")
        try:
            ctx = ref.apply_tweak(ctx, b32(t), kind != "plain")
        except ValueError:
            assert kill and k == count - 1
            return specs, tweaks, is_xonly, None
        assert not (kill and k == count - 1), "tweak to infinity did not fail"
        qd = (g * qd + t) % n
        assert ref.point_mul(G, qd) == ctx.Q
    return specs, tweaks, is_xonly, ctx


def gen_msg(rng, idx):
    m = idx % 10
    if m == 0:
        return b""
    if m == 1:
        return rng.randbytes(rng.randrange(256, 301))
    if m in (2, 3, 4):
        return rng.randbytes(32)
    return rng.randbytes(rng.randrange(1, 65))


# Signer counts, cycled through: every count from 1 to 8, mostly small ones
# to keep the corpus small.
SIGNER_COUNTS = [1, 2, 2, 3, 1, 2, 4, 2, 3, 5, 1, 2, 3, 6, 2, 1, 2, 3, 2, 7, 1, 2, 3, 4, 2, 1, 2, 3, 8, 2]


def gen_session(rng, idx):
    u = SIGNER_COUNTS[idx % len(SIGNER_COUNTS)]
    ds = gen_keys(rng, idx, u)
    pubkeys = [ref.individual_pk(b32(d)) for d in ds]
    key_sort_input = None
    if idx % 5 == 1:
        key_sort_input = list(pubkeys)
        rng.shuffle(key_sort_input)
        order = sorted(range(u), key=lambda i: pubkeys[i])
        ds = [ds[i] for i in order]
        pubkeys = [pubkeys[i] for i in order]
        assert pubkeys == ref.key_sort(list(key_sort_input))
    session = {
        "id": idx,
        "sks": [h(b32(d)) for d in ds],
        "key_sort_input": None if key_sort_input is None else [h(pk) for pk in key_sort_input],
    }
    ctx0 = ref.key_agg(pubkeys)
    qd0 = sum(ref.key_agg_coeff(pubkeys, pk) * d for pk, d in zip(pubkeys, ds)) % n
    specs, tweaks, is_xonly, ctx = gen_tweaks(rng, idx, ctx0, qd0)
    session["q"] = h(ref.cbytes(ctx0.Q)) if specs else None
    session["tweaks"] = specs
    if ctx is None:
        session["tweak_error"] = "TweakResultAtInfinity"
        return session
    session["tweak_error"] = None
    assert ctx == ref.key_agg_and_tweak(pubkeys, tweaks, is_xonly)
    msg = gen_msg(rng, idx)
    aggpk = ref.xbytes(ctx.Q)
    session.update({"aggpk": h(ref.cbytes(ctx.Q)), "gacc_neg": ctx.gacc == n - 1, "msg": h(msg)})

    # Nonces: NonceGen for every signer, except for an imported nonce that
    # cancels the others' (a half of the aggregate nonce at infinity) or a
    # DeterministicSign signer, always the last one.
    special = None
    if u >= 2 and idx % 12 in (5, 6, 7):
        special = ("r1inf", "r2inf", "bothinf")[idx % 12 - 5]
    elif u >= 2 and idx % 6 == 3:
        special = "det"
    signers, secnonces, pubnonces = [], [], []
    for i, d in enumerate(ds):
        if special is not None and i == u - 1:
            break
        combo = (idx * 5 + i) % 24  # every combination of bindings and extra input
        bind_sk, bind_aggpk, bind_msg = bool(combo & 1), bool(combo & 2), bool(combo & 4)
        extra_in = opt_bytes(rng, ("absent", "empty", "bytes")[combo // 8], 16)
        rand = rng.randbytes(32)
        secnonce, pubnonce = ref.nonce_gen_internal(
            rand, b32(d) if bind_sk else None, pubkeys[i], aggpk if bind_aggpk else None, msg if bind_msg else None, extra_in)
        signers.append({"nonce": {"rand": h(rand), "bind": combo % 8, "extra_in": h(extra_in)}, "pubnonce": h(pubnonce)})
        secnonces.append(secnonce)
        pubnonces.append(pubnonce)
    if special in ("r1inf", "r2inf", "bothinf"):
        k1 = (-sum(ref.int_from_bytes(bytes(s[0:32])) for s in secnonces)) % n
        k2 = (-sum(ref.int_from_bytes(bytes(s[32:64])) for s in secnonces)) % n
        if special == "r2inf":
            k1 = random_scalar(rng)
        if special == "r1inf":
            k2 = random_scalar(rng)
        assert k1 != 0 and k2 != 0
        secnonce = bytearray(b32(k1) + b32(k2) + pubkeys[-1])
        pubnonce = ref.cbytes(ref.point_mul(G, k1)) + ref.cbytes(ref.point_mul(G, k2))
        signers.append({"nonce": {"secnonce": h(bytes(secnonce))}, "pubnonce": h(pubnonce)})
        secnonces.append(secnonce)
        pubnonces.append(pubnonce)
    det_psig = None
    if special == "det":
        det_rand = rng.choice([None, rng.randbytes(32)])
        aggothernonce = ref.nonce_agg(pubnonces)
        pubnonce, det_psig = ref.deterministic_sign(b32(ds[-1]), aggothernonce, pubkeys, tweaks, is_xonly, msg, det_rand)
        signers.append({"nonce": {"det_rand": h(det_rand)}, "pubnonce": h(pubnonce)})
        pubnonces.append(pubnonce)
    aggnonce = ref.nonce_agg(pubnonces)
    session["aggnonce"] = h(aggnonce)
    session_ctx = ref.SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    psigs = [ref.sign(secnonces[i], b32(ds[i]), session_ctx) for i in range(len(secnonces))]
    if det_psig is not None:
        psigs.append(det_psig)
    for signer, psig in zip(signers, psigs):
        signer["psig"] = h(psig)
    session["signers"] = signers
    sig = ref.partial_sig_agg(psigs, session_ctx)
    session["sig"] = h(sig)
    # Invalid only if both halves of the aggregate nonce are infinity: the
    # final nonce is then infinity too, and BIP-327 substitutes G for it.
    session["sig_valid"] = schnorr_verify_any_length(msg, aggpk, sig)
    assert session["sig_valid"] == (special != "bothinf")

    # PartialSigVerify cases that must fail: one per session, of each kind in turn.
    bad = []
    kinds = ["plus_one", "zero", "out_of_range", "wrong_msg"] + (["wrong_signer", "swapped_nonces"] if u >= 2 else [])
    for kind in [kinds[(idx // 2) % len(kinds)]]:
        i = rng.randrange(u)
        j = rng.choice([x for x in range(u) if x != i]) if kind in ("wrong_signer", "swapped_nonces") else None
        s_i = ref.int_from_bytes(psigs[i])
        psig, nonces, vmsg, checked = psigs[i], list(pubnonces), msg, i
        if kind == "plus_one":
            psig = b32((s_i + 1) % n)
        elif kind == "zero":
            psig = b32(0)
        elif kind == "out_of_range":
            psig = b32(n)
        elif kind == "wrong_msg":
            vmsg = msg + b"\x00"
        elif kind == "wrong_signer":
            checked = j
        else:
            nonces[i], nonces[j] = nonces[j], nonces[i]
        expected = ref.partial_sig_verify(psig, nonces, pubkeys, tweaks, is_xonly, vmsg, checked)
        assert not expected
        bad.append({"kind": kind, "signer": i, "other": j, "expected": expected})
    session["bad_verify"] = bad
    return session


def schnorr_verify_any_length(msg, pubkey, sig):
    """BIP-340 verification without reference.py's 32-byte message restriction."""
    P = ref.lift_x(pubkey)
    r = ref.int_from_bytes(sig[0:32])
    s = ref.int_from_bytes(sig[32:64])
    if P is None or r >= ref.p or s >= n:
        return False
    e = ref.int_from_bytes(ref.tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = ref.point_add(ref.point_mul(G, s), ref.point_mul(P, n - e))
    return R is not None and ref.has_even_y(R) and ref.x(R) == r


def generate(job):
    """One case, from its own random number generator: the output does not
    depend on how the cases are spread over processes."""
    name, i = job
    rng = random.Random(f"musig2 differential corpus/{SEED}/{name}/{i}")
    try:
        case = (nonce_gen_case if name == "nonce_gen" else gen_session)(rng, i)
    except Exception as e:
        raise RuntimeError(f"{name} #{i}: {e!r}") from e
    return json.dumps(case, separators=(",", ":"))


def main():
    out = sys.stdout
    header = {"bips_commit": BIPS_COMMIT, "reference_sha256": REFERENCE_SHA256, "seed": SEED}
    out.write("{\n" + ",\n".join(f"{json.dumps(k)}: {json.dumps(v)}" for k, v in header.items()) + ",\n")
    with multiprocessing.get_context("fork").Pool() as pool:
        for name, count in (("nonce_gen", NONCE_GEN_CASES), ("sessions", SESSIONS)):
            cases = pool.map(generate, [(name, i) for i in range(count)], chunksize=1)
            out.write(f'"{name}": [\n' + ",\n".join(cases) + "\n]" + ("," if name == "nonce_gen" else "") + "\n")
    out.write("}\n")


if __name__ == "__main__":
    main()
