# What happens when a node misbehaves

`POSITION.md` lists two gaps in one line: *no accountability and no robustness*.
That line is accurate and it is also lazy, because the two are different
properties, they sit at different rungs of a ladder that has five of them, and
in this deployment they have very different prices. One of them turns out not to
be a price at all.

Every figure here is measured on `host-a` at `n = 7`, `T = 2`, 128-bit field
(`artifacts/multiplication_cost.json`).

---

## 1. The ladder, which is five rungs and not two

Take a protocol where one of the seven nodes deviates. What can the rest of the
world end up knowing?

| | what it gives | needs |
|---|---|---|
| **1. security with abort** | the output is right, or there is no output | dishonest majority is fine |
| **2. identifiable abort** | ...and the honest parties learn *who* | dishonest majority is fine |
| **3. publicly identifiable abort** | ...and so does anybody reading the transcript | a bulletin board |
| **4. public accountability** | ...and a *judge* reaches a verdict from the transcript alone, naming enough parties to explain the abort | a bulletin board |
| **5. robustness / guaranteed output delivery** | there is no abort. The honest parties get the output whatever the corrupt ones do | **honest majority** |

**Public verifiability is not on this ladder.** It is the orthogonal axis: *the
answer is right, and an outsider can check it*. That is what Baum–Damgård–Orlandi
2014 gives and what this stack has. A protocol can be publicly verifiable and
still stop dead at rung 1, which is exactly the situation here.

So the honest statement of the gap is: **this stack is publicly verifiable and
sits on rung 1.**

### Where the rungs come from

**Rung 2** is Ishai, Ostrovsky and Zikas (CRYPTO 2014), and their framing is the
part worth keeping: identifiable abort exists *because* a dishonest majority
rules out rung 5. When a single malicious party can force an abort, the best
available consolation is to make aborting cost the adversary its anonymity. They
also prove a limit --- information-theoretic identifiable abort is impossible in
the OT-hybrid model, so pairwise correlated randomness is not enough.

**Rungs 3 and 4** are the difference between *the other parties* knowing and
*the world* knowing. Küsters, Truderung and Vogt (CCS 2010) supply the object
that makes rung 4 precise: a **judge**, an algorithm that takes the public
transcript and returns a verdict. Rivinius et al. strengthen it to *strong*
accountability --- on abort, name not one party but at least as many as it takes
to cause an abort, so a single scapegoat is not a valid verdict.

**Rung 5 needs an honest majority and is therefore not available to most of this
literature at all**, which is why almost everything in the auditable-MPC line
lives on rungs 1 to 4.

---

## 2. Where this stack actually sits

Three mechanisms, three different rungs, and it is worth separating them because
the repository has previously described all three as "attribution".

**The dealt share: rung 4, and only at the boundary.** `rust/qomm-transport/src/roles.rs`
has the maker sign each dealt share, so a node that later claims a different
share can be shown to have done so, by anyone. That is a judge-checkable verdict
--- rung 4 --- but its scope is one message, not the protocol.

**What the node feeds the engine: rung 0.** Nothing. This is the gap `BINDING.md`
is entirely about. A node can check its share against the commitment and then
put something else into MP-SPDZ, and the transcript does not show it.

**The MPC itself: rung 1.** `malicious-shamir-party.x`, and MP-SPDZ's own README
is explicit about what that word buys:

> malicious means that not following the protocol will at least be detected

Detected. Not attributed, not survived. The protocol stops and nobody is named.

**And the quote proof is on the other axis entirely.** It shows the winner was
the minimum of the committed keys. If it fails, you know the answer was wrong.
You do not know which node made it wrong, and you do not have an answer.

---

## 3. Robustness is not a cost here. It is a saving.

This is the finding, and it took a measurement to see because "what it costs" is
a claim about a baseline, and the baseline that matters is the engine that is
actually deployed rather than the one a paper compares against.

**The setting is better than it looks.** `T = 2` of `n = 7` is `t/n = 0.286`,
which is below `n/3`. Goyal, Song and Zhu (CRYPTO 2020) give unconditionally
secure MPC with guaranteed output delivery for `t < n/2` assuming a broadcast
channel, **and note that at `t < n/3` broadcast can be simulated over
point-to-point links**. So this deployment is in the stricter of the two regimes
and needs no broadcast channel assumed --- and in any case the bulletin board
that publicly auditable MPC already requires would serve as one.

Their price for that: **5.5 field elements per party per multiplication in the
best case, 7.5 once a corrupted party has been identified**, against 5.5 for the
best semi-honest protocol. Hence the title, *Guaranteed Output Delivery Comes
Free in Honest Majority MPC*.

**Free against what?** Measured here, same host, same parameters, as a slope
between two circuit sizes in one SIMD row:

| | elements per party per multiplication | rounds |
|---|---:|---:|
| semi-honest Shamir, single phase | 5.714 | 4, flat |
| **malicious Shamir, online phase only** | **8.000** | 3, flat |
| **malicious Shamir, single phase (triples generated in the run)** | **48.231** | 17 → 137 |
| **GSZ 2020, guaranteed output delivery, single phase** | **5.5 to 7.5** | --- |

**Guaranteed output delivery costs less than the online phase alone of what is
deployed**, and 6.4x less than its total --- while giving strictly more, because
it does not stop. GSZ is single-phase and information-theoretic: there is no
offline phase to move off the critical path, so 5.5 is everything.

**So the reason this deployment has no robustness is the engine, not the
setting.** MP-SPDZ's honest-majority malicious protocols --- Shamir, Rep3, PS,
SY, Rep4 --- are all secure with abort, and GSZ is not implemented in it. That is
a very different kind of gap from "we chose a threat model that cannot have it".

### The instrument was checked before it was believed

The harness was built for a different question, so its semi-honest arm is a
control against a number it was not fitted to: **GSZ state the best known
semi-honest protocol at 5.5 elements per party, and the harness returns 5.714**
--- four per cent, on a figure from a paper. A control circuit with the
multiplications replaced by additions has slope zero, confirming that the input
sharing and the single opening do not scale with the size and so are not inside
the slope.

### Two mistakes this measurement nearly repeated

**The first version measured 48.2 elements and 22,002 rounds for 22,000
multiplications.** It was running a sequential `for_range`, so every
multiplication sat on the critical path and paid its own round. That is a real
quantity and it is not a per-multiplication cost; the quote circuit batches, and
so does the corrected program, which holds at 3 rounds from 2,000
multiplications to 220,000.

**And the phase split is recorded separately on purpose.** Measuring
preprocessing in a single-phase harness and calling it an online cost is an error
this project has already made once, with edaBits, where it produced a figure two
orders of magnitude wrong. Here both numbers are kept: 48.2 total, 8.0 online.
The comparison to GSZ uses the total, because GSZ has no offline phase --- but
the online figure is what a deployment with real preprocessing would pay, and
conflating them would flatter the wrong side.

---

## 3.5 "Just put GSZ into SPDZ" --- three reasons that is not the move

**It is not a thing that can be done, in the literal sense.** SPDZ is a
*dishonest majority* protocol: MACs on every share, offline/online, secure
against `n-1` corruptions. GSZ is an *honest majority* protocol: Shamir,
information-theoretic, and its guarantees exist **because** `t < n/2`. Putting
one inside the other is not an integration; the guarantee GSZ provides is
unavailable at SPDZ's corruption threshold at all.

The sentence that does typecheck is *"add GSZ to the MP-SPDZ framework as
another honest-majority protocol"*, alongside `shamir-party.x` and
`malicious-shamir-party.x`. **This stack does not use SPDZ.** It uses the Shamir
protocols that happen to ship in the same repository.

**Even stated correctly it is not a protocol plugin.** MP-SPDZ's protocol
interface is `init_mul / prepare_mul / exchange / finalize_mul` over a fixed
party set moving forward. GSZ needs three things that interface does not have:
the circuit cut into **segments with checkpoints** so a failure re-runs a segment
rather than the run; a **party set and threshold that change mid-computation** as
parties are eliminated, which forces re-sharing of the segment's inputs; and an
asymmetric **king with relays**. That is a change to the virtual machine, not a
new class beside the existing ones.

**And it would not deliver accountability.** GSZ's identification is towards the
other parties. Section 4.

---

## 3.6 What is available without any of that: the shares are already an error-correcting code

Reading `Protocols/MaliciousShamirMC.hpp` makes the current behaviour concrete.
On an opening, each party sends its share; the receiver reconstructs from
`t+1` of them, then reconstructs again from every longer prefix and compares:

    if (check != value)
        throw mac_fail("inconsistent Shamir secret sharing");

**That is error *detection* performed on data that supports error
*correction*.** Shamir shares of a degree-`t` secret are a Reed--Solomon
codeword `RS[n, t+1]`. At `n = 7`, `t = 2` that is `RS[7, 3]`, minimum distance
`5`, and the number of errors correctable is `floor((5-1)/2) = 2` --- **exactly
`T`**. Berlekamp--Welch would return both the correct value *and* the error
locator, which names the parties that sent wrong shares. Local computation, no
extra rounds.

**Two things stop this being a free lunch, and they are worth stating precisely
because they are what GSZ is a paper about.**

**One: the opening only collects `2t+1` shares.** `finalize_raw` does
`shares.resize(2 * threshold + 1)` --- five of seven. `RS[5, 3]` has distance
`3` and corrects one error, not two. Correcting `T = 2` needs all seven, which
is `n` instead of `2t+1` shares per opening: **40% more opening traffic**, and
that is the price, not zero.

**Two: products are degree `2t` before reduction.** A degree-`4` sharing over
seven points is `RS[7, 5]`, distance `3`, one correctable error. So the
correction capability is `T` on ordinary values and `T-1` on unreduced products,
and a protocol that wants robustness has to avoid ever needing the second ---
which is what GSZ's segmenting and re-sharing machinery is for.

**So the honest summary is: robust *reconstruction* at `t < n/3` is a local
decode plus 40% on openings, and robust *computation* is GSZ and is a bigger
job.** The first is worth doing on its own --- it removes the cheapest griefing
attack --- and nothing in this repository has measured it.

### Asked directly: is it known who cheated? No --- and the obvious guess is wrong

Four runs on `host-a`, one byte flipped in one party's preprocessing file, `-F`,
restore between runs (`artifacts/locate.json`):

| corrupted party | what the transcript says |
|---|---|
| 3 | `Fatal error at fp2000-0:3 (MULS): inconsistent Shamir secret sharing` |
| 1 | **identical** --- the `3` is the instruction offset, not the party |
| 5 | `Fatal error in communication: read_some: stream truncated` |
| 6 | `Fatal error in communication: read_some: stream truncated` |

**The first two lines settle it**: the same string for two different culprits, so
the transcript carries no party information. **The last two are worse than
nothing.** When the bad data belongs to a party the others reach later, they die
on a dropped connection first --- so the attribution a reader would naturally
reach for, *whose link went down*, points at whichever process exited first
rather than at the party whose data was wrong. **An operator debugging this would
blame the wrong node.**

### And it is decidable, on data the protocol already sends

`rust/qomm-audit/src/locate.rs` is the decode MP-SPDZ does not do, with 26 tests.
Berlekamp--Welch: solve for `Q` of degree `<= d+e` and monic `E` of degree `e`
with `Q(x_i) = y_i E(x_i)`, then `P = Q/E` is the true polynomial and every share
off it belongs to a liar.

| | capacity | 0 wrong | 1 | 2 | 3 |
|---|---:|---|---|---|---|
| degree-`t` (ordinary value) | **2** | 300/300 | 300/300 | **300/300** | 0/300 |
| degree-`2t` (unreduced product) | **1** | 300/300 | **300/300** | 0/300 | 0/300 |

*named exactly, out of 300 random trials each*

**`T = 2` and the capacity is 2. That coincidence is the finding** --- this
deployment's corruption threshold sits exactly at the decoding capacity of its
own sharing, so every corruption it is designed to tolerate is also one it could
name. At three the decoder refuses rather than guessing, which is the only
correct behaviour: naming somebody beyond capacity would be worse than silence.

Cost, on data already received, no extra rounds:

| | median |
|---|---:|
| plain Lagrange from 3 of 7, which is what the engine does | 20.6 us |
| locate, no errors | 22.9 us |
| locate, one liar | 88.4 us |
| locate, two liars | 208.1 us |

### And it is now in the engine

`rust/qomm-mpc/patches/locate-inconsistent-shares.patch`, built and run on
`host-a` (`artifacts/decode_patch.json`). Same experiment as above, one byte
flipped in one party's preprocessing:

| corrupted | what the transcript now says |
|---|---|
| P0 / P1 / P3 / P5 / P6 | `... sent by player 0` / `1` / `3` / `5` / `6` |
| {1,4} | `... sent by player 1, player 4` |
| {0,2,5} | `more than 2 parties sent wrong shares, which is beyond the decoding capacity of this sharing` |

Honest runs return the same answer as before. Three liars are refused rather
than guessed at, which is the only correct behaviour past capacity.

**The traffic cost, and the prediction it broke.** `ShamirMC::exchange` is a
*partial* broadcast: with `threshold` set to `2t` it makes each party a sender
to the `2t+1` nearest and no further --- exactly enough to reconstruct a
degree-`2t` sharing and exactly one share short of locating two liars in a
degree-`t` one. So the patch also has to widen the broadcast, and each party
goes from four correspondents per opening to six.

| | before | after | |
|---|---:|---:|---|
| online, elements per party per multiplication | 8.000 | **12.000** | **1.50x** |
| single-phase total | 48.235 | **64.236** | **1.33x** |
| rounds | 3 / 11--23 | 3 / 11--23 | unchanged |
| per quote at `M=16`, global | 17.89 MB | **23.83 MB** | |

**The prediction said this would be free**, on the reading that
`ShamirMC::POpen_Begin` calls `P.send_all()` so every share was already on the
wire. That is the *unbatched* path. The batched one is `exchange`, and it is
what runs. **Third time in this project that reading one code path and assuming
it is the one that executes has cost a number** --- after the `-P`/`-F` compile
flag and after predicting MASCOT's online phase from what Shamir does here.

### The half of the answer that is not free

**This names the party that sent a malformed share. It cannot name the party
that lied about its input**, and that is the more likely attack.

`secret_input()` sums one additive share from each party, so a party that writes
a different number into its own input file is offering a **valid sharing of a
different value**. Nothing is inconsistent. There is no codeword to decode,
because the codeword is fine --- it encodes the wrong secret.

That is the gap `BINDING.md` is about, and the input check detects it without
naming anybody: *"an input the circuit used was not the one that was
committed"*. **Turning that into a verdict means opening one combination per
party rather than one over all inputs** --- `n` openings and `n` masks instead of
one, and the masks are what forced the 164-bit field in the first place.

### And the dealer already publishes what would name that one too

`qomm_transport::roles::Dealing` carries **`share_commitments` --- one commitment
per share per value** --- so that a node can run `check_share` on what it was
handed and anyone can run `adds_up` on whether the shares sum to the committed
value. Those are exactly the commitments a per-party check combines. **What was
missing was not the commitments. It was opening one combination per party
instead of one over all inputs.**

| | statement | outcome |
|---|---|---|
| today | `s = sum_j c_j v_j + m` against `sum_j c_j C_j + C_m` | *an* input was substituted |
| **per party** | `s_p = sum_j c_j x_{p,j} + m_p` against `sum_j c_j C_{p,j} + C_{m_p}` | **node `p` did it** |

`sum_p s_p` is the old opening with the old mask, so this is strictly stronger
rather than an alternative. The soundness argument is unchanged and now applies
per party: the coefficients come from the commitments, so a node has to choose
its error before it can see the coefficient that would cancel it.

**Built and measured** --- `rust/zkpi-harness/src/bin/run_input_check.rs`'s per-party build /
`verify_per_party`, 26 tests, `host-a`:

| inputs | verify, aggregate | verify, per party | |
|---:|---:|---:|---:|
| 16 | 1.52 ms | 10.61 ms | 6.98x |
| 64 | 5.74 ms | 40.00 ms | 6.97x |
| **166** | **14.01 ms** | **103.54 ms** | **7.39x** |

and it named the substituting node at every size.

**Two things came out that were not obvious.**

**It needs a *narrower* field: 160 bits against the aggregate check's 164.**
Party `p` combines *shares*, which are `value_bits + SLACK_BITS = 71` wide
rather than 31, so its combination is wider --- but the mask is that party's own
input and is **not dealt across nodes**, so it does not pay the share slack plus
`log2(n)` that forced the aggregate check to 164. The term that dominated
`BINDING.md` section 3.1 simply is not there.

**And there is no capacity limit.** The Reed--Solomon decode caps at `T = 2` and
refuses at three. This names *any* number of substituting nodes, tested to all
seven, because each party's check stands alone against that party's own
commitments. **That matters, because the case a decoder gives up on is exactly
the case an operator most needs a name for.**

### And the circuit now emits it

`gen_qomm --check-mode per-party`. `secret_input()` folds each share into its
own node's accumulator **as it is read**, because once the sum is formed the
shares are gone; the coefficient is a compile-time constant, so the combination
is local and only the openings travel. The masks are the one input here that is
not split: one is read from each node, which is what makes the field
requirement smaller.

Measured end to end on `host-a`, `M = 16`, seven parties, `T = 2`, 192-bit
field, every arm verified against the cleartext reference:

| | rounds | global | openings | what a failure says |
|---|---:|---:|---:|---|
| no check | 70 | 41.5443 MB | 0 | --- |
| aggregate | 71 | 41.5521 MB | 7 | *an* input was substituted |
| **per party** | **71** | **41.5804 MB** | **49** | **node `p` substituted its input** |

**Naming costs zero extra rounds and 0.068% more traffic than merely
detecting.** Against no check at all it is one round and 0.087%.

**That table is the superseded variant.** Its coefficients are derived from the
dealer's commitments, which are published before a node feeds the engine, so a
node can read them and pick an error in their kernel --- `BINDING.md` 3.0 and
`security.tex` Proposition 1. The sound construction draws the challenge *after*
the input phase and takes its powers modulo the MPC prime; measured at the
matched field it is **one extra round and 0.39% more traffic** than the
aggregate check, with soundness `2^-245` instead of `2^-42`
(`artifacts/sound_check.json`). The rows above are kept because they are what
the 0.39% is measured against.

Forty-nine openings rather than seven because at the 6-bit coefficients the
generator emits, one combination binds a party at about `2^-6`, so seven
repetitions give `2^-42` --- *per party*. They are independent, so they cost one
round together, which is why the round count does not move.

*The prediction said 3 kB and it was 28.3 kB.* The estimate assumed seven
openings and forgot that soundness per party has to be bought by repetition the
same way the aggregate check buys it. The conclusion --- negligible --- survives;
the number was ten times light.

### Is the request the circuit priced the request the taker sent?

The same mechanism, and it had to be run to know. `roles.Trader` and
`roles.MarketMaker` are both `InputParty`, and the request is read through
`secret_input()` exactly like a policy field, so the accumulator should fold it.
*Should* is not *does*.

`rust/zkpi-harness/src/bin/run_identity.rs` follows one quote end to end (`artifacts/identity.json`):

| | |
|---|---|
| honest run | verified, **nobody named** |
| node 4 substitutes **the taker's quantity** | **named: node 4** |

So the chain closes: taker and makers publish a commitment per share → the
coefficients are derived by hashing those commitments → **the same list is
compiled into the circuit** → the circuit opens one combination per node →
anyone recombines the commitments and checks. A failure names a node, and the
taker's request is bound exactly as a maker's policy is.

**Running it found two defects that no amount of reading would have.**

**The generator was emitting fixture coefficients.** `1 + (617*k) % 63`, with a
comment saying a fixture stands in for the Fiat--Shamir derivation because that
needs the commitments. The comment was honest about the substitution and
understated what it costs: **with coefficients a node can predict, the check
proves nothing**, because the whole soundness argument is that the coefficients
arrive after the commitments. Until this run, the two halves of the check had
never been asked to agree.

**And a misconfigured field makes the audit accuse every node.** The first run
compiled at MP-SPDZ's default 128 bits while the commitments live in the
253-bit ed25519 scalar field. The openings wrapped, no party's check matched,
and the verdict named **all seven --- on an entirely honest run**.

That is the worst failure mode an accountability mechanism can have. It does not
fail open or closed; it **convicts everybody**, and an operator reading it could
not tell a misconfiguration from a total compromise. Matching the field is what
`BINDING.md` already recommends at 2.00x traffic; this is a second and
independent reason for it, and it is a sharper one, because the first was about
what can be proved and this is about what gets wrongly asserted.

### What is still not determinable

Three things, and none of them is a bug.

**That the maker's committed policy is one it would honour.** `policy_audit`
shows the fields sit inside bands the venue published. It cannot show intent, and
no cryptography can.

**That the request was real.** The maker never sees it --- that is the design ---
so it cannot tell a genuine request from probing. A venue could learn a policy by
running synthetic requests against it, which is what `is_real` cover traffic and
the disclosure budget exist to bound.

**That every eligible maker was included.** An omission leaves no commitment in
the statement to fail against, so no input check can see it.
`rust/qomm-audit/src/receipts.rs` covers that per slot, on a different axis: a receipt
from every node every slot, so a node that answers only when the answer suits it
is visible in the schedule rather than in the arithmetic.

**So the answer splits, and both halves now have a mechanism.** Who sent a
malformed share: named by the engine, patch applied, 1.33x. Who lied about their
input: named by the dealer's own commitments, built and measured at 7.4x the
check and a narrower field, with the circuit emission left to do.

### Why a griefing abort is worse here than in generic MPC

In most MPC deployments an abort is a liveness problem: retry. **In an auction it
is an economic instrument.** A node that can abort at will, anonymously and at no
cost, can suppress the quotes it does not like --- and a node colluding with a
maker can suppress exactly the ones where that maker is about to be picked off.
That converts a denial of service into a free option.

**This is the application-level reason accountability matters here more than the
generic intuition suggests**, and it is why rung 1 is a worse place to be sitting
than "the protocol occasionally fails" makes it sound.

---

## 3.7 Rung 5, built and run: the decoder is enough if there are nine nodes

§3.6 stops at "robust *reconstruction* at `t < n/3` is a local decode plus 40%
on openings, and robust *computation* is GSZ and is a bigger job". The second
half of that was too pessimistic, and reading the engine is what showed it.

### The line is `n >= 4t+1`, not `t < n/3`

Reed--Solomon corrects `e` errors iff `n - d >= 2e + 1`. A product before degree
reduction is `d = 2t`, and robustness wants `e = t`, so

    n - 2t >= 2t + 1,  i.e.  n >= 4t + 1.

| `n` | `t` | product degree | capacity | |
|---:|---:|---:|---:|---|
| 7 | 2 | 4 | 1 | **one short --- this deployment** |
| **9** | **2** | 4 | **2** | enough |
| 13 | 3 | 6 | 3 | enough |

`t < n/3` is the line where segmenting, checkpoints and player elimination
become necessary. **`t < n/4` is the line where a decoder is enough.** The
distance between them is the whole of GSZ's machinery, and two more nodes buys
past it.

### And it lands on ATLAS, not on the protocol deployed

`Protocols/Shamir.hpp` is GRR re-sharing --- `prepare_mul` does
`resharing->add_mine(x * y * rec_factor)` and `finalize` sums the received
degree-`t` shares. **There is no degree-`2t` opening anywhere in it**, so there
is nothing to correct and none of this touches `malicious-shamir-party.x`.

`Protocols/Atlas.hpp` is Damgård--Nielsen and does what the argument needs, and
two of the three things §3.5 said GSZ would have to be written for are already
sitting in it:

| | |
|---|---|
| **the king with relays** | already there --- `base_king`, `next_king = (next_king + 1) % n` |
| **random double sharings** | already there --- `get_double_sharing()` returns `{[r]_2t, [r]_t}` |
| hyper-invertible matrices | already there --- `Shamir<T>::get_randoms` uses `get_hyper` |
| segments, checkpoints, player elimination | not there, **and not needed** |

`atlas-party.x` ships and is semi-honest; there is no malicious ATLAS.

### The king is where "consistent but wrong" lives, and it can be removed

ATLAS's king interpolates from `2t+1` shares and then **re-shares**. A lying king
re-shares a perfectly consistent sharing of the wrong value, and no amount of
error correction on a codeword catches a codeword that is correct.

It does not have to be there. `r` is a **fresh** degree-`2t` random, so the
masked product is not secret and can go to everybody. Every party then decodes
the whole codeword itself and computes `[xy]_t = e - [r]_t` locally, with `e`
public. Nobody's word is taken; there is no re-sharing step; there is nothing to
segment and nobody to eliminate.

`patches/robust-atlas.patch`, `--options robust`.

### What it does, measured

host-a, `n = 9`, `T = 2`, 128-bit, 2000 multiplications, with
`QOMM_CORRUPT_PLAYER` making the named parties send a wrong share of **every**
masked product (`artifacts/robust_atlas.json`):

| corrupted | answer | named | |
|---|---|---|---|
| none | correct | --- | 8 rounds |
| `{0}` | **correct** | `[0]` | **did not stop** |
| `{0,1}` | **correct** | `[0,1]` | **did not stop** |
| `{8}` | **correct** | `[8]` | **did not stop** |
| `{0,1,2}` | --- | --- | refuses: beyond the capacity of a degree-4 sharing over 9 points |
| `n = 7` | --- | --- | refuses to start: corrects only 1 against a threshold of 2 |

**The four middle lines are rung 5.** The protocol did not stop and the answer
was right.

### And it is cheaper than what is deployed

| | elements/party/mult | rounds |
|---|---:|---|
| ATLAS with a king, `n=9` | 5.333 | 9 -> 13 |
| **this, `n=9`** | **18.222** | **8 -> 12** |
| malicious Shamir + naming, `n=7` | 64.236 | 11 -> 23 |

**0.28x per party and 0.37x globally against the engine actually deployed, with
fewer rounds, and it does not stop.** Dropping the king removes a round: it was
to the king and back, and it is now one all-to-all.

### What is *not* robust, named honestly

Only the degree-reduction step. The **double sharings** come from
`Shamir<T>::get_randoms`, which is hyper-invertible matrices with no malicious
check in this build --- a corrupt contributor can make `[r]_t` and `[r]_2t`
inconsistent with each other, and no decode on either alone sees it. The
**output opening** is `IndirectShamirMC`, unchanged. The **inputs** are whatever
the caller shared.

The first of those is preprocessing, **and preprocessing is allowed to abort**:
it consumes no inputs, so a failed run leaks nothing and denies nobody an
outcome. It is re-run, and a node that keeps failing it is removed between
auctions, which is governance rather than protocol. Guaranteed output delivery
is only needed once real inputs are in.

The third is already closed in QOMM and not in this benchmark: the dealer
publishes a Pedersen commitment per share, so a node handed a bad share proves
it to anybody by the commitment not opening --- the complaint protocol a robust
input phase normally needs is paid for by publicly auditable MPC.

### The prediction was 1.6x low

`artifacts/robust_by_decoding_prediction.json`, written before any of this ran,
modelled the swap as "remove the king's 2 elements, add the all-to-all's `n-1`"
and got 11.3. Measured 18.222; the swap costs 12.889 rather than 6. The model
counted global traffic on the sending side only and **the discrepancy has not
been isolated**, so it is a bad model rather than a finding about the protocol.

What did land: the round count (8 against the king's 9), the behaviour under one
and two liars, the refusal past capacity, and the refusal to start below
`n >= 4t+1`.

### What it costs that is not bandwidth

**Two more institutions.** `POSITION.md`'s own risk register says the binding
constraint is assembling the consortium at all, so `n = 9` raises the risk that
matters most. Keeping `n = 7` and dropping to `T = 1` also satisfies `n >= 4T+1`
and costs nothing on the wire --- and drops the privacy threshold to 1, so any
two colluding nodes reconstruct every order in the book. Not available to a
venue.


---

## 4. Accountability is a different question and does not have a free answer

Not stopping and naming the party that tried to stop you are separate
properties, and the second one is not delivered by the first.

**GSZ identifies, but towards the wrong audience.** Its dispute control names
either a corrupted party or a *disputed pair* --- the mechanism is that the king
accuses, the relay states its opinion, and the parties broadcast the value under
dispute --- and the circuit is cut into segments so a failure discards one
segment rather than the run. That is why the worst case is 7.5 rather than 5.5.
**But it is identification towards the other parties.** An outside auditor
reading the transcript is not the party being convinced, and rung 4 needs a
judge.

**Rivinius et al. do deliver rung 4 and 5 together, and their number is the one
to respect**: publicly verifiable *plus* accountable *plus* robust costs **11x to
20x the online phase** against plain SPDZ, at `n = 3`, `t = 2`. That is in a
dishonest-majority SPDZ-like protocol with lattice commitments on every share,
which is a much harder starting point than an honest majority --- but it is the
only measured price for the full package in the literature, and nothing here
should imply it is cheap.

**Wang et al. (2025) get complete identifiability plus robustness in the
dishonest majority setting** --- and buy the robustness with a **semi-honest
trusted third party**. That is the same weakening Prime Match makes with its
bank, and it is not available to a venue whose premise is that no party can be
trusted with the order flow.

### What accountability would take here, in order of difficulty

**Rung 4 at the dealing boundary is already there** and costs nothing more.

**Rung 4 inside the MPC is the hard one, and it is the same gap as
`BINDING.md`.** A judge can only convict on what is on the bulletin board. Today
the bulletin board carries the dealt shares and their signatures; it does not
carry what each node fed the engine. Closing that is what section 3 of
`BINDING.md` prices at one extra round --- and the input check gives *detection*,
not a verdict: it says the combination does not match, not which node broke it.
**Turning detection into a verdict means one check per node rather than one for
all of them**, which is `n` times the openings, and nothing in this repository
has measured that.

**Rung 5 is available and unimplemented**, at negative cost, per section 3.

---

## 4.5 The prediction, and the way it split

The pre-run expectation and the measured Rust result were:

| predicted | measured | |
|---|---|---|
| MP-SPDZ malicious Shamir spends 2 to 8 elements per party, most likely about 4 | **8.000 online**, **48.231 single-phase** | see below |
| GSZ over that baseline: 0.7x to 2.8x, most likely 1.4x | **0.69x against online**, **0.11x against the total** | see below |
| rounds flat in the batch size | flat at 3 (after the loop was fixed) | landed |

**Both rows landed against the online figure and missed against the total, and
the prediction did not say which one it meant.** Eight is the top of the
predicted range; 0.69 is one hundredth below its floor. Against the single-phase
number the same prediction is out by six times and by a factor of six the other
way.

So this is not a modelling error. **It is a prediction that named a quantity
without naming its phase** --- and the phase is the thing that has now bitten
this project three times: once with edaBits, where preprocessing measured in a
single-phase harness came out two orders of magnitude wrong; once with the
`-P`/`-F` compile flag; and now here, where the arithmetic was right and the
sentence was ambiguous.

**The conclusion is stronger than the prediction either way.** Robustness was
predicted to cost about 1.4x. It saves between 1.4x and 6.4x depending on which
phase it is compared against, and on both readings it is not a cost.

---

## 4.6 What if there were no honest majority at all?

The rungs above take the corruption model as given. The other move is to change
it: drop the assumption that five of seven nodes are honest and use a protocol
that survives `n-1` corruptions instead. That is **strictly stronger** --- at
`n = 7` it withstands six colluding nodes where this design breaks at three ---
so the only question is the price.

Measured with the same slope harness, `host-a`, 128-bit field
(`artifacts/dishonest_majority.json`). The harness cross-checks: 48.235 elements
per party at the quote circuit's 3,312 multiplications predicts **17.9 MB**
global, against **19.37 MB** measured end to end in `matched_field.json`, the
difference being the input sharing and the 70 openings.

| | elements per party per multiplication |
|---|---:|
| Shamir malicious, `n=7 T=2`, **online only** | 8.000 |
| **MASCOT, `n=7`, online only** | **3.429** |
| Shamir malicious, `n=7 T=2`, **total** | 48.235 |
| semi-honest dishonest majority, `n=7`, total | 3,849 |
| **MASCOT, `n=7`, total** | **26,894** |
| MASCOT, `n=3`, total | 8,969 |
| MASCOT, `n=2`, total | 4,487 |

**The answer splits in two and the halves point opposite ways.**

**Online, dishonest majority is 2.3x cheaper.** MASCOT spends 3.429 elements per
party against Shamir's 8.000. The reason is structural rather than incidental:
reconstructing a Shamir sharing collects `2t+1 = 5` shares, while opening an
additive sharing is one round trip through a designated party whatever `n` is.
**The honest majority's entire advantage is in preprocessing, and at seven
parties its online phase is the worse of the two.**

**In total, dishonest majority is 558x more expensive**, because triples stop
coming from information-theoretic tricks and start needing pairwise oblivious
transfer. The scaling is exactly linear in the number of partners --- `4,486.6 x
(n-1)` per party, which reproduces at `n = 2, 3, 7` to three digits --- so the
global cost is quadratic in `n`, which is why nobody runs seven.

**And giving up malicious security does not recover it.** Semi-honest dishonest
majority is still 3,849 elements per party, 80x honest-majority Shamir. **The
cost is the corruption model, not the adversary model.**

### The number a deployment would actually care about

Preprocessing is input-independent, so an RFQ venue can make triples between
quotes. That turns the comparison from latency into a throughput ceiling. Per
quote at `M = 16` (3,312 multiplications), fully pipelined, with a dedicated
gigabit link per party:

| | per party, per quote | ceiling |
|---|---:|---:|
| Shamir `n=7`, total | 2.56 MB | **one quote per 0.02 s** |
| MASCOT `n=2`, total | 238 MB | one quote per 1.9 s |
| MASCOT `n=7`, total | 1.43 GB | one quote per 11.4 s |

**This design is nowhere near its bandwidth ceiling**, which is why
`DEPLOYMENT.md` finds it limited by round trips --- 3.6 s at 15 ms and 23.0 s
intercontinental. A dishonest-majority venue would be limited by bandwidth
instead, and at seven parties by a wide margin.

### The two things this actually costs, which are not bandwidth

**Robustness stops being expensive and becomes impossible.** One corrupt party
of `n` can always stall, so guaranteed output delivery is unavailable at any
price. Everything in section 3 --- the finding that robustness here is a saving
--- would be closed off permanently.

**And nobody would deploy seven.** The point of a dishonest-majority protocol is
that one honest party of two suffices, so the honest comparison is not
seven-party Shamir against seven-party MASCOT; it is **seven-party Shamir against
two-party MASCOT**, which is roughly Prime Match's shape. That is a governance
decision rather than a performance one: seven KYB'd entities across
jurisdictions is a consortium, two operators is a venue, and DeFMI's regional
node structure is built on the first.

Even so, two-party MASCOT moves **475 MB of global traffic per quote against
17.9 MB** --- 27x, with two nodes instead of seven.

### The prediction, and how it split

| predicted | measured | |
|---|---|---|
| MASCOT online at `n=7`: 12 to 20 elements per party | **3.429** | **wrong, and in the opposite direction** |
| MASCOT total at `n=7`: 30x to 300x, likely 100x | **558x** | wrong, 1.9x above the range |
| semi-honest dishonest majority still well above Shamir | 80x | landed |

**The online miss is the instructive one.** The arithmetic said "an opening
means every party sends to every other, so `2(n-1) = 12` elements". That is what
*Shamir* does here, not what SPDZ does --- SPDZ opens through a designated party
and pays `O(1)` per party regardless of `n`. **The mistake was assuming the
protocol we run is the efficient one on the axis being compared.** It is the
same shape as the earlier finding that MP-SPDZ's malicious Shamir is 6x off the
state of the art for its own regime.

---

## 4.7 The taker is a party too, and probing is its version of misbehaving

Everything above is about a node. A **taker** misbehaves differently: it submits
requests it never intends to trade on and reads the price envelope for free.
`is_real` cover traffic hides which slots are real *from the maker*; it does
nothing about the party doing the asking.

**The fix is not cryptographic, it is a market rule made enforceable by
cryptography.** The taker commits an acceptance level `L` with the request. The
circuit computes the winner as before, then one comparison, and returns
`fill * key` under the trader's mask. **A quote at or inside the level is a
trade, not an offer.**

`gen_qomm --binding-limit`. Measured on `host-a`, `M = 16`, seven parties:

| | rounds | global | what the taker gets |
|---|---:|---:|---|
| plain | 70 | 41.5443 MB | the quote, always |
| binding, level above the quote | 79 | 42.2438 MB | `(99990, 5)` --- filled |
| binding, level below the quote | 79 | 42.2438 MB | **`(0, 0)`** |

That last row is the whole design and it is measured rather than argued: on a
no-fill the taker removes its own mask and gets **zero**. It learns the fill bit
and nothing else.

**The fill bit is masked too**, and that is not fussiness. Revealing it in the
clear would say which slots traded --- which is precisely what the cover traffic
exists to hide, since a public fill bit marks every cover slot as cover.

### What this buys, stated honestly

**It does not stop probing.** A prober can raise `L` from below and learn *worse
than this* each time for free, converging on the quote from underneath. What
costs a trade is learning the market is **better** than a stated level, because
that is a fill.

**And that is exactly what a resting limit order already reveals.** Posting at
`L` in a public book says *I will trade at L*, and not being filled says the
market is worse. So a binding-limit RFQ leaks **no more than a central limit
order book**, and less, because `L` is committed rather than displayed ---
against a baseline the removed baseline runner already measures.

**Bisection costs fills.** Binary search terminates on the first `q <= L`, which
*is* a fill; against a uniform quote the first midpoint probe fills with
probability 1/2. Only the linear crawl from below stays free, and it needs
`range/step` requests, which a venue can rate-limit or charge for.

### The cost, the prediction it broke, and the fix

Predicted +2 to +8 rounds and under 0.5% traffic. **Measured +9 rounds and
+1.68%** --- one round outside on the first and 3.4x outside on the second.

One cause for both: **the tournament's comparisons run sixteen wide per layer
and amortise, and the fill comparison was a single standalone one paying full
depth.** The estimate priced it as though it joined the batch.

So it was made to join the batch. `min(a, b) <= L` is decided by `a <= L` and
`b <= L`, and both operands exist *before* the last tournament level runs. The
last level now compares three pairs in one layer where it compared one ---
`(a,b)`, `(a,L)`, `(b,L)` --- and selects twice in one layer where it selected
once:

    best = (a<=b).if_else(a, b)
    fill = (a<=b).if_else(a<=L, b<=L)

Both selects read only the three comparison bits, so they share a layer, and
the comparison the fill needed is now inside a layer that was going to run
anyway. `gen_qomm` emits this as `argmin_fill`; the k-ary tournament gets the
same treatment through a split-out level function.

Measured on `host-c`, same configuration for all three arms, three repeats:

| arm | rounds | global | traffic |
|---|---:|---:|---:|
| plain | 70 | 32.5137 MB | --- |
| binding, standalone comparison | 79 (+9) | 33.0596 MB | +1.68% |
| binding, folded into the last layer | **72 (+2)** | 33.6037 MB | +3.35% |

The standalone arm reproduces the host-a table above exactly --- +9 rounds and
+1.68% --- which is the reason to believe the arm beside it. **Seven of the
nine rounds come back.**

The prediction written before the change said +1 or +2 rounds and traffic
roughly unchanged. The rounds landed at the top of that; **the traffic did
not**. It doubled, +1.68% to +3.35%, and the arithmetic says why: the standalone
arm ran two comparisons in total, the folded arm runs three, and each 63-bit
comparison at `M = 16` over seven parties costs about 0.545 MB globally ---
0.546 measured for the first, 0.544 for the second. Depth was bought with
width, which is this project's recurring trade rather than a surprise in it.

The unfillable arm returns `(0, 0)` after the fold as it did before, so the
seven rounds were not bought by changing what the taker learns.
`artifacts/fill_fold.json`.

### What is not resolved

**Binding needs a settlement the taker cannot decline, and the quorum cannot see
the bit it would be settling on.** The shape is that the quorum signs an
instruction carrying a *commitment* to `fill`, and DeFMI requires a proof that
`fill = 1` before it moves anything. Who can produce that proof, and what stops a
taker sitting on it, is not answered here. Escrowed collateral is necessary and
probably not sufficient.

**And it costs an honest taker something real**: giving up the right to decline
after seeing the price is giving up *last look* --- which is what makes probing
possible, and what the FX Global Code spent years constraining. Aligned with
where the regulation went, and still a cost: a binding level is exposed to being
filled on a stale quote, which is what the 26-second staleness measurement is
about.

---

## 5. What this changes about the position

`POSITION.md` says "no accountability and no robustness" and lists both as gaps
of the same kind. They are not.

**Robustness is no longer a gap. It is built and it is cheaper than what it
replaces.** §3.7: at `n = 9` the degree-reduction step corrects up to two wrong
shares, names their senders, and does not stop --- 0.28x per party against the
deployed engine, with fewer rounds. What is still not robust is the
preprocessing, which is allowed to abort because it consumes no inputs.

**Accountability stays a gap, and a real one.** The only measured price for the
full package is 11x to 20x, in a harder regime, and the honest-majority version
has not been measured by anybody --- including here.

---

## 6. What is not settled

- **GSZ is not implemented here and has not been run.** The 5.5 to 7.5 figure is
  theirs, not ours. What is ours is the 8.0 and 48.2 it is being compared to ---
  and §3.7 reaches rung 5 without it, by moving to `n >= 4T+1` where a decoder
  suffices, at a cost GSZ's asymptotics would beat.
- **Rung 5 here is the multiplication, not the whole protocol.** The double
  sharings, the output opening and the input phase are unchanged; §3.7 says
  which of those matter and why the preprocessing one does not.
- **The honest-majority price of rung 4 is unknown.** Rivinius et al. measured
  the dishonest-majority price; the analogous number for `t < n/3` Shamir does
  not appear to exist and is not derived here.
- **The bulletin board is assumed, not built.** Both public auditability and the
  broadcast channel that rung 5 wants at `t < n/2` need one, and this repository
  has a delay proxy on a single machine rather than seven sites with a shared
  append-only log.
- **Nothing here addresses input-party misbehaviour.** A maker that commits to a
  policy and then disputes it is a contract problem, not a protocol one, and the
  only work that treats corrupt input parties seriously is Baldimtsi et al. ---
  at the cost of exact correctness. `POSITION.md` section 3 has why that trade
  does not apply here.
