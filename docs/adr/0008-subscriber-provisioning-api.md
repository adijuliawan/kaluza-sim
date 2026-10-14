# ADR 0008: subscriber provisioning through the UDR's API, with kaluza-sim's own client

- **Status:** accepted, 2026-10-14 (user, on kaluza-core's recommendation)
- **Context:**
  - The first design had `ksim-sim` write a seed fragment for a kaluza-core session to import ([`../sim-uicc.md`](../sim-uicc.md) §8).
  - kaluza-core then described both routes (2026-10-14):
    - **The seed** is a create-only bootstrap, read when the UDR starts. Every import needs an `apply.sh` roll, and it cannot remove a subscriber.
    - **The provisioning API** has a `PUT`/`DELETE` per subscriber at `…/provisioning/v1/subscribers/imsi-<IMSI>`, on the UDR's listener `:7779`. There is one UDR per PLMN: namespace `kaluza` for 001/01, `kaluza-h99970` for 999/70.
      - No pod restarts.
      - The UDR seals K/OPc to the UDM itself.
      - Its NetworkPolicy admits only the OAM and the node, so calls run from the dev PC.
  - **The step-up gate.** Writing keys through the API needs the `acr` `key-entry` with an `auth_time` within 300 s (KeyEntryStepUp, which fails closed).
    - The only exemption is by client name, in `kaluza.udr.provisioning.key-entry.exempt-clients`.
    - kaluza-core's `deploy/check` pins that list to the gate's service account.
  - **The options:**
    1. A seed fragment imported by a kaluza-core session.
    2. The API under the gate's service account.
    3. The API under kaluza-sim's own Keycloak client, added to the exemption.
- **Decision:** option 3.
  - **Setup.** kaluza-core creates the client, adds it to the exemption and to the `deploy/check` pin, and names it, all **before P1**. The credential arrives as a 0600 file on the dev PC and is never printed or deployed to the VM.
  - **Use.** `ksim-sim range provision` and `range deprovision` call the API from the dev PC. They send one SubscriberBundle per subscriber, built in memory from the derived keys and the profile YAML.
  - **Scope.** The client is used for kaluza-sim's IMSI ranges only, and `ksim-sim` refuses any other IMSI.
  - **Fallback.** The seed fragment stays as a fallback, only for when the API is unavailable.
  - **SUCI (the same day).** The sim cards use the **null SUCI scheme** until P1 reaches its SUCI rows. The user then picks the Profile A/B key ids.
- **Why not the gate's service account:** a separate identity keeps the UDR's audit trail able to tell the sim's writes from the gates' writes. It can be revoked without touching the gates, and the gate's credential is not copied into another tool.
- **Consequences:**
  - **A narrow exception to "read-only on kaluza-core".** kaluza-sim writes subscriber data into the live UDR, but only for its own ranges and only through the public API. No kaluza-core file or cluster object is touched. Tell the core session before a first import or a bulk delete.
  - **Keys cross the wire in clear,** inside the API's mTLS. A bundle must not carry `protectionParameterId`: beside key values, the UDR refuses it with PROTECTED_KEY_UNSUPPORTED. Bodies are never logged or written to disk, and the tool prints only the ueId, the HTTP status and `K_FPR`. The secret canary covers `ksim-sim`'s output too.
  - **Independence holds** ([ADR 0005](0005-independence-from-kaluza-core.md)). The core stores what the sim derives, and nothing the core computes becomes an expected value. The bundles are built from the TS 29.505 and TS 29.519 types, not from kaluza-core's code or seeds.
  - **P1 has a kaluza-core prerequisite** (the client and its exemption), alongside the V-UPF neighbour entries ([`../lab.md`](../lab.md) §4, §8).
  - **Real cards outside the sim ranges** keep the core's rule that K/OPc are typed by a person.
