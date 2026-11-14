# SecureScan AI — Primary Legal Sources & Commencement Registry

> [!IMPORTANT]
> **LEGAL REVIEW PENDING**  
> The legal references, statutory provisions, and commencement timelines catalogued below were extracted and verified against official Gazette notifications as of **2026-11-14**.  
> SecureScan AI is a developer-assistance diagnostic tool and does **not** provide legal advice, compliance certification, or formal legal opinions. A qualified legal professional licensed in India must review this catalogue prior to commercial production deployment.

---

## 1. Statutory Foundations & Primary Gazette Notifications

| # | Document / Gazette ID | Title & Authority | Notification Date | Verification Date (`reviewed_at`) | Operational Status |
|---|---|---|---|---|---|
| **1** | **Act No. 22 of 2023** | **Digital Personal Data Protection Act, 2023**<br>Ministry of Law and Justice (Legislative Dept) | 11 August 2023 | 2026-11-14 | Primary Act; phased commencement under §1(2) |
| **2** | **G.S.R. 843(E)** | **Commencement Notification under Section 1(2)**<br>Ministry of Electronics and Information Technology (MeitY) | 13 November 2025 | 2026-11-14 | Phase 1 & 2 operational; Phase 3 scheduled for 13 May 2027 |
| **3** | **G.S.R. 846(E)** | **Digital Personal Data Protection Rules, 2025**<br>Ministry of Electronics and Information Technology (MeitY) | 13 November 2025 | 2026-11-14 | Rules 1, 2, 17–21 active; Rule 4 active since 13 Nov 2026; remaining rules upcoming |
| **4** | **Schedule to Act** | **Penalties Schedule (Section 33(1))**<br>Items 1 through 7 | 11 August 2023 | 2026-11-14 | Statutory upper limits (ceilings) only |

---

## 2. Dynamic Phased Commencement Matrix

Under Section 1(2) of the Act and Rule 1 of the 2025 Rules, provisions commence on three distinct milestones. SecureScan AI computes status dynamically relative to the audit's `as_of_date` (never hard-coded).

```
Phase 1 (13 Nov 2025)       Phase 2 (13 Nov 2026)             Phase 3 (13 May 2027)
[IN FORCE]                  [IN FORCE]                        [UPCOMING]
• Board establishment       • Section 6(9): Consent Managers  • Sections 3–5, 6(1)-(8)
• Adjudication machinery    • Section 27(1)(d): CM powers     • Section 7 (Legitimate uses)
• Inquiries & appeals       • Rule 4: Consent Manager duties  • Section 8 (Safeguards/Breach)
• Penalties framework                                         • Sections 9–17 (Children, SDF, Rights)
• Rules 1, 2, 17–21                                           • Rules 3, 5–16, 22, 23
```

### Dynamic Commencement Evaluation Rule
- If `as_of_date < 2025-11-13`: `NOT_YET_IN_FORCE`
- If `2025-11-13 <= as_of_date < 2026-11-13`: Phase 1 `IN_FORCE`, others `NOT_YET_IN_FORCE`
- If `2026-11-13 <= as_of_date < 2027-05-13`: Phase 1 & 2 `IN_FORCE`, Phase 3 `UPCOMING`
- If `as_of_date >= 2027-05-13`: All provisions `IN_FORCE`

---

## 3. Statutory Penalty Catalogue (Schedule to Section 33)

SecureScan AI adheres strictly to non-speculative reporting:
1. **Ceilings Only**: Reports display statutory upper bounds (e.g., *"Up to ₹250 crore"*).
2. **Mandatory Caveat**: Every penalty entry carries the statutory caveat:  
   *"Potential legal category; applicability and liability not determined."*
3. **No Predicted Fines**: The engine strictly forbids estimating, calculating, or predicting fines.
4. **No Summed Fines**: Penalty ceilings must never be added together across rows.

| Item | Statutory Provision | Breach Description | Statutory Ceiling (INR) | SecureScan Control Linkage |
|:---:|---|---|---|---|
| **1** | Section 8(5) | Breach in observing reasonable security safeguards to prevent personal data breach | Up to ₹250 crore | `DPDP-006`, `DPDP-018` |
| **2** | Section 8(6) | Failure to notify Board and affected Data Principals of a personal data breach | Up to ₹200 crore | `DPDP-008` |
| **3** | Section 9 | Non-fulfillment of obligations in relation to children (or persons with disability) | Up to ₹200 crore | `DPDP-009` |
| **4** | Section 10 | Non-fulfillment of additional obligations of Significant Data Fiduciary | Up to ₹150 crore | `DPDP-010`, `DPDP-014`, `DPDP-017` |
| **5** | Section 15 | Non-fulfillment of duties by Data Principal | Up to ₹10,000 | `DPDP-013` (informational) |
| **6** | Section 32 | Breach of any term of voluntary undertaking accepted by the Board | Up to underlying breach amount | `DPDP-016` |
| **7** | Other provisions | Breach of any other provision of Act or Rules | Up to ₹50 crore | `DPDP-001`..`005`, `007`, `011`, `012`, `015` |

---

## 4. Maintenance and Update Protocol

1. **Quarterly Gazette Review**: Check the Gazette of India (`egazette.gov.in`) and MeitY circulars for amendments or additional commencement notifications.
2. **Policy Bundle Update**: Update `policies/dpdp_controls.yaml` and `policies/penalty_schedule.yaml` with any new gazette IDs or revised dates.
3. **Automated Schema Verification**: Run `python scripts/ci.py` to ensure all controls maintain primary citation completeness (enforced by `test_at14_citation_completeness_on_all_dpdp_controls`).

