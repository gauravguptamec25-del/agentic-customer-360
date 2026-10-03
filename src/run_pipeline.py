import json
import os
import re
import math
import heapq
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict

# =====================================================================
# 1. ALLOWED EVALUATION ENUMS
# =====================================================================
ALLOWED_INFERRED_STATES = {
    "no_significant_event", "new_child_life_event", "marriage_or_relationship_change",
    "job_change_or_promotion", "job_loss_or_income_disruption", "medical_hardship",
    "financial_distress_general", "relocation", "retirement_transition",
    "wealth_growth_or_windfall", "potential_fraud_or_takeover",
    "elder_vulnerability_or_scam_risk", "churn_risk", "small_business_cashflow_event"
}

ALLOWED_ACTIONS = {
    "no_action", "proactive_retention_outreach", "relationship_manager_escalation",
    "personalized_offer", "support_intervention", "compliance_fraud_hold"
}

ALLOWED_HITL_STATUSES = {
    "auto_approved", "escalated", "human_approved", "human_rejected", "human_modified"
}

ALLOWED_CONFIDENCE_BANDS = {"low", "medium", "high"}


# =====================================================================
# 2. DETERMINISTIC GUARDRAILS & PII FILTER
# =====================================================================
class GuardrailEngine:
    HARD_STOPS = [
        re.compile(r"\b(lawsuit|attorney|legal action|court|subpoena|regulatory complaint)\b", re.IGNORECASE),
        re.compile(r"\b(fraud|unauthorized transaction|hacked|account takeover)\b", re.IGNORECASE)
    ]
    CARD_REGEX = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    ACCOUNT_REGEX = re.compile(r"\bACC_[A-Z0-9_]+\b")

    @classmethod
    def redact_pii(cls, text: str) -> str:
        if not text:
            return ""
        text = cls.CARD_REGEX.sub("[CARD_REDACTED]", text)
        return cls.ACCOUNT_REGEX.sub("[ACC_REDACTED]", text)

    @classmethod
    def check_hard_stop(cls, text: str) -> Optional[str]:
        if not text:
            return None
        for pattern in cls.HARD_STOPS:
            match = pattern.search(text)
            if match:
                return f"HARD_STOP: {match.group(0)}"
        return None


# =====================================================================
# 3. EXPONENTIAL DECAYING MEMORY & TELEMETRY BOARD
# =====================================================================
class CustomerStateBoard:
    def __init__(self, half_life_days: float = 30.0):
        self.board = {}
        self.decay_lambda = math.log(2) / (half_life_days * 86400.0)

    def init_customer(self, customer_id: str, profile_data: dict):
        self.board[customer_id] = {
            "profile": profile_data.get("profile", {}),
            "accounts": profile_data.get("accounts", []),
            "baselines": profile_data.get("baselines", {}),
            "live_metrics": {
                "last_event_time": None,
                "latest_spend_anomaly_zscore": 0.0,
                "login_timestamps": [],          # Store actual login datetimes
                "card_spend_timestamps": [],     # Store transaction frequencies
                "initial_balance": None,
                "peak_balance": 0.0,
                "current_balance": 0.0,
                "hard_stop_flag": None
            },
            "decaying_signals": {},
            "recent_events_window": [],
            "inferred_state": "no_significant_event"
        }

    def record_signal(self, cid: str, signal_name: str, weight: float, event_time_str: str):
        if cid in self.board:
            try:
                t = datetime.fromisoformat(event_time_str.replace("Z", "+00:00")).timestamp()
                self.board[cid]["decaying_signals"][signal_name] = (weight, t)
            except Exception:
                pass

    def get_state(self, cid: str) -> dict:
        return self.board.get(cid, {})


# =====================================================================
# 4. STREAM INGESTION & MATHEMATICAL TELEMETRY
# =====================================================================
class StreamingReplayBuffer:
    def __init__(self, state_board: CustomerStateBoard, watermark_seconds: int = 60):
        self.state_board = state_board
        self.watermark = timedelta(seconds=watermark_seconds)
        self.buffer = []
        self.seq = 0

    def push(self, event: dict):
        try:
            dt = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
            heapq.heappush(self.buffer, (dt, self.seq, event))
            self.seq += 1
        except Exception:
            pass

    def flush_until(self, current_dt: datetime, flush_all: bool = False):
        while self.buffer:
            evt_dt, _, event = self.buffer[0]
            if not flush_all and (current_dt - evt_dt < self.watermark):
                break
            heapq.heappop(self.buffer)
            self._apply_event_transforms(event)

    def _apply_event_transforms(self, event: dict):
        cid = event.get("customer_id")
        source = event.get("source_system")
        etype = event.get("event_type", "")
        payload = event.get("payload", {})
        cust = self.state_board.board.get(cid)
        if not cust:
            return

        baselines = cust.get("baselines", {})
        metrics = cust["live_metrics"]
        metrics["last_event_time"] = event.get("event_time")

        # 1. Deterministic Guardrail Check
        raw_text = payload.get("raw_text") or payload.get("search_text") or ""
        if raw_text:
            hard_stop = GuardrailEngine.check_hard_stop(raw_text)
            if hard_stop:
                metrics["hard_stop_flag"] = hard_stop
            payload["raw_text"] = GuardrailEngine.redact_pii(raw_text)

        # 2. Dynamic Login Telemetry Tracking (Web / Mobile App)
        if source == "web_app_events" and etype == "login":
            try:
                e_dt = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
                metrics["login_timestamps"].append(e_dt)
                cutoff = e_dt - timedelta(days=90)
                metrics["login_timestamps"] = [t for t in metrics["login_timestamps"] if t >= cutoff]
            except Exception:
                pass

        # 3. Card Transactions: Frequency Telemetry & Spend Anomaly
        if source == "card_payments":
            try:
                e_dt = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
                metrics["card_spend_timestamps"].append(e_dt)
                cutoff = e_dt - timedelta(days=90)
                metrics["card_spend_timestamps"] = [t for t in metrics["card_spend_timestamps"] if t >= cutoff]
            except Exception:
                pass

            if "amount" in payload:
                mcc = payload.get("mcc_category", "general")
                try:
                    amt = float(payload["amount"])
                    stat = baselines.get("spend_by_mcc", {}).get(mcc)
                    if stat and stat["std_dev"] > 0:
                        z = (amt - stat["mean"]) / stat["std_dev"]
                        metrics["latest_spend_anomaly_zscore"] = round(z, 2)
                        if z >= 2.5:
                            self.state_board.record_signal(cid, f"spike_{mcc}", 1.0, event["event_time"])
                except (ValueError, TypeError):
                    pass

        # 4. Rolling Ledger Balance, Peak & Drain Tracking
        if "balance_after" in payload:
            try:
                bal = float(payload["balance_after"])
                metrics["rolling_balance"] = bal
                metrics["current_balance"] = bal
                if metrics.get("initial_balance") is None:
                    metrics["initial_balance"] = bal
                metrics["peak_balance"] = max(metrics.get("peak_balance", 0.0), bal)
            except (ValueError, TypeError):
                pass

        cust["recent_events_window"].append(event)
        if len(cust["recent_events_window"]) > 250:
            cust["recent_events_window"].pop(0)

# =====================================================================
# 5. GENERALIZED MULTI-AGENT INFERENCE ENGINE (COMPLETE HYPOTHESES)
# =====================================================================
# 5. GENERALIZED MULTI-AGENT INFERENCE ENGINE (COMPLETE HYPOTHESES & TELEMETRY)
# =====================================================================
class MASInferenceEngine:
    HEALTH_MCCS = {"medical", "hospital", "pharmacy", "health", "doctor", "clinic", "dental"}
    FAMILY_MCCS = {"baby", "toddler", "nursery", "childcare", "daycare", "maternity"}
    EDUCATION_MCCS = {"education", "tuition", "school", "university", "college"}
    TRAVEL_MCCS = {"travel", "lodging", "resort", "hotel", "airline", "cruise"}
    FRAUD_RISK_MCCS = {"crypto", "gambling", "wire_transfer", "money_order", "pawn"}

    @classmethod
    def evaluate_checkpoint(cls, state: dict, as_of_time: str) -> dict:
        events = state.get("recent_events_window", [])
        metrics = state.get("live_metrics", {})
        profile = state.get("profile", {})
        baselines = state.get("baselines", {})
        tier = profile.get("customer_value_tier", "mid").lower()
        cp_dt = datetime.fromisoformat(as_of_time.replace("Z", "+00:00"))

        if metrics.get("hard_stop_flag"):
            return {
                "as_of_time": as_of_time,
                "inferred_state": "potential_fraud_or_takeover",
                "confidence_band": "high",
                "action": "compliance_fraud_hold",
                "action_subtype": "immediate_account_security_freeze",
                "hitl_status": "escalated",
                "notes": f"Deterministic Guardrail Triggered: {metrics['hard_stop_flag']}"
            }

        hypotheses = {
            "medical_hardship": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "new_child_life_event": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "job_loss_or_income_disruption": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "job_change_or_promotion": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "relocation": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "retirement_transition": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "wealth_growth_or_windfall": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "financial_distress_general": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "potential_fraud_or_takeover": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "elder_vulnerability_or_scam_risk": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "churn_risk": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "marriage_or_relationship_change": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0},
            "small_business_cashflow_event": {"domains": set(), "first_seen": None, "last_seen": None, "has_direct_anchor": False, "event_count": 0}
        }

        def record(hyp_key: str, domain: str, evt_time: datetime, is_anchor: bool = False):
            if hyp_key in hypotheses:
                h = hypotheses[hyp_key]
                h["domains"].add(domain)
                h["event_count"] += 1
                if not h["first_seen"] or evt_time < h["first_seen"]:
                    h["first_seen"] = evt_time
                if not h["last_seen"] or evt_time > h["last_seen"]:
                    h["last_seen"] = evt_time
                if is_anchor:
                    h["has_direct_anchor"] = True

        mean_sal = baselines.get("mean_salary", 0.0)
        total_inbound_window = 0.0
        total_outbound_window = 0.0
        has_genuine_capital_infusion = False

        for e in events:
            try:
                evt_t = datetime.fromisoformat(e.get("event_time", "").replace("Z", "+00:00"))
                if evt_t > cp_dt:
                    continue
            except Exception:
                continue

            src = str(e.get("source_system", "")).lower()
            etype = str(e.get("event_type", "")).lower()
            p = e.get("payload", {})
            mcc = str(p.get("mcc_category", "")).lower()
            tx_type = str(p.get("transaction_type", "")).lower()
            subtype = str(p.get("event_subtype", "")).lower()
            status = str(p.get("status", "")).lower()
            desc = str(p.get("description", "")).lower()

            # Resilient full-text extractor: parses all possible text containers
            text_blobs = [
                str(p.get("raw_text") or ""),
                str(p.get("search_text") or ""),
                str(p.get("transcript") or ""),
                str(p.get("notes") or ""),
                str(p.get("resolution") or ""),
                str(p.get("subject") or ""),
                str(p.get("reason") or ""),
                desc,
                status
            ]
            full_text = " ".join(b for b in text_blobs if b).lower()

            try:
                amt = float(p.get("amount", 0.0) or 0.0)
            except (ValueError, TypeError):
                amt = 0.0

            mcc_stat = baselines.get("spend_by_mcc", {}).get(mcc, {})
            z_score = 0.0
            if mcc_stat and mcc_stat.get("std_dev", 0) > 0:
                z_score = (amt - mcc_stat["mean"]) / mcc_stat["std_dev"]

            # --- 1. KYC & MASTER DATA ---
            if "kyc" in src:
                if subtype == "dependents_change":
                    record("new_child_life_event", "kyc", evt_t, is_anchor=True)
                elif subtype == "address_change":
                    record("relocation", "kyc", evt_t, is_anchor=True)
                elif subtype == "employment_change":
                    record("job_change_or_promotion", "kyc", evt_t, is_anchor=True)
                elif subtype == "marital_status_change":
                    record("marriage_or_relationship_change", "kyc", evt_t, is_anchor=True)

            # --- 2. CARD PAYMENTS ---
            elif "card" in src:
                if any(k in mcc for k in cls.HEALTH_MCCS):
                    record("medical_hardship", "card_clinical", evt_t)
                elif any(k in mcc for k in cls.FAMILY_MCCS):
                    record("new_child_life_event", "card_family", evt_t)
                elif any(k in mcc for k in cls.FRAUD_RISK_MCCS):
                    record("potential_fraud_or_takeover", "card_highrisk", evt_t)
                elif p.get("is_international") and z_score >= 3.0:
                    record("potential_fraud_or_takeover", "card_anomalous_intl", evt_t)
                elif any(k in mcc for k in ["moving", "storage", "furniture"]):
                    record("relocation", "card_relocation", evt_t)

            # --- 3. LEDGER & PAYMENTS & STANDING INSTRUCTIONS ---
            elif any(k in src for k in ["ledger", "wire", "payment", "ach", "standing", "order"]):
                direction = p.get("direction", "outbound" if etype in ("withdrawal", "transfer_out") else "inbound")

                # Standing instruction cancellation / feature termination
                if any(w in etype or w in tx_type or w in desc or w in status for w in ["cancel", "delete", "stop", "terminate", "standing", "recurring"]):
                    if any(w in etype or w in tx_type or w in desc or w in status for w in ["cancel", "delete", "stop", "terminate", "disabled"]):
                        record("churn_risk", "standing_instruction_depletion", evt_t, is_anchor=True)

                if direction == "inbound" or etype == "deposit":
                    is_routine_salary = (mean_sal > 0 and abs(amt - mean_sal) <= 0.20 * mean_sal) or ("salary" in tx_type)
                    is_transient_refund = any(w in full_text for w in ["refund", "tax", "rebate"])

                    if not is_routine_salary and not is_transient_refund:
                        total_inbound_window += amt
                        if (mean_sal > 0 and amt >= 3.0 * mean_sal) or amt >= 20000.0:
                            has_genuine_capital_infusion = True

                    if "disability" in tx_type or "benefit" in tx_type:
                        record("medical_hardship", "ledger_disability", evt_t)
                    elif "pension" in tx_type or "social_security" in tx_type:
                        record("retirement_transition", "ledger_annuity", evt_t, is_anchor=True)

                elif direction == "outbound" or etype in ("withdrawal", "transfer_out"):
                    is_fixed_bill = any(k in tx_type or k in desc for k in ["mortgage", "rent", "utility", "insurance"])
                    if not is_fixed_bill:
                        total_outbound_window += amt

                    # Major capital drain or outbound sweep
                    if amt >= 4000.0 or z_score >= 2.0:
                        if any(w in full_text for w in ["external", "wire", "competitor", "brokerage", "sweep", "transfer", "chase", "fidelity", "vanguard", "citi"]):
                            record("churn_risk", "ledger_asset_drain", evt_t, is_anchor=True)

            # --- 4. CUSTOMER SUPPORT & INTERACTIONS ---
            elif any(k in src for k in ["support", "ticket", "crm", "interaction"]):
                # Denied fee / grievance catalyst
                if any(w in full_text for w in ["denied", "reject", "fee", "dispute", "unresolved", "dissatisfied", "complaint", "close account", "cancel", "unfair"]):
                    record("churn_risk", "support_grievance_catalyst", evt_t, is_anchor=True)
                elif any(w in full_text for w in ["hardship", "medical bill", "hospital bill", "payment plan"]):
                    record("medical_hardship", "support_distress", evt_t, is_anchor=True)
                elif any(w in full_text for w in ["education savings", "529 plan", "child insurance"]):
                    record("new_child_life_event", "support_inquiry", evt_t)
                elif any(w in full_text for w in ["unauthorized", "stolen card", "fraud", "hacked"]):
                    record("potential_fraud_or_takeover", "support_fraud_claim", evt_t, is_anchor=True)
                elif any(w in full_text for w in ["unemployment", "laid off", "job loss", "lost job"]):
                    record("job_loss_or_income_disruption", "support_unemployment", evt_t, is_anchor=True)
                elif any(w in full_text for w in ["retirement", "pension rollover", "401k"]):
                    record("retirement_transition", "support_retirement", evt_t, is_anchor=True)

        if has_genuine_capital_infusion and total_inbound_window > (total_outbound_window * 2.0):
            record("wealth_growth_or_windfall", "ledger_net_capital_injection", cp_dt)

        # =====================================================================
        # CONTINUOUS TELEMETRY & BEHAVIORAL CONTRACTION
        # =====================================================================
        login_ts = [t for t in metrics.get("login_timestamps", []) if t <= cp_dt]
        spend_ts = [t for t in metrics.get("card_spend_timestamps", []) if t <= cp_dt]
        peak_bal = metrics.get("peak_balance", 0.0)
        curr_bal = metrics.get("current_balance", 0.0)

        expected_monthly_logins = baselines.get("monthly_login_rate", 6.0)
        expected_monthly_spends = baselines.get("monthly_card_tx_rate", 10.0)

        recent_logins_30d = sum(1 for t in login_ts if 0 <= (cp_dt - t).days <= 30)
        recent_spends_30d = sum(1 for t in spend_ts if 0 <= (cp_dt - t).days <= 30)

        # 1. Login Velocity Contraction (>= 35% contraction flags early decay)
        if expected_monthly_logins >= 2.0:
            if recent_logins_30d <= (expected_monthly_logins * 0.65):
                record("churn_risk", "telemetry_login_contraction", cp_dt)

        # 2. Card Frequency Decay / Complete Cessation
        if expected_monthly_spends >= 3.0:
            if recent_spends_30d == 0 or recent_spends_30d <= (expected_monthly_spends * 0.50):
                record("churn_risk", "card_velocity_contraction", cp_dt)

        # 3. Capital Drainage (50%+ Drawdown or large negative delta)
        balance_drawdown = (peak_bal > 500.0) and (curr_bal <= peak_bal * 0.50)
        net_negative_outflow = (total_outbound_window >= 3000.0) and (total_outbound_window > total_inbound_window * 1.1)
        if balance_drawdown or net_negative_outflow:
            record("churn_risk", "ledger_capital_drainage", cp_dt)

        # =====================================================================
        # CONTINUOUS EVIDENCE ACCUMULATOR & DYNAMIC CONFIDENCE
        # =====================================================================
        eligible = []
        for s_name, h in hypotheses.items():
            d_count = len(h["domains"])
            if d_count == 0:
                continue

            elapsed_days = (cp_dt - h["first_seen"]).total_seconds() / 86400.0 if h["first_seen"] else 0.0
            recency_gap = (cp_dt - h["last_seen"]).total_seconds() / 86400.0 if h["last_seen"] else 999.0

            c_domain = min(1.0, d_count / 3.0)
            c_density = 1.0 - math.exp(-h["event_count"] / 2.0)
            c_persistence = min(1.0, elapsed_days / 14.0)
            c_anchor = 1.0 if h["has_direct_anchor"] else 0.0

            evidence_score = (
                0.40 * c_domain + 
                0.25 * c_density + 
                0.15 * c_persistence + 
                0.20 * c_anchor
            )

            # Statistical Multi-Corroboration:
            # If 2+ distinct behavioral systems corroborate an anchor, or 3 distinct domains confirm
            if (d_count >= 2 and h["has_direct_anchor"] and elapsed_days >= 5.0) or d_count >= 3:
                evidence_score = max(evidence_score, 0.72)

            if recency_gap > 45.0:
                evidence_score *= 0.50

            # Dynamic Band Assignment:
            if evidence_score >= 0.70:
                conf = "high"
            elif evidence_score >= 0.40:
                conf = "medium"
            else:
                conf = "low"

            eligible.append({
                "state": s_name,
                "confidence": conf,
                "score": evidence_score,
                "domain_count": d_count,
                "event_count": h["event_count"],
                "has_anchor": h["has_direct_anchor"],
                "elapsed_days": elapsed_days
            })

        if not eligible:
            return {
                "as_of_time": as_of_time,
                "inferred_state": "no_significant_event",
                "confidence_band": "high",
                "action": "no_action",
                "action_subtype": None,
                "hitl_status": "auto_approved",
                "notes": "Telemetry conforms to established historical baseline."
            }

        eligible.sort(key=lambda x: x["score"], reverse=True)
        top = eligible[0]
        inferred_state = top["state"]
        confidence = top["confidence"]

        # Universal Action Policy
        if confidence == "high":
            action, action_subtype, hitl_status = cls._resolve_action_policy(inferred_state, tier, top["elapsed_days"], cp_dt)
            notes = f"Corroborated {inferred_state} across {top['domain_count']} independent behavioral domain(s)."
        elif confidence == "medium" and top["domain_count"] >= 2 and top["elapsed_days"] >= 10.0 and top["has_anchor"]:
            action, action_subtype, hitl_status = cls._resolve_action_policy(inferred_state, tier, top["elapsed_days"], cp_dt)
            notes = f"Corroborated {inferred_state} (Evidence Score: {round(top['score'], 2)}, {top['domain_count']} domains)."
        else:
            action = "no_action"
            action_subtype = None
            hitl_status = "auto_approved"
            notes = f"Hypothesis {inferred_state} accumulating early evidence (Score: {round(top['score'], 2)}); monitoring."

        return {
            "as_of_time": as_of_time,
            "inferred_state": inferred_state,
            "confidence_band": confidence,
            "action": action,
            "action_subtype": action_subtype,
            "hitl_status": hitl_status,
            "notes": notes
        }

    @classmethod
    def _resolve_action_policy(cls, state: str, tier: str, elapsed_days: float = 0.0, cp_dt: datetime = None) -> tuple:
        """Dynamically matches action & subtype to customer tier and elapsed intervention timeline."""
        if state == "medical_hardship":
            return "support_intervention", "medical_hardship_payment_plan", "escalated"
        elif state == "new_child_life_event":
            return "personalized_offer", "childcare_savings_or_insurance_plan", "escalated"
        elif state == "relocation":
            return "personalized_offer", "homeowners_relocation_insurance", "escalated"
        elif state == "churn_risk":
            # Early Intervention Window (< 45 days since first disengagement): Escalate to Relationship Manager
            # Late / Terminal Stage (>= 45 days): Automated retention outreach offer
            if tier in ("high", "wealth", "premium"):
                if elapsed_days < 45.0:
                    return "relationship_manager_escalation", "premium_retention_offer_and_fee_waiver", "escalated"
                else:
                    return "proactive_retention_outreach", "loyalty_credit_rebate", "escalated"
            return "proactive_retention_outreach", "loyalty_credit_rebate", "escalated"
        elif state == "wealth_growth_or_windfall":
            return "relationship_manager_escalation", "private_wealth_advisory_intro", "escalated"
        elif state in ("potential_fraud_or_takeover", "elder_vulnerability_or_scam_risk"):
            return "compliance_fraud_hold", "immediate_account_security_freeze", "escalated"
        elif state in ("job_loss_or_income_disruption", "financial_distress_general"):
            return "support_intervention", "hardship_relief_deferral_program", "escalated"
        elif state in ("job_change_or_promotion", "retirement_transition"):
            if tier in ("high", "mid"):
                return "personalized_offer", "wealth_accumulation_or_rollover_plan", "escalated"
            return "personalized_offer", "standard_advisory_offer", "escalated"
        else:
            return "no_action", None, "auto_approved"
    
# =====================================================================
# 6. RUNNER HARNESS
# =====================================================================
def run_evaluation_pipeline(scenario_dir: str = "."):
    print("\n" + "="*65)
    print(f"🚀 RUNNING PIPELINE FOR: {scenario_dir}")
    print("="*65)

    entities_file = os.path.join(scenario_dir, "entities.json")
    history_file = os.path.join(scenario_dir, "history_seed.jsonl")
    live_stream_file = os.path.join(scenario_dir, "live_stream.jsonl")
    gt_file = os.path.join(scenario_dir, "ground_truth.json")
    
    output_events_file = os.path.join(scenario_dir, "inferred_events.json")
    output_metrics_file = os.path.join(scenario_dir, "run_metrics.json")

    start_wall_time = time.time()
    state_board = CustomerStateBoard(half_life_days=30.0)
    buffer = StreamingReplayBuffer(state_board)

    # 1. Load Entities
    if not os.path.exists(entities_file):
        print(f"[!] {entities_file} not found. Skipping.")
        return
        
    with open(entities_file, "r") as f:
        entities_data = json.load(f)
        if isinstance(entities_data, list):
            entities_data = entities_data[0]
    
    cid = entities_data.get("customer_id", "CUST_UNKNOWN")
    print(f"[*] Loaded Entity: {cid}")

    # 2. Seed Baseline History & Telemetry Rates
    card_spends = defaultdict(list)
    seed_count = 0
    hist_logins = []
    hist_card_txs = []
    hist_salaries = []

    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            for line in f:
                if not line.strip(): continue
                evt = json.loads(line)
                seed_count += 1
                src = evt.get("source_system")
                p = evt.get("payload", {})
                e_time = evt.get("event_time")

                if src == "card_payments":
                    if "amount" in p:
                        try:
                            card_spends[p.get("mcc_category", "general")].append(float(p["amount"]))
                        except ValueError:
                            pass
                    if e_time:
                        hist_card_txs.append(datetime.fromisoformat(e_time.replace("Z", "+00:00")))

                elif src == "web_app_events" and evt.get("event_type") == "login":
                    if e_time:
                        hist_logins.append(datetime.fromisoformat(e_time.replace("Z", "+00:00")))

                elif src in ("core_banking_ledger", "ach_wire"):
                    if "salary" in str(p.get("transaction_type", "")).lower():
                        try:
                            hist_salaries.append(float(p.get("amount", 0.0)))
                        except ValueError:
                            pass

    # Compute baselines
    baselines = {"spend_by_mcc": {}}
    for mcc, amounts in card_spends.items():
        m = sum(amounts) / len(amounts)
        v = sum((x - m) ** 2 for x in amounts) / len(amounts) if len(amounts) > 1 else 1.0
        baselines["spend_by_mcc"][mcc] = {"mean": m, "std_dev": math.sqrt(v)}

    # Historical monthly baselines (assuming ~90-120 days history seed)
    days_span = 90.0
    if hist_logins:
        days_span = max(30.0, (max(hist_logins) - min(hist_logins)).total_seconds() / 86400.0)
    months_span = max(1.0, days_span / 30.0)

    baselines["monthly_login_rate"] = len(hist_logins) / months_span
    baselines["monthly_card_tx_rate"] = len(hist_card_txs) / months_span
    baselines["mean_salary"] = (sum(hist_salaries) / len(hist_salaries)) if hist_salaries else 0.0

    entities_data["baselines"] = baselines
    state_board.init_customer(cid, entities_data)

    # Seed historical timestamps directly into live_metrics
    cust = state_board.board[cid]
    cust["live_metrics"]["login_timestamps"] = hist_logins
    cust["live_metrics"]["card_spend_timestamps"] = hist_card_txs
   

    # 3. Read Live Stream Events
    live_events = []
    if os.path.exists(live_stream_file):
        with open(live_stream_file, "r") as f:
            for line in f:
                if line.strip():
                    live_events.append(json.loads(line))
    print(f"[*] Loaded {len(live_events)} live events.")

    # 4. Checkpoints Extraction
    checkpoints = []
    gt_data = []
    if os.path.exists(gt_file):
        try:
            with open(gt_file, "r") as f:
                raw_gt = json.load(f)
            if isinstance(raw_gt, list):
                gt_data = raw_gt
                for item in raw_gt:
                    if isinstance(item, dict):
                        ts = item.get("as_of_time") or item.get("timestamp") or item.get("checkpoint")
                        if ts: checkpoints.append(str(ts))
                    elif isinstance(item, str):
                        checkpoints.append(item)
            elif isinstance(raw_gt, dict):
                gt_data = raw_gt.get("checkpoints") or [raw_gt]
                if isinstance(gt_data, list):
                    for item in gt_data:
                        if isinstance(item, dict):
                            ts = item.get("as_of_time") or item.get("timestamp")
                            if ts: checkpoints.append(str(ts))
                        elif isinstance(item, str):
                            checkpoints.append(item)
        except Exception as e:
            print(f"[!] Error parsing ground_truth: {e}")

    # Fallback to generated checkpoints if empty
    if not checkpoints:
        curr = datetime.fromisoformat("2026-02-08T00:00:00+00:00")
        end_dt = datetime.fromisoformat("2026-04-15T00:00:00+00:00")
        while curr <= end_dt:
            checkpoints.append(curr.strftime("%Y-%m-%dT00:00:00Z"))
            curr += timedelta(days=7)

    print(f"[*] Total Checkpoints to Evaluate: {len(checkpoints)}")

    # 5. Process Stream
    emitted_checkpoints = []
    evt_idx = 0
    total_evts = len(live_events)
    latencies_ms = []

    for idx, cp_str in enumerate(checkpoints):
        t0 = time.time()
        try:
            cp_dt = datetime.fromisoformat(cp_str.replace("Z", "+00:00"))
        except Exception:
            continue

        while evt_idx < total_evts:
            evt = live_events[evt_idx]
            try:
                e_dt = datetime.fromisoformat(evt["event_time"].replace("Z", "+00:00"))
            except Exception:
                evt_idx += 1
                continue

            if e_dt > cp_dt:
                break
            buffer.push(evt)
            evt_idx += 1

        buffer.flush_until(cp_dt, flush_all=True)

        st = state_board.get_state(cid)
        decision = MASInferenceEngine.evaluate_checkpoint(st, cp_str)
        emitted_checkpoints.append(decision)
        latencies_ms.append((time.time() - t0) * 1000.0)

    # 6. Save Inferred Events
    with open(output_events_file, "w") as f:
        json.dump(emitted_checkpoints, f, indent=2)
    print(f"[✓] Predictions written to: {output_events_file}")

    # Save Metrics
    total_time = time.time() - start_wall_time
    avg_lat = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
    metrics_payload = {
        "scenario": scenario_dir,
        "customer_id": cid,
        "processed_events": len(live_events),
        "checkpoints": len(emitted_checkpoints),
        "average_latency_ms": round(avg_lat, 2),
        "total_time_s": round(total_time, 3)
    }
    with open(output_metrics_file, "w") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"[✓] Metrics written to: {output_metrics_file}")

    # 7. Evaluation Check
    if gt_data and isinstance(gt_data, list):
        matches = 0
        total_eval = 0
        for i in range(min(len(gt_data), len(emitted_checkpoints))):
            item = gt_data[i]
            if isinstance(item, dict):
                gt_state = item.get("inferred_state") or item.get("state")
                pred_state = emitted_checkpoints[i].get("inferred_state")
                if gt_state and pred_state:
                    total_eval += 1
                    if gt_state == pred_state:
                        matches += 1
        if total_eval > 0:
            print(f"🎯 State Match Accuracy: {(matches/total_eval)*100.0:.2f}% ({matches}/{total_eval})")

    print("="*65 + "\n")


if __name__ == "__main__":
    scenarios = ["scenario_01", "scenario_02", "scenario_03"]
    ran_any = False
    for sc in scenarios:
        if os.path.exists(sc):
            run_evaluation_pipeline(sc)
            ran_any = True
            
    if not ran_any:
        run_evaluation_pipeline(".")