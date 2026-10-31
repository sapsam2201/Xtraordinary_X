"""
Brightloop Software - Subscription Management & Recurring Billing (single file)

Run API:      JWT_SECRET=... DATABASE_URL=postgresql+psycopg://... uvicorn brightloop:app
Run workers:  python brightloop.py billing | dunning | revenue | create_tables
Install:      pip install fastapi uvicorn "sqlalchemy>=2.0" "psycopg[binary]" pyjwt "passlib[bcrypt]" "pydantic[email]"
Sections:     1 Models | 2 Billing math | 3 Workers (billing, ledger, rev-rec, dunning) | 4 API routes
"""
import calendar, enum, hashlib, os, re, sys, uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import (JSON, Boolean, CheckConstraint, Date, DateTime, Enum, ForeignKey, Index,
                        Integer, Numeric, String, Text, UniqueConstraint,
                        case, create_engine, func, select, update)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker)



# ======================================================================
# 1. MODELS
# ======================================================================
def now(): return datetime.now(timezone.utc)
def tok(): return uuid.uuid4().hex + uuid.uuid4().hex
Money = Numeric(14, 2)

class Base(DeclarativeBase): pass

class Role(str, enum.Enum): ADMIN="admin"; STAFF="staff"; CUSTOMER="customer"
class Interval(str, enum.Enum): DAILY="daily"; WEEKLY="weekly"; MONTHLY="monthly"; YEARLY="yearly"
class SubState(str, enum.Enum):
    DRAFT="draft"; QUOTATION="quotation"; CONFIRMED="confirmed"; ACTIVE="active"
    GRACE_PERIOD="grace_period"; PAUSED="paused"; CLOSED="closed"
class InvState(str, enum.Enum):
    DRAFT="draft"; CONFIRMED="confirmed"; PAID="paid"; PAYMENT_FAILED="payment_failed"; CANCELLED="cancelled"

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)  # one account per email
    password_hash: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.CUSTOMER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 of emailed token
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)

class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    type: Mapped[str] = mapped_column(String(40))
    sales_price: Mapped[Decimal] = mapped_column(Money)
    cost_price: Mapped[Decimal] = mapped_column(Money, default=0)
    notes: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    variants: Mapped[list["ProductVariant"]] = relationship(back_populates="product")

class ProductVariant(Base):
    """e.g. attribute='Brand', value='Odoo', price_modifier=560."""
    __tablename__ = "product_variants"
    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), index=True)
    attribute: Mapped[str] = mapped_column(String(80))
    value: Mapped[str] = mapped_column(String(80))
    price_modifier: Mapped[Decimal] = mapped_column(Money, default=0)
    product: Mapped[Product] = relationship(back_populates="variants")
    __table_args__ = (UniqueConstraint("product_id", "attribute", "value"),)

class Plan(Base):
    __tablename__ = "plans"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    price: Mapped[Decimal] = mapped_column(Money)
    interval: Mapped[Interval] = mapped_column(Enum(Interval))
    min_quantity: Mapped[int] = mapped_column(Integer, default=1)
    available_from: Mapped[date | None] = mapped_column(Date)
    available_to: Mapped[date | None] = mapped_column(Date)
    # lifecycle flags, set per plan by admin
    auto_close: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_early_close: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_pause: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_renew: Mapped[bool] = mapped_column(Boolean, default=True)

class QuotationTemplate(Base):
    __tablename__ = "quotation_templates"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    validity_days: Mapped[int] = mapped_column(Integer, default=30)
    lines: Mapped[list["QuotationTemplateLine"]] = relationship()

class QuotationTemplateLine(Base):
    __tablename__ = "quotation_template_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("quotation_templates.id"), index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"))
    variant_id: Mapped[int | None] = mapped_column(ForeignKey("product_variants.id"))
    quantity: Mapped[int] = mapped_column(Integer, default=1)

class TaxRule(Base):
    __tablename__ = "tax_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    rate_pct: Mapped[Decimal] = mapped_column(Numeric(6, 3))
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id"))  # NULL = applies to all
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class DiscountRule(Base):
    __tablename__ = "discount_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(10))  # 'fixed' | 'percent'
    value: Mapped[Decimal] = mapped_column(Money)
    min_amount: Mapped[Decimal] = mapped_column(Money, default=0)
    min_quantity: Mapped[int] = mapped_column(Integer, default=0)
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id"))  # NULL = whole subscription
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    usage_limit: Mapped[int | None] = mapped_column(Integer)
    times_used: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (CheckConstraint("kind in ('fixed','percent')"),)

class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    number: Mapped[str] = mapped_column(String(32), unique=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    state: Mapped[SubState] = mapped_column(Enum(SubState), default=SubState.DRAFT)
    start_date: Mapped[date] = mapped_column(Date)
    expiry_date: Mapped[date | None] = mapped_column(Date)
    quote_valid_until: Mapped[date | None] = mapped_column(Date)
    payment_terms_days: Mapped[int] = mapped_column(Integer, default=15)
    next_billing_date: Mapped[date | None] = mapped_column(Date)
    # Enterprise overrides, e.g. {"locked_unit_prices": {"<product_id>": "99.00"},
    #  "milestones": [{"date": "2026-03-01", "amount": "5000"}], "ignore_catalog_updates": true}
    contract_override: Mapped[dict | None] = mapped_column(JSON)
    grace_until: Mapped[date | None] = mapped_column(Date)
    lines: Mapped[list["SubscriptionLine"]] = relationship(cascade="all, delete-orphan")
    plan: Mapped[Plan] = relationship()
    customer: Mapped[User] = relationship()
    __table_args__ = (Index("ix_sub_state_nextbill", "state", "next_billing_date"),)

class SubscriptionLine(Base):
    __tablename__ = "subscription_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"), index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"))
    variant_id: Mapped[int | None] = mapped_column(ForeignKey("product_variants.id"))
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    unit_price: Mapped[Decimal] = mapped_column(Money)  # snapshot at confirmation
    product: Mapped[Product] = relationship()

class Invoice(Base):
    __tablename__ = "invoices"
    id: Mapped[int] = mapped_column(primary_key=True)
    number: Mapped[str] = mapped_column(String(32), unique=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"), index=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    state: Mapped[InvState] = mapped_column(Enum(InvState), default=InvState.DRAFT)
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    issue_date: Mapped[date] = mapped_column(Date, default=date.today)
    due_date: Mapped[date] = mapped_column(Date)
    subtotal: Mapped[Decimal] = mapped_column(Money, default=0)
    discount_total: Mapped[Decimal] = mapped_column(Money, default=0)
    tax_total: Mapped[Decimal] = mapped_column(Money, default=0)
    total: Mapped[Decimal] = mapped_column(Money, default=0)
    amount_paid: Mapped[Decimal] = mapped_column(Money, default=0)
    lines: Mapped[list["InvoiceLine"]] = relationship(cascade="all, delete-orphan")
    __table_args__ = (
        # IDEMPOTENCY: one invoice per subscription per billing period, enforced by the DB.
        UniqueConstraint("subscription_id", "period_start", "period_end", name="uq_invoice_period"),
        Index("ix_inv_state_due", "state", "due_date"),
        Index("ix_inv_issue", "issue_date"),
    )

class InvoiceLine(Base):
    __tablename__ = "invoice_lines"
    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True)
    kind: Mapped[str] = mapped_column(String(12), default="product")  # product|usage|discount|proration
    description: Mapped[str] = mapped_column(String(255))
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id"))
    quantity: Mapped[Decimal] = mapped_column(Numeric(12, 3), default=1)
    unit_price: Mapped[Decimal] = mapped_column(Money)
    tax_amount: Mapped[Decimal] = mapped_column(Money, default=0)
    amount: Mapped[Decimal] = mapped_column(Money)

class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True)
    method: Mapped[str] = mapped_column(String(40))
    amount: Mapped[Decimal] = mapped_column(Money)
    paid_on: Mapped[date] = mapped_column(Date)
    note: Mapped[str | None] = mapped_column(Text)
    recorded_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    __table_args__ = (Index("ix_pay_date", "paid_on"),)

class UnbilledLineItem(Base):
    """Usage event log (seats, API calls). Swept onto the next invoice."""
    __tablename__ = "unbilled_line_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    metric: Mapped[str] = mapped_column(String(60))
    quantity: Mapped[Decimal] = mapped_column(Numeric(14, 3))
    unit_price: Mapped[Decimal] = mapped_column(Money)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    invoice_id: Mapped[int | None] = mapped_column(ForeignKey("invoices.id"))  # NULL = unbilled
    external_event_id: Mapped[str | None] = mapped_column(String(80), unique=True)  # dedupe metering
    __table_args__ = (Index("ix_unbilled_pending", "subscription_id", "invoice_id"),)

class DunningAttempt(Base):
    __tablename__ = "dunning_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True)
    attempt_no: Mapped[int] = mapped_column(Integer)  # 1,2,3 -> day 1,3,7
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("invoice_id", "attempt_no"),)

class CardUpdateToken(Base):
    __tablename__ = "card_update_tokens"
    token: Mapped[str] = mapped_column(String(64), primary_key=True, default=tok)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)

class DeferredRevenueSchedule(Base):
    """ASC 606 / IFRS 15: one row per month of the service period."""
    __tablename__ = "deferred_revenue_schedule"
    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True)
    recognition_date: Mapped[date] = mapped_column(Date)
    amount: Mapped[Decimal] = mapped_column(Money)
    recognized: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (Index("ix_defrev_due", "recognized", "recognition_date"),)

class LedgerEntry(Base):
    """Double-entry: every journal has debits == credits."""
    __tablename__ = "ledger_entries"
    id: Mapped[int] = mapped_column(primary_key=True)
    journal_id: Mapped[str] = mapped_column(String(40), index=True)
    account: Mapped[str] = mapped_column(String(40))  # cash|accounts_receivable|deferred_revenue|revenue|tax_payable
    debit: Mapped[Decimal] = mapped_column(Money, default=0)
    credit: Mapped[Decimal] = mapped_column(Money, default=0)
    invoice_id: Mapped[int | None] = mapped_column(ForeignKey("invoices.id"))
    entry_date: Mapped[date] = mapped_column(Date)

class ProrationLog(Base):
    __tablename__ = "proration_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"), index=True)
    change_date: Mapped[date] = mapped_column(Date)
    explanation: Mapped[dict] = mapped_column(JSON)
    net_amount: Mapped[Decimal] = mapped_column(Money)
    applied: Mapped[bool] = mapped_column(Boolean, default=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(80))
    entity: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSON)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


# ======================================================================
# 2. BILLING MATH
# ======================================================================
D = Decimal
def q(x): return D(x).quantize(D("0.01"), rounding=ROUND_HALF_UP)

def add_interval(d: date, interval: Interval) -> date:
    if interval == Interval.DAILY: return d + timedelta(days=1)
    if interval == Interval.WEEKLY: return d + timedelta(weeks=1)
    months = 1 if interval == Interval.MONTHLY else 12
    y, m = divmod(d.month - 1 + months, 12)
    y += d.year; m += 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))

def prorate(old_price, new_price, period_start: date, period_end: date, change_date: date):
    """period_end is exclusive (= next period_start). Returns (net, itemised audit steps)."""
    old_price, new_price = D(old_price), D(new_price)
    total_days = (period_end - period_start).days
    if not (period_start <= change_date < period_end) or total_days <= 0:
        raise ValueError("change_date must fall inside the current billing period")
    used, remaining = (change_date - period_start).days, (period_end - change_date).days
    old_daily, new_daily = old_price / total_days, new_price / total_days
    credit, charge = q(old_daily * remaining), q(new_daily * remaining)
    steps = [
        {"step": "Period length", "detail": f"{period_start} to {period_end} = {total_days} days"},
        {"step": "Old daily rate", "detail": f"{old_price} / {total_days} = {old_daily:.4f}/day"},
        {"step": "New daily rate", "detail": f"{new_price} / {total_days} = {new_daily:.4f}/day"},
        {"step": "Days used on old plan", "detail": f"{used}"},
        {"step": "Days remaining", "detail": f"{remaining}"},
        {"step": "Credit for unused time", "detail": f"{old_daily:.4f} x {remaining} = -{credit}"},
        {"step": "Charge for new plan", "detail": f"{new_daily:.4f} x {remaining} = +{charge}"},
        {"step": "Net due now", "detail": f"{charge} - {credit} = {charge - credit}"},
    ]
    return charge - credit, {"credit": str(credit), "charge": str(charge), "steps": steps}

def current_period_start(period_end: date, interval: Interval) -> date:
    """Inverse of add_interval for the period that ends at period_end."""
    if interval == Interval.DAILY: return period_end - timedelta(days=1)
    if interval == Interval.WEEKLY: return period_end - timedelta(weeks=1)
    months = 1 if interval == Interval.MONTHLY else 12
    y, m = divmod(period_end.month - 1 - months, 12)
    y += period_end.year; m += 1
    return date(y, m, min(period_end.day, calendar.monthrange(y, m)[1]))


# ======================================================================
# 3. BACKGROUND WORKERS
# ======================================================================
engine = create_engine(os.environ.get("DATABASE_URL", "postgresql+psycopg://localhost/brightloop"),
                       pool_pre_ping=True)
SessionLocal = sessionmaker(engine)
DUNNING_DAYS = {1: 1, 2: 3, 3: 7}   # attempt_no -> days after failure

# ---------------------------------------------------------------- BILLING DAY
def effective_price(sub: Subscription, line: SubscriptionLine) -> D:
    """Enterprise override layer: locked prices shield from catalog changes."""
    ov = (sub.contract_override or {}).get("locked_unit_prices", {})
    return D(ov[str(line.product_id)]) if str(line.product_id) in ov else line.unit_price

def tax_rate_for(db: Session, product_id) -> D:
    rows = db.scalars(select(TaxRule).where(TaxRule.active,
            (TaxRule.product_id == product_id) | (TaxRule.product_id.is_(None)))).all()
    return sum((r.rate_pct for r in rows), D(0)) / 100

def claim_discount(db: Session, rule: DiscountRule) -> bool:
    """Atomic usage-limit claim: prevents two concurrent runs over-using a rule."""
    res = db.execute(update(DiscountRule).where(DiscountRule.id == rule.id,
        (DiscountRule.usage_limit.is_(None)) | (DiscountRule.times_used < DiscountRule.usage_limit))
        .values(times_used=DiscountRule.times_used + 1))
    return res.rowcount == 1

def build_invoice(db: Session, sub: Subscription, p_start: date, p_end: date) -> Invoice:
    inv = Invoice(number=f"INV-{sub.number}-{p_start:%Y%m%d}", subscription_id=sub.id,
                  customer_id=sub.customer_id, period_start=p_start, period_end=p_end,
                  issue_date=p_start, due_date=p_start + timedelta(days=sub.payment_terms_days))
    sub_total = D(0)
    # 1) recurring lines
    for l in sub.lines:
        price = effective_price(sub, l)
        amt = q(price * l.quantity)
        tax = q(amt * tax_rate_for(db, l.product_id))
        inv.lines.append(InvoiceLine(kind="product", description=l.product.name, product_id=l.product_id,
                                     quantity=l.quantity, unit_price=price, amount=amt, tax_amount=tax))
        sub_total += amt
    # 2) staggered milestones from the contract override
    for m in (sub.contract_override or {}).get("milestones", []):
        if p_start <= date.fromisoformat(m["date"]) < p_end:
            amt = D(m["amount"])
            inv.lines.append(InvoiceLine(kind="product", description=m.get("label", "Contract milestone"),
                                         unit_price=amt, amount=amt))
            sub_total += amt
    # 3) usage (locked rows so a concurrent run cannot sweep the same events)
    usage = db.scalars(select(UnbilledLineItem).where(UnbilledLineItem.subscription_id == sub.id,
            UnbilledLineItem.invoice_id.is_(None), UnbilledLineItem.occurred_at < datetime.now(timezone.utc))
            .with_for_update(skip_locked=True)).all()
    grouped: dict[tuple, list] = {}
    for u in usage: grouped.setdefault((u.metric, u.unit_price), []).append(u)
    for (metric, price), items in grouped.items():
        qty = sum(i.quantity for i in items); amt = q(qty * price)
        inv.lines.append(InvoiceLine(kind="usage", description=f"Usage: {metric}", quantity=qty,
                                     unit_price=price, amount=amt, tax_amount=q(amt * tax_rate_for(db, None))))
        sub_total += amt
    # 4) rule-based discounts
    qty_total = sum(l.quantity for l in sub.lines)
    rules = db.scalars(select(DiscountRule).where(
        (DiscountRule.start_date.is_(None)) | (DiscountRule.start_date <= p_start),
        (DiscountRule.end_date.is_(None)) | (DiscountRule.end_date >= p_start))).all()
    discount = D(0)
    for r in rules:
        base, qty = (sub_total, qty_total) if r.product_id is None else (
            sum((q(effective_price(sub, l) * l.quantity) for l in sub.lines if l.product_id == r.product_id), D(0)),
            sum((l.quantity for l in sub.lines if l.product_id == r.product_id), 0))
        if base <= 0 or base < r.min_amount or qty < r.min_quantity: continue
        if not claim_discount(db, r): continue
        d = q(base * r.value / 100) if r.kind == "percent" else min(r.value, base)
        inv.lines.append(InvoiceLine(kind="discount", description=f"Discount: {r.name}",
                                     product_id=r.product_id, unit_price=-d, amount=-d))
        discount += d
    inv.subtotal, inv.discount_total = sub_total, discount
    # tax on discounted lines is reduced proportionally
    gross_tax = sum((l.tax_amount for l in inv.lines), D(0))
    inv.tax_total = q(gross_tax * (1 - discount / sub_total)) if sub_total else D(0)
    inv.total = sub_total - discount + inv.tax_total
    inv.state = InvState.CONFIRMED
    for u in usage: u.invoice_id = None  # set after flush below
    db.add(inv); db.flush()
    for u in usage: u.invoice_id = inv.id
    db.add(AuditLog(action="invoice.generated", entity="invoice", entity_id=inv.id,
                    detail={"subscription": sub.number, "total": str(inv.total)}))
    return inv

def run_billing(today: date | None = None) -> dict:
    today = today or date.today()
    stats = {"created": 0, "skipped_existing": 0, "errors": 0}
    with SessionLocal() as db:
        ids = db.scalars(select(Subscription.id).where(Subscription.state == SubState.ACTIVE,
                                                       Subscription.next_billing_date <= today)).all()
    for sid in ids:                      # one transaction per subscription: a failure never blocks the rest
        with SessionLocal() as db:
            try:
                with db.begin():
                    sub = db.scalars(select(Subscription).where(Subscription.id == sid)
                                     .with_for_update(skip_locked=True)).first()
                    if not sub or sub.state != SubState.ACTIVE or sub.next_billing_date > today:
                        continue         # another worker got it / already advanced
                    while sub.next_billing_date <= today:   # catch up on missed cycles, none skipped
                        p_start = sub.next_billing_date
                        p_end = add_interval(p_start, sub.plan.interval)
                        if sub.expiry_date and p_start >= sub.expiry_date:
                            if sub.plan.auto_close: sub.state = SubState.CLOSED
                            sub.next_billing_date = None; break
                        exists = db.scalar(select(Invoice.id).where(Invoice.subscription_id == sub.id,
                                    Invoice.period_start == p_start, Invoice.period_end == p_end))
                        if exists: stats["skipped_existing"] += 1
                        else:
                            build_invoice(db, sub, p_start, p_end); stats["created"] += 1
                        sub.next_billing_date = p_end
            except IntegrityError:       # unique(subscription, period) tripped by a race: safe to ignore
                stats["skipped_existing"] += 1
            except Exception as e:
                stats["errors"] += 1; print(f"billing error sub={sid}: {e}", file=sys.stderr)
    return stats

# ---------------------------------------------------------------- PAYMENTS / LEDGER / REV REC
def split_months(total: D, start: date, end: date) -> list[tuple[date, D]]:
    """Straight-line monthly release; last month absorbs rounding."""
    dates, d = [], start
    while d < end: dates.append(d); d = add_interval(d, Interval.MONTHLY)
    each = q(total / len(dates)); out = [(x, each) for x in dates]
    out[-1] = (out[-1][0], total - each * (len(dates) - 1))
    return out

def post_payment_ledger(db: Session, inv: Invoice, amount: D, paid_on: date):
    # call AFTER inv.state has been set to PAID
    """Cash received -> clears A/R. If the service period spans >1 month, the net
    amount sits in deferred revenue and is released monthly; otherwise recognise at once."""
    jid = f"PAY-{inv.id}-{uuid.uuid4().hex[:10]}"
    net = amount - inv.tax_total * (amount / inv.total if inv.total else 1)
    tax = amount - net
    db.add(LedgerEntry(journal_id=jid, account="cash", debit=amount, entry_date=paid_on, invoice_id=inv.id))
    db.add(LedgerEntry(journal_id=jid, account="tax_payable", credit=q(tax), entry_date=paid_on, invoice_id=inv.id))
    months = len(split_months(D(1), inv.period_start, inv.period_end))
    if months > 1 and inv.state == InvState.PAID:
        db.add(LedgerEntry(journal_id=jid, account="deferred_revenue", credit=q(net), entry_date=paid_on, invoice_id=inv.id))
        for d, amt in split_months(q(net), inv.period_start, inv.period_end):
            db.add(DeferredRevenueSchedule(invoice_id=inv.id, recognition_date=d, amount=amt))
    else:
        db.add(LedgerEntry(journal_id=jid, account="revenue", credit=q(net), entry_date=paid_on, invoice_id=inv.id))

def run_revenue_recognition(today: date | None = None) -> int:
    today, n = today or date.today(), 0
    with SessionLocal() as db, db.begin():
        rows = db.scalars(select(DeferredRevenueSchedule).where(DeferredRevenueSchedule.recognized.is_(False),
                DeferredRevenueSchedule.recognition_date <= today).with_for_update(skip_locked=True)).all()
        for r in rows:
            jid = f"REC-{r.id}"
            db.add_all([LedgerEntry(journal_id=jid, account="deferred_revenue", debit=r.amount,
                                    entry_date=r.recognition_date, invoice_id=r.invoice_id),
                        LedgerEntry(journal_id=jid, account="revenue", credit=r.amount,
                                    entry_date=r.recognition_date, invoice_id=r.invoice_id)])
            r.recognized = True; n += 1
    return n

# ---------------------------------------------------------------- SMART DUNNING
def charge_card(inv: Invoice) -> bool:
    """Plug in Stripe/Razorpay here (off-session charge using saved token)."""
    raise NotImplementedError

def send_email(to: str, subject: str, body: str): print(f"[email] {to}: {subject}")  # replace with SES/SMTP

def run_dunning(now_: datetime | None = None) -> dict:
    now_ = now_ or datetime.now(timezone.utc); stats = {"retried": 0, "recovered": 0, "closed": 0}
    with SessionLocal() as db, db.begin():
        # Newly overdue confirmed invoices enter dunning: access stays on (grace period)
        for inv in db.scalars(select(Invoice).where(Invoice.state == InvState.CONFIRMED,
                              Invoice.due_date < now_.date()).with_for_update(skip_locked=True)):
            inv.state = InvState.PAYMENT_FAILED
            sub = db.get(Subscription, inv.subscription_id)
            if sub.state == SubState.ACTIVE:
                sub.state = SubState.GRACE_PERIOD; sub.grace_until = now_.date() + timedelta(days=DUNNING_DAYS[3])
            _send_card_link(db, inv, now_)
        failed = db.scalars(select(Invoice).where(Invoice.state == InvState.PAYMENT_FAILED)
                            .with_for_update(skip_locked=True)).all()
        for inv in failed:
            done = db.scalar(select(func.count()).select_from(DunningAttempt).where(DunningAttempt.invoice_id == inv.id)) or 0
            sub = db.get(Subscription, inv.subscription_id)
            age = (now_.date() - inv.due_date).days
            nxt = done + 1
            if nxt <= 3 and age >= DUNNING_DAYS[nxt]:
                try: ok = charge_card(inv)
                except Exception: ok = False
                db.add(DunningAttempt(invoice_id=inv.id, attempt_no=nxt, success=ok)); stats["retried"] += 1
                if ok:
                    inv.state, inv.amount_paid = InvState.PAID, inv.total
                    if sub.state == SubState.GRACE_PERIOD: sub.state, sub.grace_until = SubState.ACTIVE, None
                    stats["recovered"] += 1
                else:
                    _send_card_link(db, inv, now_)
            elif done >= 3 and age > DUNNING_DAYS[3]:        # schedule exhausted
                sub.state = SubState.CLOSED; stats["closed"] += 1
    return stats

def _send_card_link(db: Session, inv: Invoice, now_: datetime):
    t = CardUpdateToken(invoice_id=inv.id, expires_at=now_ + timedelta(days=7)); db.add(t)
    cust = db.get(User, inv.customer_id)
    send_email(cust.email, f"Payment failed for {inv.number}",
               f"Update your card: https://app.brightloop.io/card-update/{t.token}")



# ======================================================================
# 4. API ROUTES
# ======================================================================
SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")  # ALWAYS set in production
app = FastAPI(title="Brightloop Billing")
pwd = CryptContext(schemes=["bcrypt"]); bearer = HTTPBearer()
MIN_PASSWORD_LEN = 8   # PDF text says "more than eight" while the bullet says 8+: set to 9 if strict reading is intended

def get_db():
    with SessionLocal() as db:
        yield db

# ------------------------------------------------------------------ auth / RBAC
def validate_password(p: str):
    if (len(p) < MIN_PASSWORD_LEN or not re.search(r"[A-Z]", p) or not re.search(r"[a-z]", p)
            or not re.search(r"[^A-Za-z0-9]", p)):
        raise HTTPException(422, "Password needs 8+ chars with uppercase, lowercase and a special character")

def current_user(c: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    try: uid = jwt.decode(c.credentials, SECRET, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError: raise HTTPException(401, "Invalid token")
    u = db.get(User, int(uid))
    if not u or not u.is_active: raise HTTPException(401, "Inactive user")
    return u

def require(*roles: Role):
    def dep(u: User = Depends(current_user)):
        if u.role not in roles: raise HTTPException(403, "Insufficient role")
        return u
    return dep

class Credentials(BaseModel): email: EmailStr; password: str
class Register(Credentials): name: str

@app.post("/auth/register", status_code=201)
def register(b: Register, db: Session = Depends(get_db)):
    validate_password(b.password)
    if db.scalar(select(User.id).where(func.lower(User.email) == b.email.lower())):
        raise HTTPException(409, "Email already registered")
    db.add(User(email=b.email.lower(), name=b.name, password_hash=pwd.hash(b.password), role=Role.CUSTOMER))
    db.commit(); return {"ok": True}

@app.post("/auth/login")
def login(b: Credentials, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == b.email.lower()))
    if not u or not pwd.verify(b.password, u.password_hash): raise HTTPException(401, "Bad credentials")
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return {"token": jwt.encode({"sub": str(u.id), "role": u.role.value, "exp": exp}, SECRET)}

@app.post("/auth/forgot-password")
def forgot(email: EmailStr, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == email.lower()))
    if u:
        raw = tok()
        db.add(PasswordResetToken(user_id=u.id, token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                                  expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        db.commit()
        send_email(u.email, "Reset your password", f"https://app.brightloop.io/reset?token={raw}")
    return {"ok": True}   # identical response whether or not the email exists

class Reset(BaseModel): token: str; new_password: str
@app.post("/auth/reset-password")
def reset(b: Reset, db: Session = Depends(get_db)):
    validate_password(b.new_password)
    t = db.scalar(select(PasswordResetToken).where(
        PasswordResetToken.token_hash == hashlib.sha256(b.token.encode()).hexdigest()))
    if not t or t.used or t.expires_at < datetime.now(timezone.utc): raise HTTPException(400, "Invalid or expired link")
    db.get(User, t.user_id).password_hash = pwd.hash(b.new_password); t.used = True; db.commit()
    return {"ok": True}

@app.post("/admin/staff", status_code=201)   # admin-only staff creation
def add_staff(b: Register, admin: User = Depends(require(Role.ADMIN)), db: Session = Depends(get_db)):
    validate_password(b.password)
    if db.scalar(select(User.id).where(User.email == b.email.lower())): raise HTTPException(409, "Email exists")
    db.add(User(email=b.email.lower(), name=b.name, password_hash=pwd.hash(b.password), role=Role.STAFF))
    db.add(AuditLog(actor_id=admin.id, action="staff.created", entity="user", detail={"email": b.email}))
    db.commit(); return {"ok": True}

# ------------------------------------------------------------------ catalog (admin)
class ProductIn(BaseModel):
    name: str; type: str; sales_price: Decimal; cost_price: Decimal = 0; notes: str | None = None
    variants: list[dict] = []   # [{"attribute":"Brand","value":"Odoo","price_modifier":560}]

@app.post("/admin/products", status_code=201)
def create_product(b: ProductIn, _=Depends(require(Role.ADMIN)), db: Session = Depends(get_db)):
    p = Product(**b.model_dump(exclude={"variants"}))
    p.variants = [ProductVariant(**v) for v in b.variants]
    db.add(p); db.commit(); return {"id": p.id}

class PlanIn(BaseModel):
    name: str; price: Decimal; interval: Interval; min_quantity: int = 1
    available_from: date | None = None; available_to: date | None = None
    auto_close: bool = False; allow_early_close: bool = True; allow_pause: bool = True; allow_renew: bool = True

@app.post("/admin/plans", status_code=201)
def create_plan(b: PlanIn, _=Depends(require(Role.ADMIN)), db: Session = Depends(get_db)):
    p = Plan(**b.model_dump()); db.add(p); db.commit(); return {"id": p.id}

class DiscountIn(BaseModel):
    name: str; kind: str; value: Decimal; min_amount: Decimal = 0; min_quantity: int = 0
    product_id: int | None = None; start_date: date | None = None; end_date: date | None = None
    usage_limit: int | None = None

@app.post("/admin/discounts", status_code=201)
def create_discount(b: DiscountIn, _=Depends(require(Role.ADMIN)), db: Session = Depends(get_db)):
    r = DiscountRule(**b.model_dump()); db.add(r); db.commit(); return {"id": r.id}

# ------------------------------------------------------------------ quote -> subscription
TRANSITIONS = {SubState.DRAFT: {SubState.QUOTATION}, SubState.QUOTATION: {SubState.CONFIRMED, SubState.DRAFT},
               SubState.CONFIRMED: {SubState.ACTIVE}, SubState.ACTIVE: {SubState.CLOSED, SubState.PAUSED},
               SubState.PAUSED: {SubState.ACTIVE, SubState.CLOSED},
               SubState.GRACE_PERIOD: {SubState.ACTIVE, SubState.CLOSED}, SubState.CLOSED: set()}

class QuoteIn(BaseModel):
    template_id: int; customer_id: int; start_date: date; payment_terms_days: int = 15

@app.post("/subscriptions/from-template", status_code=201)
def quote_from_template(b: QuoteIn, u: User = Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    t = db.get(QuotationTemplate, b.template_id)
    if not t: raise HTTPException(404, "Template not found")
    plan = db.get(Plan, t.plan_id)
    sub = Subscription(number=f"SUB-{datetime.now():%y%m}-{tok()[:6].upper()}", customer_id=b.customer_id,
                       plan_id=plan.id, start_date=b.start_date, payment_terms_days=b.payment_terms_days,
                       quote_valid_until=date.today() + timedelta(days=t.validity_days))
    for l in t.lines:
        prod = db.get(Product, l.product_id); mod = db.get(ProductVariant, l.variant_id).price_modifier if l.variant_id else 0
        sub.lines.append(SubscriptionLine(product_id=l.product_id, variant_id=l.variant_id,
                                          quantity=max(l.quantity, plan.min_quantity), unit_price=prod.sales_price + mod))
    db.add(sub); db.add(AuditLog(actor_id=u.id, action="quote.created", entity="subscription"))
    db.commit(); return {"id": sub.id, "number": sub.number}

@app.post("/subscriptions/{sid}/transition")
def transition(sid: int, to: SubState, u: User = Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    sub = db.scalars(select(Subscription).where(Subscription.id == sid).with_for_update()).first()
    if not sub: raise HTTPException(404)
    if to not in TRANSITIONS[sub.state]: raise HTTPException(409, f"Cannot go {sub.state.value} -> {to.value}")
    if to == SubState.CONFIRMED and sub.quote_valid_until and sub.quote_valid_until < date.today():
        raise HTTPException(409, "Quotation expired")
    plan = sub.plan
    if to == SubState.PAUSED and not plan.allow_pause: raise HTTPException(409, "Plan does not allow pausing")
    if to == SubState.CLOSED and sub.state == SubState.ACTIVE and not plan.allow_early_close:
        raise HTTPException(409, "Plan does not allow early close")
    if to == SubState.ACTIVE and sub.next_billing_date is None: sub.next_billing_date = sub.start_date
    prev, sub.state = sub.state, to
    db.add(AuditLog(actor_id=u.id, action="subscription.transition", entity="subscription", entity_id=sub.id,
                    detail={"from": prev.value, "to": to.value}))
    db.commit(); return {"state": sub.state.value}

class PlanChange(BaseModel): new_plan_id: int; change_date: date; apply: bool = False

@app.post("/subscriptions/{sid}/proration")
def proration(sid: int, b: PlanChange, u: User = Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    sub = db.get(Subscription, sid); new = db.get(Plan, b.new_plan_id)
    if not sub or not new or sub.state != SubState.ACTIVE: raise HTTPException(404, "Active subscription/plan required")
    p_end = sub.next_billing_date; p_start = current_period_start(p_end, sub.plan.interval)
    try: net, log = prorate(sub.plan.price, new.price, p_start, p_end, b.change_date)
    except ValueError as e: raise HTTPException(422, str(e))
    row = ProrationLog(subscription_id=sub.id, change_date=b.change_date, explanation=log, net_amount=q(net), applied=b.apply)
    db.add(row)
    if b.apply:   # simulator by default; apply=true commits the plan switch
        sub.plan_id = new.id
        db.add(AuditLog(actor_id=u.id, action="plan.changed", entity="subscription", entity_id=sub.id, detail=log))
    db.commit(); return {"net": str(q(net)), "audit": log["steps"], "applied": b.apply}

# ------------------------------------------------------------------ usage metering
class Usage(BaseModel): subscription_id: int; metric: str; quantity: Decimal; unit_price: Decimal; event_id: str
@app.post("/usage", status_code=202)
def log_usage(b: Usage, _=Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    if db.scalar(select(UnbilledLineItem.id).where(UnbilledLineItem.external_event_id == b.event_id)):
        return {"duplicate": True}
    db.add(UnbilledLineItem(subscription_id=b.subscription_id, metric=b.metric, quantity=b.quantity,
                            unit_price=b.unit_price, external_event_id=b.event_id)); db.commit()
    return {"ok": True}

# ------------------------------------------------------------------ invoices & payments
INV_FLOW = {InvState.DRAFT: {InvState.CONFIRMED, InvState.CANCELLED}, InvState.CONFIRMED: {InvState.PAID, InvState.CANCELLED}}

@app.post("/invoices/{iid}/transition")
def inv_transition(iid: int, to: InvState, _=Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    inv = db.scalars(select(Invoice).where(Invoice.id == iid).with_for_update()).first()
    if not inv: raise HTTPException(404)
    if to not in INV_FLOW.get(inv.state, set()): raise HTTPException(409, "Invalid invoice transition")
    inv.state = to; db.commit(); return {"state": to.value}

class PaymentIn(BaseModel): invoice_id: int; method: str; amount: Decimal; paid_on: date; note: str | None = None

@app.post("/payments", status_code=201)
def log_payment(b: PaymentIn, u: User = Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    inv = db.scalars(select(Invoice).where(Invoice.id == b.invoice_id).with_for_update()).first()
    if not inv or inv.state not in (InvState.CONFIRMED, InvState.PAYMENT_FAILED): raise HTTPException(409, "Invoice not payable")
    if b.amount <= 0 or inv.amount_paid + b.amount > inv.total: raise HTTPException(422, "Invalid amount")
    db.add(Payment(invoice_id=inv.id, method=b.method, amount=b.amount, paid_on=b.paid_on, note=b.note, recorded_by=u.id))
    inv.amount_paid += b.amount
    if inv.amount_paid == inv.total:        # Confirmed -> Paid instantly
        inv.state = InvState.PAID
        sub = db.get(Subscription, inv.subscription_id)
        if sub.state == SubState.GRACE_PERIOD: sub.state, sub.grace_until = SubState.ACTIVE, None
    post_payment_ledger(db, inv, b.amount, b.paid_on)
    db.commit(); return {"state": inv.state.value, "outstanding": str(inv.total - inv.amount_paid)}

# ------------------------------------------------------------------ customer portal (own data only)
@app.get("/portal/subscriptions")
def my_subs(u: User = Depends(require(Role.CUSTOMER)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Subscription).where(Subscription.customer_id == u.id)).all()
    return [{"number": s.number, "state": s.state.value, "next_billing": s.next_billing_date} for s in rows]

@app.get("/portal/invoices")
def my_invoices(u: User = Depends(require(Role.CUSTOMER)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Invoice).where(Invoice.customer_id == u.id).order_by(Invoice.issue_date.desc())).all()
    return [{"id": i.id, "number": i.number, "state": i.state.value, "total": str(i.total), "due": i.due_date} for i in rows]

@app.get("/portal/invoices/{iid}/pdf")
def my_invoice_pdf(iid: int, u: User = Depends(require(Role.CUSTOMER)), db: Session = Depends(get_db)):
    inv = db.get(Invoice, iid)
    if not inv or inv.customer_id != u.id: raise HTTPException(404)   # 404, not 403: don't leak existence
    raise HTTPException(501, "Render with WeasyPrint/ReportLab from inv.lines")

# ------------------------------------------------------------------ executive dashboard (single aggregate queries, index-backed)
@app.get("/dashboard/summary")
def dashboard(date_from: date | None = None, date_to: date | None = None,
              _=Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    today = date.today(); date_from = date_from or today.replace(day=1); date_to = date_to or today
    active = db.scalar(select(func.count()).select_from(Subscription).where(Subscription.state == SubState.ACTIVE))
    # MRR normalised per plan interval, computed in SQL
    monthly = case((Plan.interval == Interval.YEARLY, Plan.price / 12), (Plan.interval == Interval.WEEKLY, Plan.price * 52 / 12),
                   (Plan.interval == Interval.DAILY, Plan.price * 365 / 12), else_=Plan.price)
    mrr = db.scalar(select(func.coalesce(func.sum(monthly), 0)).select_from(Subscription)
                    .join(Plan, Plan.id == Subscription.plan_id).where(Subscription.state == SubState.ACTIVE))
    collected = db.scalar(select(func.coalesce(func.sum(Payment.amount), 0))
                          .where(Payment.paid_on.between(date_from, date_to)))
    open_states = (InvState.CONFIRMED, InvState.PAYMENT_FAILED)
    owed, = db.execute(select(func.coalesce(func.sum(Invoice.total - Invoice.amount_paid), 0))
                       .where(Invoice.state.in_(open_states))).one()
    overdue_q = select(func.count(), func.coalesce(func.sum(Invoice.total - Invoice.amount_paid), 0)).where(
        Invoice.state.in_(open_states), Invoice.due_date < today)
    n_over, amt_over = db.execute(overdue_q).one()
    return {"active_subscriptions": active, "mrr": str(q(mrr)), "collected": str(collected), "outstanding": str(owed),
            "overdue": {"count": n_over, "amount": str(amt_over)}}

@app.get("/dashboard/overdue")
def overdue(page: int = 1, size: int = 50, _=Depends(require(Role.ADMIN, Role.STAFF)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Invoice).where(Invoice.state.in_((InvState.CONFIRMED, InvState.PAYMENT_FAILED)),
                      Invoice.due_date < date.today()).order_by(Invoice.due_date)
                      .limit(min(size, 200)).offset((page - 1) * size)).all()   # uses ix_inv_state_due
    return [{"id": i.id, "number": i.number, "due": i.due_date, "balance": str(i.total - i.amount_paid)} for i in rows]


# ======================================================================
# CLI entrypoint for cron jobs
# ======================================================================
if __name__ == "__main__":
    job = sys.argv[1] if len(sys.argv) > 1 else "billing"
    if job == "create_tables":
        Base.metadata.create_all(engine); print("tables created")
    else:
        print({"billing": run_billing, "dunning": run_dunning, "revenue": run_revenue_recognition}[job]())
