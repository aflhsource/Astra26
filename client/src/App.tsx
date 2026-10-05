import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  ArrowUpRight,
  BadgeCheck,
  Bell,
  Check,
  ChevronRight,
  CircleAlert,
  CircleDashed,
  ClipboardCheck,
  FileCheck2,
  GitBranch,
  LayoutDashboard,
  Menu,
  ScanLine,
  Shield,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  UserRoundCheck,
  X,
  Zap,
} from "lucide-react";
import {
  consumeDownstream,
  getDashboardSummary,
  getExchanges,
  runDemoScenario,
  type DashboardSummary,
  type DemoExchange,
  type DemoRunResult,
  type DemoScenario,
} from "./services/demoApi";
import "./App.css";

type Page =
  | "Overview"
  | "Exchanges"
  | "Trust Chain"
  | "Security Events"
  | "Demo Lab"
  | "Human Review"
  | "Trust Pass"
  | "DOWNTIME-PASS";
type Tone = "allow" | "review" | "quarantine" | "info" | "neutral";
const nav: { label: Page; icon: typeof LayoutDashboard }[] = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Exchanges", icon: Activity },
  { label: "Trust Chain", icon: GitBranch },
  { label: "Security Events", icon: Bell },
  { label: "Demo Lab", icon: Zap },
  { label: "Human Review", icon: UserRoundCheck },
  { label: "Trust Pass", icon: BadgeCheck },
  { label: "DOWNTIME-PASS", icon: ScanLine },
];
const exchanges = [
  ["TX-001", "LAB-A", "DiagnosticReport", "92", "LOW", "ALLOW"],
  ["TX-002", "EHR-A", "Observation", "41", "HIGH", "QUARANTINE"],
  ["TX-003", "LAB-A", "Observation", "74", "MEDIUM", "REVIEW"],
];
const scenarios = [
  [
    "Genuine Exchange",
    "clean",
    "Valid clinical exchange from a registered trusted source.",
  ],
  [
    "Valid Transformation",
    "valid-transformation",
    "Authorized transformation with valid provenance continuity.",
  ],
  ["Tampered Payload", "tamper", "Payload modified after signing."],
  [
    "Replay Attack",
    "replay",
    "Previously accepted transaction submitted again.",
  ],
  [
    "Expired Exchange",
    "expired",
    "Signed clinical exchange whose validity window has expired.",
  ],
  [
    "Unknown Source",
    "unknown-source",
    "Exchange originating from an unregistered source.",
  ],
  [
    "Unauthorized Transformation",
    "unauthorized-transformation",
    "Transformation actor attempts an unauthorized operation.",
  ],
  [
    "Context Mismatch",
    "context-mismatch",
    "Cryptographically valid exchange with inconsistent context.",
  ],
] as const;
const events = [
  [
    "HASH_MISMATCH",
    "Payload integrity verification failed",
    "QUARANTINE",
    "08:42",
  ],
  [
    "REPLAY_DETECTED",
    "Previously processed transaction detected",
    "QUARANTINE",
    "08:17",
  ],
  ["CONTEXT_MISMATCH", "Exchange requires human review", "REVIEW", "Yesterday"],
];
const checks = [
  "Schema Validation",
  "Source Verification",
  "Hash Verification",
  "Signature Verification",
  "Replay Protection",
  "Freshness",
  "Provenance",
  "Context",
  "Risk Analysis",
  "Policy",
];
const metricItems: { label: string; icon: typeof Activity }[] = [
  { label: "Exchanges", icon: Activity },
  { label: "Allowed", icon: ShieldCheck },
  { label: "Review", icon: ClipboardCheck },
  { label: "Quarantined", icon: ShieldX },
];

function Badge({ tone, children }: { tone: Tone; children: string }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
function payloadDescription(exchange: DemoExchange): string {
  const payload = exchange.payload as { data?: Record<string, unknown> };
  const data = payload.data ?? {};
  if (typeof data.medication === "string") {
    const adjunct = data.adjunctMedication
      ? ` · ${String(data.adjunctMedication)} ${String(data.adjunctDose ?? "")}`
      : "";
    return `${data.medication} · ${String(data.dose ?? "dose unavailable")} · ${String(data.route ?? "route unavailable")}${adjunct}`;
  }
  if (typeof data.test === "string") {
    return `${data.test} · ${String(data.value ?? "value unavailable")} ${String(data.unit ?? "")}`.trim();
  }
  return "Synthetic clinical payload";
}
function reasonExplanation(exchange: DemoExchange): string {
  const reason = exchange.verification.reasonCodes[0];
  const explanations: Record<string, string> = {
    HASH_MISMATCH:
      "The received payload no longer matches its declared SHA-256 digest.",
    INVALID_SIGNATURE:
      "The signed exchange cannot be verified against the registered source key.",
    REPLAY_DETECTED:
      "This transaction, nonce or sequence has already been processed.",
    EXPIRED_MESSAGE: "The exchange arrived outside its signed validity window.",
    UNKNOWN_SOURCE:
      "The sender is not registered in the TRUST-PASS source registry.",
    UNAUTHORIZED_TRANSFORMATION:
      "The registered transformer is not authorized for this operation.",
    PROVENANCE_FAILURE: "The origin or transformation chain cannot be trusted.",
    CONTEXT_MISMATCH:
      "The signed context does not match the patient or encounter in the payload.",
  };
  return reason
    ? (explanations[reason] ?? `Backend reported ${reason}.`)
    : "All verification gates passed for this exchange.";
}
function Header({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
function Metrics({ summary }: { summary: DashboardSummary | null }) {
  const values = summary
    ? [
        summary.totalExchanges,
        summary.allowed,
        summary.review,
        summary.quarantined,
      ]
    : ["—", "—", "—", "—"];
  return (
    <div className="metrics">
      {metricItems.map(({ label, icon: Icon }, index) => (
        <div className="metric" key={label}>
          <span>
            <Icon size={15} />
            {label}
          </span>
          <strong>{values[index]}</strong>
          <small>
            {summary ? "Live backend summary" : "Loading backend data"}
          </small>
        </div>
      ))}
    </div>
  );
}
function Score({
  compact = false,
  value = 92,
}: {
  compact?: boolean;
  value?: number;
}) {
  return (
    <div className={`score ${compact ? "compact" : ""}`}>
      <div className="ring">
        <b>{value}</b>
        <small>/100</small>
      </div>
      <div>
        <span className="eyebrow">Security Trust Score</span>
        <strong className="low">
          <i />
          LOW RISK
        </strong>
        {!compact && (
          <p>
            Based on cryptographic integrity, provenance, freshness, source
            authorization and security evidence.
          </p>
        )}
      </div>
    </div>
  );
}
function Table({
  select,
  rows = exchanges,
}: {
  select: () => void;
  rows?: readonly (readonly string[])[];
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Transaction</th>
            <th>Source</th>
            <th>Resource</th>
            <th>Trust</th>
            <th>Risk</th>
            <th>Decision</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map(([id, source, resource, trust, risk, decision]) => (
            <tr key={id} onClick={select}>
              <td className="mono strong">{id}</td>
              <td>{source}</td>
              <td>{resource}</td>
              <td className="strong">{trust}</td>
              <td>
                <Badge
                  tone={
                    risk === "LOW"
                      ? "allow"
                      : risk === "MEDIUM"
                        ? "review"
                        : "quarantine"
                  }
                >
                  {risk}
                </Badge>
              </td>
              <td>
                <Badge
                  tone={
                    decision === "ALLOW"
                      ? "allow"
                      : decision === "REVIEW"
                        ? "review"
                        : "quarantine"
                  }
                >
                  {decision}
                </Badge>
              </td>
              <td>
                <ChevronRight size={16} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function Overview({ go }: { go: (page: Page) => void }) {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  useEffect(() => {
    const refresh = () =>
      void getDashboardSummary()
        .then(setSummary)
        .catch(() => setSummary(null));
    refresh();
    window.addEventListener("trust-pass:refresh", refresh);
    return () => window.removeEventListener("trust-pass:refresh", refresh);
  }, []);
  return (
    <>
      <Header
        eyebrow="Security Overview"
        title="Clinical Data Trust"
        description="Monitor, verify and enforce trust across healthcare data exchanges."
        action={
          <button className="ghost" onClick={() => go("Demo Lab")}>
            <Zap size={15} />
            Open simulator
          </button>
        }
      />
      <Metrics summary={summary} />
      <section className="posture panel">
        <div className="section-top">
          <div>
            <span className="eyebrow">Current Security Posture</span>
            <h2>Evidence, made legible.</h2>
          </div>
          <span className="live">
            <i />
            Live monitoring
          </span>
        </div>
        <Score value={summary?.averageTrustScore ?? 0} />
      </section>
      <section>
        <div className="section-head">
          <div>
            <span className="eyebrow">Exchange activity</span>
            <h2>Recent Exchanges</h2>
          </div>
          <button className="link" onClick={() => go("Exchanges")}>
            View all <ArrowUpRight size={15} />
          </button>
        </div>
        <Table select={() => go("Exchanges")} />
      </section>
    </>
  );
}
function Exchanges({ go }: { go: (page: Page) => void }) {
  const [rows, setRows] = useState<readonly (readonly string[])[]>([]);
  useEffect(() => {
    const refresh = () =>
      void getExchanges()
        .then((items) =>
          setRows(
            items.map((item) => [
              item.transactionId,
              item.source.sourceId,
              item.resourceType,
              String(item.trustScore),
              item.riskLevel,
              item.verification.decision,
            ]),
          ),
        )
        .catch(() => setRows([]));
    refresh();
    window.addEventListener("trust-pass:refresh", refresh);
    return () => window.removeEventListener("trust-pass:refresh", refresh);
  }, []);
  return (
    <>
      <Header
        eyebrow="Exchange Monitor"
        title="Exchanges"
        description="Every handoff, verified at the trust boundary."
        action={
          <button className="ghost">
            <SlidersHorizontal size={15} />
            Filters
          </button>
        }
      />
      <div className="notice panel">
        <div>
          <span className="eyebrow">Backend connection</span>
          <strong>Ready for live exchange data</strong>
        </div>
        <Badge tone="info">API READY</Badge>
      </div>
      <section>
        <div className="section-head">
          <div>
            <span className="eyebrow">All activity</span>
            <h2>Clinical exchanges</h2>
          </div>
          <small>Demo presentation data</small>
        </div>
        <Table rows={rows} select={() => go("Trust Chain")} />
      </section>
    </>
  );
}
function Details() {
  return (
    <>
      <Header
        eyebrow="Exchange Details"
        title="TX-001"
        description="A signed clinical exchange from LAB-A, verified at the gateway."
        action={<Badge tone="allow">ALLOW</Badge>}
      />
      <div className="two-col">
        <section className="panel">
          <span className="eyebrow">Exchange metadata</span>
          <div className="meta">
            {[
              ["Source", "LAB-A"],
              ["Resource type", "DiagnosticReport"],
              ["Patient reference", "PAT-1001"],
              ["Encounter", "ENC-1001"],
              ["Timestamp", "05 Oct 2026 · 08:42 UTC"],
            ].map(([a, b]) => (
              <div key={a}>
                <span>{a}</span>
                <b
                  className={
                    a.includes("reference") || a === "Encounter" ? "mono" : ""
                  }
                >
                  {b}
                </b>
              </div>
            ))}
          </div>
          <Score compact />
        </section>
        <section className="panel">
          <div className="section-head">
            <div>
              <span className="eyebrow">Evidence chain</span>
              <h2>Verification</h2>
            </div>
            <FileCheck2 size={19} />
          </div>
          <div className="timeline">
            {checks.map((item) => (
              <div key={item}>
                <i>
                  <Check size={13} />
                </i>
                <span>
                  <b>{item}</b>
                  <small>Passed</small>
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}
function Chain() {
  return (
    <>
      <Header
        eyebrow="Provenance"
        title="Trust Chain"
        description="Follow how clinical data moved between systems."
      />
      <section className="panel chain">
        <div className="chain-flow">
          <Node id="LAB-A" role="Source" />
          <em>›</em>
          <Node id="INTEGRATION-A" role="Transformer · NORMALIZE_UNIT" />
          <em>›</em>
          <Node id="CLINICAL-CONSUMER" role="Consumer" />
        </div>
        <div className="transform">
          <div>
            <span className="eyebrow">Transformation evidence</span>
            <b>NORMALIZE_UNIT</b>
          </div>
          <span>
            Input <code>e4a8…92b1</code>
          </span>
          <span>
            Output <code>7c1f…a014</code>
          </span>
        </div>
      </section>
    </>
  );
}
function Node({ id, role }: { id: string; role: string }) {
  return (
    <div className="node">
      <div>
        <GitBranch size={19} />
      </div>
      <span className="eyebrow">{role}</span>
      <b>{id}</b>
      <small>08:41:28 UTC</small>
    </div>
  );
}
function Events() {
  return (
    <>
      <Header
        eyebrow="Detection Log"
        title="Security Events"
        description="A concise record of integrity and trust decisions."
      />
      <div className="events">
        {events.map(([code, detail, decision, time]) => (
          <div className="event" key={code}>
            <i>
              <CircleAlert size={18} />
            </i>
            <div>
              <b>{code}</b>
              <span>{detail}</span>
            </div>
            <Badge tone={decision === "REVIEW" ? "review" : "quarantine"}>
              {decision}
            </Badge>
            <time>{time}</time>
            <ChevronRight size={16} />
          </div>
        ))}
      </div>
    </>
  );
}
function DemoLab({
  selected,
  setSelected,
}: {
  selected: number;
  setSelected: (n: number) => void;
}) {
  const [result, setResult] = useState<DemoRunResult | null>(null);
  const [running, setRunning] = useState(false);
  const [downstream, setDownstream] = useState<{
    allowed: boolean;
    message: string;
  } | null>(null);
  const [downstreamChecking, setDownstreamChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (index: number) => {
    setSelected(index);
    setRunning(true);
    setDownstream(null);
    setError(null);
    try {
      setResult(await runDemoScenario(scenarios[index][1] as DemoScenario));
      window.dispatchEvent(new Event("trust-pass:refresh"));
    } catch (requestError) {
      setResult(null);
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Backend unavailable",
      );
    } finally {
      setRunning(false);
    }
  };
  const exchange = result?.exchange;
  const tone: Tone =
    exchange?.verification.decision === "ALLOW"
      ? "allow"
      : exchange?.verification.decision === "REVIEW"
        ? "review"
        : "quarantine";
  const testDownstream = async () => {
    if (!exchange) return;
    setDownstreamChecking(true);
    setDownstream(null);
    try {
      await consumeDownstream({
        transactionId: exchange.transactionId,
        trustPassId: exchange.trustPassId ?? "",
        payload: exchange.payload,
        audience: exchange.context.audience,
        purpose: exchange.context.purpose,
      });
      setDownstream({
        allowed: true,
        message: "HTTP 200 · Downstream consumption allowed",
      });
    } catch (requestError) {
      setDownstream({
        allowed: false,
        message:
          requestError instanceof Error
            ? `${requestError.message} · HTTP 403`
            : "HTTP 403 · Downstream blocked",
      });
    } finally {
      setDownstreamChecking(false);
    }
  };
  return (
    <>
      <Header
        eyebrow="Synthetic Data · Safe Demo Environment"
        title="TRUST-PASS Demo Lab"
        description="Controlled synthetic scenarios for verification, attack detection and downstream enforcement."
        action={
          <span className="synthetic">
            <CircleDashed size={14} />
            Backend-driven
          </span>
        }
      />
      <div className="sim-grid">
        <section className="panel scenarios">
          <span className="eyebrow">Run a real scenario</span>
          {scenarios.map((item, i) => (
            <button
              className={selected === i ? "selected" : ""}
              onClick={() => void run(i)}
              disabled={running}
              key={item[0]}
            >
              <small>0{i + 1}</small>
              <span>
                <b>{item[0]}</b>
                <em>{item[2]}</em>
              </span>
              <ChevronRight size={15} />
            </button>
          ))}
        </section>
        <section className="panel result">
          <div className="result-head">
            <span className="eyebrow">Simulation result</span>
            {running ? (
              <span className="processed">Running verification…</span>
            ) : result ? (
              <span className="processed">
                <Check size={13} />
                Backend response received
              </span>
            ) : (
              <span className="processed">Waiting for a scenario</span>
            )}
          </div>
          {error ? (
            <div className="demo-error">
              <b>BACKEND UNAVAILABLE</b>
              <p>{error}</p>
              <small>Check that the backend is running on port 5001.</small>
            </div>
          ) : exchange ? (
            <>
              <div className="payload-preview">
                <div>
                  <span className="eyebrow">Synthetic clinical payload</span>
                  <b>{payloadDescription(exchange)}</b>
                </div>
                <span className="mono">
                  {exchange.context.patientRef} ·{" "}
                  {exchange.context.encounterRef}
                </span>
              </div>
              {!downstream && !downstreamChecking && (
                <div className="preflight-result">
                  <CircleDashed size={23} />
                  <b>Verification complete</b>
                  <span>
                    Test downstream to reveal the final decision and enforcement
                    result.
                  </span>
                </div>
              )}
              {downstream && (
                <>
                  <div className="decision">
                    <span className="eyebrow">Decision</span>
                    <b className={`decision-${tone}`}>
                      {exchange.verification.decision}
                    </b>
                    <small>
                      {exchange.verification.reasonCodes.join(", ") ||
                        "No security findings"}
                    </small>
                  </div>
                  <div className="result-stats">
                    <div>
                      <span>Trust Score</span>
                      <b>{exchange.trustScore}</b>
                    </div>
                    <div>
                      <span>Risk</span>
                      <b>{exchange.riskLevel}</b>
                    </div>
                    <div>
                      <span>Trust Pass</span>
                      <b>{exchange.trustPassId ? "ISSUED" : "NOT ISSUED"}</b>
                    </div>
                  </div>
                </>
              )}
              <div className="demo-result-actions">
                <button className="dark" onClick={() => void testDownstream()}>
                  Test downstream <ArrowUpRight size={15} />
                </button>
              </div>
              {downstreamChecking && (
                <div className="downstream-result downstream-checking">
                  <span className="eyebrow">Downstream consumption</span>
                  <b>Verifying Trust Pass…</b>
                </div>
              )}
              {downstream && (
                <div className="reason-explanation">
                  <span className="eyebrow">Why this result</span>
                  <p>{reasonExplanation(exchange)}</p>
                </div>
              )}
              {downstream && (
                <div
                  className={`downstream-result ${downstream.allowed ? "downstream-allowed" : "downstream-blocked"}`}
                >
                  <span className="eyebrow">Downstream consumption</span>
                  <b>
                    {downstream.allowed
                      ? "✓ DOWNSTREAM ALLOWED"
                      : "✕ DOWNSTREAM BLOCKED"}
                  </b>
                  <small>{downstream.message}</small>
                </div>
              )}
              <div className="coming-soon-panel">
                <div>
                  <span className="eyebrow">AI Review</span>
                  <b>Coming soon</b>
                </div>
                <span>
                  Security evidence review will be added as a separate advisory
                  layer.
                </span>
              </div>
              {result.attempts && (
                <div className="attempts">
                  <span>Replay attempts</span>
                  {result.attempts.map((attempt, index) => (
                    <b key={`${attempt.transactionId}-${index}`}>
                      {index + 1}. {attempt.verification.decision}{" "}
                      {attempt.verification.reasonCodes.length > 0 &&
                        `· ${attempt.verification.reasonCodes.join(", ")}`}
                    </b>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="empty-demo">
              <CircleDashed size={25} />
              <p>
                Select a scenario to send a real request through the backend
                verification pipeline.
              </p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
function Review() {
  return (
    <>
      <Header
        eyebrow="Decision Queue"
        title="Human Review"
        description="Resolve policy-level exceptions with a clear evidence trail."
      />
      <section className="review-layout">
        <div className="panel review-card">
          <div className="review-label">
            <CircleAlert size={15} />
            Review required
          </div>
          <h2>Context mismatch</h2>
          <div className="review-meta">
            <div>
              <span>Transaction</span>
              <b className="mono">TX-003</b>
            </div>
            <div>
              <span>Source</span>
              <b>LAB-A</b>
            </div>
            <div>
              <span>Risk</span>
              <Badge tone="review">HIGH</Badge>
            </div>
          </div>
          <div className="evidence">
            <span className="eyebrow">Security evidence</span>
            <p>
              Cryptographic integrity is valid. Payload encounter does not match
              the declared exchange context.
            </p>
            <code>CONTEXT_MISMATCH</code>
          </div>
          <div className="review-actions">
            <button className="outline">
              <X size={15} />
              Reject
            </button>
            <button className="dark">
              <Check size={15} />
              Approve
            </button>
          </div>
        </div>
        <aside>
          <span className="eyebrow">Reviewer guidance</span>
          <p>
            Human approval can resolve a review state, but never overrides a
            hard cryptographic failure.
          </p>
        </aside>
      </section>
    </>
  );
}
function Pass() {
  return (
    <>
      <Header
        eyebrow="Authorization Artifact"
        title="Trust Pass"
        description="A scoped, signed authorization for downstream use."
      />
      <div className="pass-layout">
        <div className="pass-card">
          <div className="pass-head">
            <strong>
              <span>
                <ShieldCheck size={19} />
              </span>
              TRUST-PASS
            </strong>
            <Badge tone="allow">VERIFIED</Badge>
          </div>
          <div className="pass-score">
            <span className="eyebrow">Security trust score</span>
            <b>92</b>
            <small>Cryptographically verified</small>
          </div>
          <div className="pass-meta">
            {[
              ["Pass ID", "TP-8A91F2C0"],
              ["Transaction", "TX-001"],
              ["Decision", "ALLOW"],
              ["Audience", "CLINICAL-CONSUMER"],
              ["Purpose", "Clinical Decision Support"],
              ["Expires", "05 Oct 2026 · 08:47 UTC"],
            ].map(([a, b]) => (
              <div key={a}>
                <span>{a}</span>
                <b
                  className={
                    a.includes("ID") || a === "Transaction" ? "mono" : ""
                  }
                >
                  {b}
                </b>
              </div>
            ))}
          </div>
          <footer>
            <BadgeCheck size={17} />
            Signature verified <small>TP1 · Ed25519</small>
          </footer>
        </div>
        <div className="pass-notes">
          <div>
            <span className="eyebrow">Bound claims</span>
            <p>
              Payload, transaction, audience and purpose are cryptographically
              bound to this pass.
            </p>
          </div>
          <div>
            <span className="eyebrow">Downstream rule</span>
            <b>No Trust Pass · No downstream use</b>
          </div>
        </div>
      </div>
    </>
  );
}
function Downtime() {
  return (
    <>
      <Header
        eyebrow="Continuity Mode"
        title="DOWNTIME-PASS"
        description="Offline verification for healthcare continuity."
      />
      <div className="downtime">
        <section className="panel drop">
          <div>
            <ScanLine size={29} />
            <span>TP1</span>
          </div>
          <h2>Drop or scan a Safety Card</h2>
          <p>Verify a signed card locally, without the gateway.</p>
          <button className="dark">
            <ScanLine size={15} />
            Verify locally
          </button>
          <small>
            <Check size={14} />
            No backend required
            <br />
            <Check size={14} />
            No database required
            <br />
            <Check size={14} />
            No internet required
          </small>
        </section>
        <section className="panel offline">
          <Badge tone="allow">OFFLINE VERIFIED</Badge>
          <h2>Ready for local verification</h2>
          <p>
            Safety Card results will appear here after a TP1 payload is
            provided.
          </p>
          <div>
            <span>
              <CircleDashed size={15} />
              Signature verification
            </span>
            <span>
              <CircleDashed size={15} />
              Trust root verification
            </span>
            <span>
              <CircleDashed size={15} />
              Expiry validation
            </span>
          </div>
        </section>
      </div>
    </>
  );
}
function App() {
  const [page, setPage] = useState<Page>("Overview");
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState(0);
  const go = (next: Page) => {
    setPage(next);
    setOpen(false);
  };
  const content =
    page === "Overview" ? (
      <Overview go={go} />
    ) : page === "Exchanges" ? (
      <Exchanges go={go} />
    ) : page === "Trust Chain" ? (
      <Chain />
    ) : page === "Security Events" ? (
      <Events />
    ) : page === "Demo Lab" ? (
      <DemoLab selected={selected} setSelected={setSelected} />
    ) : page === "Human Review" ? (
      <Review />
    ) : page === "Trust Pass" ? (
      <Pass />
    ) : page === "DOWNTIME-PASS" ? (
      <Downtime />
    ) : (
      <Details />
    );
  return (
    <div className="app">
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <span>
            <Shield size={17} />
          </span>
          <div>
            <b>TRUST-PASS</b>
            <small>Clinical Data Trust Layer</small>
          </div>
        </div>
        <nav>
          {nav.map(({ label, icon: Icon }) => (
            <button
              className={page === label ? "active" : ""}
              key={label}
              onClick={() => go(label)}
            >
              <Icon size={17} />
              {label}
              {label === "Human Review" && <i />}
            </button>
          ))}
        </nav>
        <div className="side-footer">
          <span className="eyebrow">System Status</span>
          <b>
            <i />
            Operational
          </b>
          <small>Gateway · TP-1.0</small>
        </div>
      </aside>
      <main>
        <header className="top">
          <button
            className="mobile"
            onClick={() => setOpen(!open)}
            aria-label="Toggle navigation"
          >
            <Menu size={20} />
          </button>
          <div className="crumb">
            <span>TRUST-PASS</span>
            <ChevronRight size={13} />
            <b>{page}</b>
          </div>
          <div className="top-right">
            <span className="env">
              <i />
              Synthetic environment
            </span>
            <button className="icon" aria-label="Notifications">
              <Bell size={17} />
            </button>
            <span className="avatar">SR</span>
          </div>
        </header>
        <div className="content">{content}</div>
      </main>
    </div>
  );
}
export default App;
