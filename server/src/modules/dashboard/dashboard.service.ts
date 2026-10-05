import { SourceModel } from '../sources/source.model.js';
import { ExchangeModel } from '../exchanges/exchange.model.js';
import { TrustPassModel } from '../trust-pass/trust-pass.model.js';
import { AuditEventModel } from '../audit/audit.model.js';

export async function getDashboardSummary() {
  const [exchanges, activeSources, trustPassesIssued, auditEvents] = await Promise.all([
    ExchangeModel.find().sort({ createdAt: -1 }).limit(10).lean().exec(),
    SourceModel.countDocuments({ status: 'ACTIVE' }),
    TrustPassModel.countDocuments(),
    AuditEventModel.find({ eventType: { $in: ['DOWNSTREAM_CONSUMED', 'DOWNSTREAM_DENIED'] } })
      .lean()
      .exec(),
  ]);
  const all = await ExchangeModel.find().lean().exec();
  const averageTrustScore = all.length
    ? Math.round(all.reduce((sum, e) => sum + (e.trustScore ?? 0), 0) / all.length)
    : 0;
  return {
    totalExchanges: all.length,
    allowed: all.filter((e) => e.verification?.decision === 'ALLOW').length,
    review: all.filter((e) => e.verification?.decision === 'REVIEW').length,
    quarantined: all.filter((e) => e.verification?.decision === 'QUARANTINE').length,
    averageTrustScore,
    trustPassesIssued,
    downstreamAllowed: auditEvents.filter((e) => e.eventType === 'DOWNSTREAM_CONSUMED').length,
    downstreamDenied: auditEvents.filter((e) => e.eventType === 'DOWNSTREAM_DENIED').length,
    activeSources,
    recentExchanges: exchanges,
  };
}
