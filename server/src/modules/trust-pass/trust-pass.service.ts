import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { env } from '../../config/env.js';
import { sha256 } from '../crypto/hash.js';
import { sign, verify } from '../crypto/signature.js';
import { TrustPassModel, type TrustPassDocument } from './trust-pass.model.js';
import type { TrustPassClaims, TrustPassRecord } from './trust-pass.types.js';
import type { ExchangeRecord } from '../exchanges/exchange.types.js';

const POLICY_VERSION = 'TP-POLICY-1.0';

export function trustPassClaims(pass: TrustPassRecord | TrustPassDocument): TrustPassClaims {
  const plainPass = ('toObject' in pass ? pass.toObject() : pass) as TrustPassRecord & {
    _id?: unknown;
  };
  const {
    _id: _mongoId,
    signature,
    status: _status,
    createdAt: _createdAt,
    updatedAt: _updatedAt,
    ...claims
  } = plainPass;
  void signature;
  void _mongoId;
  void _status;
  void _createdAt;
  void _updatedAt;
  return claims;
}

export async function issueTrustPass(exchange: ExchangeRecord): Promise<TrustPassDocument> {
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + env.TRUST_PASS_TTL_MS).toISOString();
  const claims: TrustPassClaims = {
    passId: `PASS-${randomUUID()}`,
    transactionId: exchange.transactionId,
    decision: 'ALLOW',
    trustScore: exchange.trustScore,
    payloadHash: exchange.payloadHash,
    evidenceDigest: sha256({
      verification: exchange.verification,
      securityAssessment: exchange.securityAssessment,
      resourceRisk: exchange.resourceRisk,
    }),
    policyVersion: POLICY_VERSION,
    audience: exchange.context.audience,
    purpose: exchange.context.purpose,
    issuedAt,
    expiresAt,
    issuer: 'TRUST-PASS-GATEWAY',
    keyId: env.GATEWAY_KEY_ID,
  };
  const privateKeyPath = resolve(process.cwd(), env.GATEWAY_PRIVATE_KEY_PATH);
  if (!existsSync(privateKeyPath)) throw new Error('Gateway signing key is unavailable');
  const signature = sign(claims, createPrivateKey(readFileSync(privateKeyPath)));
  return TrustPassModel.create({ ...claims, signature, status: 'ACTIVE' });
}

export async function getTrustPassByTransactionId(
  transactionId: string,
): Promise<TrustPassDocument | null> {
  return TrustPassModel.findOne({ transactionId }).exec();
}

export async function getTrustPassById(passId: string): Promise<TrustPassDocument | null> {
  return TrustPassModel.findOne({ passId }).exec();
}

export async function revokeTrustPass(transactionId: string): Promise<TrustPassDocument | null> {
  return TrustPassModel.findOneAndUpdate(
    { transactionId },
    { $set: { status: 'REVOKED' } },
    { returnDocument: 'after' },
  ).exec();
}

export interface ConsumptionInput {
  transactionId: string;
  trustPassId: string;
  payload: unknown;
  audience: string;
  purpose: string;
}

export interface ConsumptionResult {
  allowed: boolean;
  reasonCode?: string;
  pass?: TrustPassRecord;
}

export async function verifyForConsumption(
  input: ConsumptionInput,
  exchange: ExchangeRecord,
): Promise<ConsumptionResult> {
  const pass = await TrustPassModel.findOne({
    passId: input.trustPassId,
    transactionId: input.transactionId,
  }).exec();
  if (!pass) return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  const publicKeyPath = resolve(process.cwd(), env.GATEWAY_PUBLIC_KEY_PATH);
  if (!existsSync(publicKeyPath)) return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  const claims = trustPassClaims(pass);
  if (!verify(claims, pass.signature, createPublicKey(readFileSync(publicKeyPath))))
    return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  if (pass.status === 'REVOKED') return { allowed: false, reasonCode: 'TRUST_PASS_REVOKED' };
  if (pass.expiresAt <= new Date().toISOString())
    return { allowed: false, reasonCode: 'TRUST_PASS_EXPIRED' };
  if (pass.decision !== 'ALLOW' || exchange.verification.decision !== 'ALLOW')
    return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  if (input.audience !== pass.audience || input.audience !== exchange.context.audience)
    return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  if (input.purpose !== pass.purpose || input.purpose !== exchange.context.purpose)
    return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  if (sha256(input.payload) !== pass.payloadHash || pass.payloadHash !== exchange.payloadHash)
    return { allowed: false, reasonCode: 'TRUST_PASS_INVALID' };
  return { allowed: true, pass: pass.toObject() as TrustPassRecord };
}
