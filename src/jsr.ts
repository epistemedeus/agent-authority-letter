/** Verify immutable company letter terms and check their current status. @module */
import { createVerifier as create } from './verify.mjs';

/** The version 1 manifest carried by the attached JWS. */
export interface AuthorityManifest {
  schema: 'einllc.agent-authority.v1';
  id: string;
  check: string;
  issuer: { legalName: string; jurisdiction?: string; entityType: string; entityNumber?: string };
  companyProvenance?: { kind: 'formed-through-ein' } | { kind: 'signer-stated'; emailDomain?: string };
  signedBy: { name: string; title: string; at: string };
  agent: { name: string; reference: string; operator?: string; role: 'agent'; isOwnerOrOfficer: false; maySign: false };
  may: Array<'quote' | 'order' | 'sell' | 'pay' | 'refund' | 'terms' | 'correspond' | 'documents'>;
  limits: { currency: 'USD'; perTransaction: number; perMonth: number | null };
  counterparties: 'any' | string[];
  needsPerson: Array<'contract' | 'account' | 'hire' | 'over-limit' | 'new-counterparty'>;
  validFrom: string;
  validUntil: string;
  grantsAccessToMoneyOrAccounts: false;
}

/** Trust settings for a verifier instance. */
export interface VerifierOptions {
  /** Trusted HTTPS origin for live status and remote JWKS. */
  origin?: string;
  /** Pinned public JWKS object. Required in offline mode and validated at runtime. */
  jwks?: unknown;
  /** Check integrity only and return unknown current status. */
  offline?: boolean;
  /** Require the synthetic fixture signature profile. */
  fixture?: boolean;
  /** Permit explicit loopback HTTP for local tests. */
  allowLoopback?: boolean;
  /** Clock in Unix milliseconds. Defaults to Date.now. */
  clock?: () => number;
}

/** Integrity, schema, and live status are separate parts of the decision. */
export interface LetterDecision {
  signature: 'valid' | 'invalid' | 'unknown';
  schema: 'valid' | 'invalid' | 'unknown';
  currentStatus: 'active' | 'pending' | 'expired' | 'revoked' | 'replaced' | 'unknown';
  usable: boolean;
  fixture: boolean;
  reason: string;
  manifest?: AuthorityManifest;
}

/** Verifies one compact attached JWS. */
export type VerifyLetter = (token: string) => Promise<LetterDecision>;

type CreateVerifier = (options?: VerifierOptions) => VerifyLetter;

/** Create a verifier with a caller-pinned origin or public JWKS. */
export const createVerifier: CreateVerifier = create as CreateVerifier;
