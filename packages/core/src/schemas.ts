import { z } from 'zod';
import {
  SUPPORTED_SIGNATURE_VERSIONS,
  SUPPORTED_ATTESTATION_VERSIONS,
  SUPPORTED_INTEGRITY_VERSIONS,
  SUPPORTED_PERMISSIONS_VERSIONS,
  SUPPORTED_REVOCATION_VERSIONS,
  HALDIR_PAYLOAD_TYPE,
} from './types.js';

export const HashStringSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, 'Must be sha256:<64 lowercase hex chars>');

export const DSSESignatureSchema = z.object({
  keyid: z.string().min(1),
  sig: z.string().min(1),
});

export const SignatureEnvelopeSchema = z.object({
  schema_version: z.enum(SUPPORTED_SIGNATURE_VERSIONS),
  payloadType: z.literal(HALDIR_PAYLOAD_TYPE),
  payload: z.string().min(1),
  signatures: z.array(DSSESignatureSchema).min(1),
});

export const AttestationSchema = z
  .object({
    schema_version: z.enum(SUPPORTED_ATTESTATION_VERSIONS),
    skill: z.object({
      name: z.string().min(1),
      version: z.string().min(1),
      type: z.string().min(1),
    }),
    integrity_hash: HashStringSchema,
    permissions_hash: HashStringSchema,
    signed_at: z.string().datetime(),
    _critical: z.array(z.string()).optional(),
  })
  .passthrough();

export const IntegritySchema = z.object({
  schema_version: z.enum(SUPPORTED_INTEGRITY_VERSIONS),
  algorithm: z.literal('sha256'),
  files: z.record(z.string(), HashStringSchema),
  generated_at: z.string().datetime(),
});

export const PermissionsSchema = z
  .object({
    schema_version: z.enum(SUPPORTED_PERMISSIONS_VERSIONS),
    declared: z
      .object({
        filesystem: z
          .object({
            read: z.array(z.string()).optional(),
            write: z.array(z.string()).optional(),
          })
          .passthrough()
          .optional(),
        network: z.union([z.string(), z.array(z.string())]).optional(),
        exec: z.array(z.string()).optional(),
        agent_capabilities: z
          .object({
            memory_read: z.boolean().optional(),
            memory_write: z.boolean().optional(),
            spawn_agents: z.boolean().optional(),
            modify_system_prompt: z.boolean().optional(),
          })
          .passthrough()
          .optional(),
      })
      .passthrough(),
  })
  .passthrough();

export const RevocationEntrySchema = z.object({
  name: z.string().min(1),
  versions: z.array(z.string().min(1)).min(1),
  revoked_at: z.string().datetime(),
  reason: z.string().min(1),
  severity: z.string().min(1),
});

export const RevocationListSchema = z.object({
  schema_version: z.enum(SUPPORTED_REVOCATION_VERSIONS),
  sequence_number: z.number().int().positive(),
  issued_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  next_update: z.string().datetime(),
  entries: z.array(RevocationEntrySchema),
  signature: z.object({
    keyid: z.string().min(1),
    sig: z.string().min(1),
  }),
});
