import { writeFileSync, mkdirSync } from 'fs';
import { z } from 'zod';
import {
  SignatureEnvelopeSchema,
  AttestationSchema,
  IntegritySchema,
  PermissionsSchema,
  RevocationListSchema,
} from '../packages/core/src/schemas';

const schemasDir = './schemas';
mkdirSync(schemasDir, { recursive: true });

const schemas = {
  'signature.schema.json': SignatureEnvelopeSchema,
  'attestation.schema.json': AttestationSchema,
  'integrity.schema.json': IntegritySchema,
  'permissions.schema.json': PermissionsSchema,
  'revocation.schema.json': RevocationListSchema,
};

for (const [filename, zodSchema] of Object.entries(schemas)) {
  const jsonSchema = z.toJSONSchema(zodSchema) as {
    $schema?: string;
    $id?: string;
    title?: string;
  };

  // Add spec-specific metadata
  jsonSchema.$schema = 'https://json-schema.org/draft/2020-12/schema';
  jsonSchema.$id = `https://haldir.ai/schemas/${filename}`;
  jsonSchema.title = `ASAF ${filename.replace('.schema.json', '')}`;

  writeFileSync(
    `${schemasDir}/${filename}`,
    JSON.stringify(jsonSchema, null, 2) + '\n'
  );
}

console.log('✓ Generated 5 JSON Schemas from Zod');
