import { createReadStream } from 'node:fs';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AGENT_ARCH, AGENT_OS, type AgentBinaries } from '../agent/binaries.ts';
import { notFound, parse } from '../http.ts';

const Params = z.object({ os: z.enum(AGENT_OS), arch: z.enum(AGENT_ARCH) });

export function downloadRoutes(app: FastifyInstance, binaries: AgentBinaries) {
  // Public – agent binaries are not secret and are needed before enrolment.
  app.get('/agent-downloads', async () => {
    const { version, items } = await binaries.scan();
    return {
      version,
      items: items.map(({ os, arch, sizeBytes, sha256 }) => ({ os, arch, version, sizeBytes, sha256, url: `/api/v1/agent-downloads/${os}/${arch}` })),
    };
  });

  app.get('/agent-downloads/:os/:arch', async (req, reply) => {
    const { os, arch } = parse(Params, req.params);
    const { binary } = await binaries.find(os, arch);
    if (!binary) throw notFound(`Agent binary for ${os}/${arch}`);
    const filename = `opencm-agent${os === 'windows' ? '.exe' : ''}`;
    return reply
      .header('content-type', 'application/octet-stream')
      .header('content-length', binary.sizeBytes)
      .header('content-disposition', `attachment; filename="${filename}"`)
      .header('x-checksum-sha256', binary.sha256)
      .send(createReadStream(binary.path));
  });
}
