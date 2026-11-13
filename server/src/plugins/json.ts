import type { FastifyInstance } from 'fastify';

/**
 * Accepts an empty body with `Content-Type: application/json` (several HTTP clients
 * send the header on body-less POSTs). Everything else goes through Fastify's
 * default parser, which keeps prototype-poisoning protection.
 */
export function lenientJson(app: FastifyInstance): void {
  const parseJson = app.getDefaultJsonParser('error', 'error');
  app.removeContentTypeParser('application/json');
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    const text = typeof body === 'string' ? body : body.toString('utf8');
    if (text.trim() === '') return done(null, undefined);
    parseJson(req, text, done);
  });
}
