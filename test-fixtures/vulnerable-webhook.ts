// Test Fixture: Vulnerable Webhook Dispatcher
// Target for AEGIS AST Taint Localization Engine: CWE-918 SSRF

import { Request, Response } from 'express';

// Simulated axios client
const axios = {
  get: async (url: string) => ({ status: 200, data: 'OK' })
};

export async function dispatchWebhookHandler(req: Request, res: Response) {
  // Source: Untrusted target URL from request payload
  const { webhookUrl } = req.body;

  // VULNERABLE SINK: Unvalidated user URL forwarded directly to HTTP client
  // Allows access to AWS metadata service (169.254.169.254) or localhost
  const response = await axios.get(webhookUrl);

  return res.json({ dispatched: true, status: response.status });
}

export async function safeWebhookHandler(req: Request, res: Response) {
  const { webhookUrl } = req.body;
  const parsed = new URL(webhookUrl);

  // Safe handler: Protocol and hostname allowlist validation
  const ALLOWED_HOSTS = ['hooks.slack.com', 'api.github.com'];
  if (!ALLOWED_HOSTS.includes(parsed.hostname) || parsed.protocol !== 'https:') {
    return res.status(403).json({ error: 'Prohibited target host' });
  }

  const sanitizedTargetUrl = `https://${parsed.hostname}${parsed.pathname}`;
  const response = await axios.get(sanitizedTargetUrl);
  return res.json({ dispatched: true, status: response.status });
}
