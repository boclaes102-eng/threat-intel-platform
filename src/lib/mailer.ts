import nodemailer from 'nodemailer';
import { env } from './env';
import { logger } from './logger';

const transporter = env.SMTP_HOST
  ? nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_PORT === 465,
      auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined,
    })
  : null;

export interface AlertEmailPayload {
  to: string;
  title: string;
  severity: string;
  assetValue?: string;
  details: Record<string, unknown>;
}

export async function sendAlertEmail(payload: AlertEmailPayload): Promise<void> {
  if (!transporter) {
    logger.debug({ to: payload.to, title: payload.title }, 'Email skipped — SMTP not configured');
    return;
  }

  const severityColor: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#2563eb',
    info: '#6b7280',
  };
  const color = severityColor[payload.severity] ?? '#6b7280';

  const html = `
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
      <div style="background:${color};color:#fff;padding:16px 24px;border-radius:8px 8px 0 0">
        <h2 style="margin:0">${payload.title}</h2>
        <span style="font-size:12px;text-transform:uppercase;letter-spacing:1px">${payload.severity}</span>
      </div>
      <div style="background:#f9fafb;padding:24px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
        ${payload.assetValue ? `<p><strong>Asset:</strong> <code>${payload.assetValue}</code></p>` : ''}
        <pre style="background:#1e293b;color:#e2e8f0;padding:16px;border-radius:6px;overflow:auto;font-size:13px">${JSON.stringify(payload.details, null, 2)}</pre>
        <hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0">
        <p style="color:#9ca3af;font-size:12px">Threat Intelligence Platform &mdash; automated alert</p>
      </div>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: env.SMTP_FROM,
      to: payload.to,
      subject: `[${payload.severity.toUpperCase()}] ${payload.title}`,
      html,
    });
    logger.info({ to: payload.to, title: payload.title }, 'Alert email sent');
  } catch (err) {
    logger.error({ err, to: payload.to }, 'Failed to send alert email');
  }
}
