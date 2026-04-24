import { Resend } from 'resend';
import { env } from './env';
import { logger } from './logger';

const resend = env.RESEND_API_KEY ? new Resend(env.RESEND_API_KEY) : null;

export async function sendIncidentAlert(opts: {
  title:     string;
  severity:  'critical' | 'high' | 'medium' | 'low' | 'info';
  ruleName:  string;
  firstSeen: Date;
}): Promise<void> {
  if (!resend || !env.ALERT_EMAIL) {
    logger.debug({ title: opts.title }, 'Incident alert skipped — RESEND_API_KEY/ALERT_EMAIL not configured');
    return;
  }

  const severityColor: Record<string, string> = {
    critical: '#dc2626',
    high:     '#ea580c',
    medium:   '#d97706',
    low:      '#2563eb',
    info:     '#6b7280',
  };
  const color = severityColor[opts.severity] ?? '#6b7280';
  const dashboardUrl = `${env.DASHBOARD_URL}/tools/monitor/incidents`;
  const timeStr = opts.firstSeen.toLocaleString('en-BE', { timeZone: 'Europe/Brussels' });

  const html = `
    <div style="font-family:'Courier New',monospace;max-width:600px;margin:0 auto;background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;overflow:hidden">
      <div style="background:#0f1117;border-bottom:2px solid ${color};padding:20px 24px">
        <div style="font-size:10px;letter-spacing:3px;color:#4ade80;margin-bottom:8px">⚡ CYBEROPS SIEM — INCIDENT ALERT</div>
        <h2 style="margin:0;color:#f8fafc;font-size:16px;letter-spacing:1px">${opts.title}</h2>
      </div>
      <div style="padding:24px;background:#0d0d0d">
        <table style="width:100%;border-collapse:collapse;font-size:13px;color:#94a3b8">
          <tr>
            <td style="padding:8px 0;border-bottom:1px solid #1e293b;width:140px;color:#64748b;letter-spacing:1px;font-size:11px">SEVERITY</td>
            <td style="padding:8px 0;border-bottom:1px solid #1e293b">
              <span style="background:${color};color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;letter-spacing:2px;text-transform:uppercase">${opts.severity}</span>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 0;border-bottom:1px solid #1e293b;color:#64748b;letter-spacing:1px;font-size:11px">RULE</td>
            <td style="padding:8px 0;border-bottom:1px solid #1e293b;color:#67e8f9">${opts.ruleName}</td>
          </tr>
          <tr>
            <td style="padding:8px 0;color:#64748b;letter-spacing:1px;font-size:11px">FIRST SEEN</td>
            <td style="padding:8px 0;color:#94a3b8">${timeStr}</td>
          </tr>
        </table>
        <div style="margin-top:24px;text-align:center">
          <a href="${dashboardUrl}" style="display:inline-block;background:${color};color:#fff;padding:10px 28px;border-radius:4px;text-decoration:none;font-size:12px;letter-spacing:2px;text-transform:uppercase">View Incident →</a>
        </div>
        <p style="margin-top:24px;color:#334155;font-size:11px;text-align:center;letter-spacing:1px">THREAT INTELLIGENCE PLATFORM — AUTOMATED ALERT</p>
      </div>
    </div>
  `;

  try {
    await resend.emails.send({
      from:    'CyberOps SIEM <onboarding@resend.dev>',
      to:      env.ALERT_EMAIL,
      subject: `[${opts.severity.toUpperCase()}] ${opts.title}`,
      html,
    });
    logger.info({ to: env.ALERT_EMAIL, title: opts.title }, 'Incident alert email sent');
  } catch (err) {
    logger.error({ err, title: opts.title }, 'Failed to send incident alert email');
  }
}

export interface AlertEmailPayload {
  to:          string;
  title:       string;
  severity:    string;
  assetValue?: string;
  details:     Record<string, unknown>;
}

export async function sendAlertEmail(payload: AlertEmailPayload): Promise<void> {
  if (!resend) {
    logger.debug({ to: payload.to, title: payload.title }, 'Email skipped — RESEND_API_KEY not configured');
    return;
  }

  const severityColor: Record<string, string> = {
    critical: '#dc2626',
    high:     '#ea580c',
    medium:   '#d97706',
    low:      '#2563eb',
    info:     '#6b7280',
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
    await resend.emails.send({
      from:    'CyberOps SIEM <onboarding@resend.dev>',
      to:      payload.to,
      subject: `[${payload.severity.toUpperCase()}] ${payload.title}`,
      html,
    });
    logger.info({ to: payload.to, title: payload.title }, 'Alert email sent');
  } catch (err) {
    logger.error({ err, to: payload.to }, 'Failed to send alert email');
  }
}
