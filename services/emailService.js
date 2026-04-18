const nodemailer = require('nodemailer');

const createTransporter = () => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('[Email] EMAIL_USER or EMAIL_PASS not set in .env — emails will be skipped');
    return null;
  }
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
  },
  });
};

/**
 * Send campaign notification email to a single user.
 */
const sendCampaignEmail = async ({ to, name, campaign }) => {
  try {
    const transporter = createTransporter();
    if (!transporter) return false;

    const dateStr = new Date(campaign.dateTime).toLocaleString('en-IN', {
      weekday: 'long',
      year:    'numeric',
      month:   'long',
      day:     'numeric',
      hour:    '2-digit',
      minute:  '2-digit',
      timeZone: 'Asia/Kolkata',
    });

    const mailOptions = {
      from:    `"ZeroX Waste" <${process.env.EMAIL_USER}>`,
      to,
      subject: `New Campaign in Your Area — ${campaign.name}`,
      html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, initial-scale=1.0">
  <title>ZeroX Waste | Executive Campaign Invitation</title>
  <style>
    /* Email client resets & premium baseline */
    * {
      margin: 0;
      padding: 0;
      border-collapse: collapse;
    }
    body {
      margin: 0;
      padding: 0;
      background-color: #EDF2EF;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    /* Outer container subtle depth */
    .outer-wrap {
      background-color: #EDF2EF;
      padding: 40px 20px;
    }
    /* Main card: premium, elevated, yet subtle */
    .main-card {
      max-width: 600px;
      width: 100%;
      margin: 0 auto;
      background-color: #FFFFFF;
      border-radius: 24px;
      overflow: hidden;
      box-shadow: 0 20px 35px -10px rgba(0, 0, 0, 0.05), 0 0 0 1px rgba(0, 0, 0, 0.02);
    }
    /* refined dividers */
    .divider-premium {
      width: 48px;
      height: 2px;
      background: #1C4E3C;
      margin: 20px 0 24px 0;
    }
    .divider-light {
      height: 1px;
      background: #E6EDE8;
      width: 100%;
    }
    /* responsive spacing */
    @media only screen and (max-width: 600px) {
      .inner-padding {
        padding-left: 28px !important;
        padding-right: 28px !important;
      }
      .header-padding {
        padding: 40px 28px 32px !important;
      }
      .footer-padding {
        padding: 32px 28px !important;
      }
      .campaign-card {
        padding: 24px 24px !important;
      }
      .hero-title {
        font-size: 32px !important;
      }
      .cta-button {
        padding: 14px 32px !important;
        font-size: 15px !important;
      }
    }
    @media only screen and (max-width: 480px) {
      .inner-padding {
        padding-left: 20px !important;
        padding-right: 20px !important;
      }
      .campaign-card {
        padding: 20px !important;
      }
      .info-label {
        width: 70px !important;
      }
    }
    /* Outlook & legacy support */
    .fallback-font {
      font-family: 'Inter', Helvetica, Arial, sans-serif;
    }
  </style>
</head>
<body style="margin:0;padding:0;background-color:#EDF2EF;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Helvetica,Arial,sans-serif;">
  <div class="outer-wrap" style="background-color:#EDF2EF;padding:40px 20px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" align="center" style="background-color:#EDF2EF;">
      <tr>
        <td align="center" style="padding:0;">
          <!-- MAIN CARD TABLE -->
          <table class="main-card" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background:#FFFFFF;border-radius:24px;overflow:hidden;box-shadow:0 20px 35px -10px rgba(0,0,0,0.05),0 0 0 1px rgba(0,0,0,0.02);margin:0 auto;">
            
            <!-- HEADER: Prestigious, dark & sophisticated with fine details -->
            <tr>
              <td class="header-padding" style="background:#0B2B1F;padding:44px 40px 38px 40px;">
                <!-- Brand wordmark: refined, elevated -->
                <p style="margin:0 0 6px 0;font-size:11px;letter-spacing:2.2px;font-weight:500;color:#AAC7B8;text-transform:uppercase;opacity:0.85;">ZeroX Waste</p>
                <div style="height:2px;background:#2F6B51;width:42px;margin:10px 0 24px 0;"></div>
                <!-- Hero title: commanding yet elegant -->
                <h1 class="hero-title" style="margin:0;font-size:34px;font-weight:550;letter-spacing:-0.4px;color:#FFFFFF;line-height:1.2;max-width:85%;">
                  Campaign invitation
                </h1>
                <p style="margin:18px 0 0 0;font-size:16px;color:#D3E2DA;font-weight:400;line-height:1.5;border-left:2px solid #3F7A60;padding-left:18px;">
                  Strategic environmental initiative · immediate impact
                </p>
              </td>
            </tr>
            
            <!-- BODY SECTION: polished, spacious, executive tone -->
            <tr>
              <td class="inner-padding" style="padding:46px 40px 32px 40px;">
                <!-- Salutation refined -->
                <p style="margin:0 0 12px 0;font-size:18px;font-weight:480;color:#1F2F27;letter-spacing:-0.2px;">
                  <span style="font-weight:600;color:#0F3B2C;">${name}</span>,
                </p>
                <p style="margin:0 0 28px 0;font-size:16px;line-height:1.6;color:#3F564A;font-weight:400;">
                  A high-priority cleanup campaign has been mobilized within your operational zone. 
                  Your expertise and leadership are requested to drive measurable environmental progress.
                </p>
                
                <!-- PREMIUM CAMPAIGN CARD: structured, borderless elegance with subtle shadow -->
                <div style="background:#FCFDFC;border-radius:20px;margin-bottom:36px;border:1px solid #E2EBE5;box-shadow:0 4px 12px rgba(0,0,0,0.02);overflow:hidden;">
                  <div style="padding:28px 30px 30px 30px;">
                    <!-- Campaign name + refined accent -->
                    <h2 style="margin:0 0 8px 0;font-size:24px;font-weight:550;color:#0B2B1F;letter-spacing:-0.2px;">
                      ${campaign.name}
                    </h2>
                    <div style="width:44px;height:2px;background:#C9DDD0;margin-bottom:26px;"></div>
                    
                    <!-- Campaign details grid: clean, no icons, high readability -->
                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;">
                      <!-- Date row -->
                      <tr>
                        <td style="padding:0 0 22px 0;width:96px;vertical-align:top;" class="info-label">
                          <span style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#6B8F7A;">Date</span>
                        </td>
                        <td style="padding:0 0 22px 0;vertical-align:top;">
                          <span style="font-size:17px;font-weight:500;color:#1A2D24;">${dateStr}</span>
                        </td>
                      </tr>
                      <!-- Location row -->
                      <tr>
                        <td style="padding:0 0 22px 0;width:96px;vertical-align:top;">
                          <span style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#6B8F7A;">Location</span>
                        </td>
                        <td style="padding:0 0 22px 0;vertical-align:top;">
                          <span style="font-size:16px;font-weight:500;color:#2B4437;">${campaign.location.address || 'Venue details to be confirmed'}</span>
                        </td>
                      </tr>
                      <!-- Description row (Objective) -->
                      <tr>
                        <td style="padding:0;width:96px;vertical-align:top;">
                          <span style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#6B8F7A;">Brief</span>
                        </td>
                        <td style="padding:0;vertical-align:top;">
                          <p style="margin:0;font-size:15px;line-height:1.55;color:#3E5B4E;font-weight:400;">${campaign.description}</p>
                        </td>
                      </tr>
                    </table>
                  </div>
                </div>
                
                <!-- Persuasive, executive copy: authoritative & inspiring -->
                <p style="margin:0 0 32px 0;font-size:16px;line-height:1.55;color:#476654;font-weight:400;background:#F8FBF9;padding:20px 24px;border-radius:14px;border-left:3px solid #1C4E3C;">
                  Your participation amplifies our collective mission. Every action contributes to measurable waste reduction, urban revitalization, and sustainable infrastructure.
                </p>
                
                <!-- CTA SECTION: Elegant, high-converting, authoritative button -->
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:12px;">
                  <tr>
                    <td align="center" style="padding:0;">
                      <table cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;" class="btn-table">
                        <tr>
                          <td align="center" style="background:#0B2B1F;border-radius:60px;padding:0;">
                            <a href="#" style="display:inline-block;background:#0B2B1F;color:#FFFFFF;font-size:16px;font-weight:500;text-decoration:none;padding:15px 44px;border-radius:60px;letter-spacing:0.2px;border:1px solid #2C5F48;transition:all 0.2s ease;font-family:'Inter',Arial,sans-serif;">Confirm attendance →</a>
                          </td>
                        </tr>
                       </>
                    </td>
                  </tr>
                </table>
                <p style="margin:18px 0 0 0;font-size:13px;color:#89A396;text-align:center;letter-spacing:0.2px;border-top:0;">
                  Priority access · registration closes 48 hours prior
                </p>
              </td>
            </tr>
            
            <!-- Subtle divider for elegance -->
            <tr>
              <td style="padding:0 40px;">
                <div class="divider-light" style="height:1px;background:#ECF2EE;"></div>
              </td>
            </tr>
            
            <!-- FOOTER: Prestige enterprise, clean, trusted brand -->
            <tr>
              <td class="footer-padding" style="background:#FFFFFF;padding:34px 40px 38px 40px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0">
                  <tr>
                    <td align="center" style="padding-bottom:20px;">
                      <span style="font-size:10px;letter-spacing:1.5px;font-weight:600;color:#A0B8AB;text-transform:uppercase;">ZeroX Waste Management</span>
                    </td>
                  </tr>
                  <tr>
                    <td align="center" style="padding-bottom:18px;">
                      <p style="margin:0;font-size:13px;color:#789484;line-height:1.5;">
                        Advancing urban circularity · net-zero innovation
                      </p>
                    </td>
                  </tr>
                  <tr>
                    <td align="center" style="padding-bottom:8px;">
                      <p style="margin:0;font-size:12px;color:#A8BEAF;">
                        © ${new Date().getFullYear()} ZeroX · All rights reserved
                      </p>
                    </td>
                  </tr>
                  <tr>
                    <td align="center">
                      <p style="margin:12px 0 0 0;font-size:11px;color:#B9CDBF;line-height:1.4;">
                        You are receiving this executive briefing because you are a registered stakeholder of ZeroX Waste.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
          <!-- subtle spacer for better deliverability context -->
          <p style="margin:26px auto 0 auto;font-size:11px;color:#B3C9BB;text-align:center;max-width:500px;">
            ZeroX · environmental leadership platform
          </p>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`[Email] Sent to ${to} for campaign: ${campaign.name}`);
    return true;
  } catch (error) {
    console.error(`[Email] Failed to send to ${to}:`, error.message);
    return false;
  }
};

/**
 * Send campaign emails to multiple users in batches to avoid rate limits.
 */
const sendCampaignEmailBatch = async (registrations, campaign) => {
  const BATCH_SIZE = 5;
  const DELAY_MS   = 1000;

  let sent = 0;
  let failed = 0;

  for (let i = 0; i < registrations.length; i += BATCH_SIZE) {
    const batch = registrations.slice(i, i + BATCH_SIZE);

    await Promise.all(
      batch.map(async (reg) => {
        const ok = await sendCampaignEmail({
          to:       reg.email,
          name:     reg.name,
          campaign,
        });
        ok ? sent++ : failed++;
      })
    );

    // Delay between batches to respect SMTP rate limits
    if (i + BATCH_SIZE < registrations.length) {
      await new Promise(r => setTimeout(r, DELAY_MS));
    }
  }

  console.log(`[Email] Campaign batch done — sent: ${sent}, failed: ${failed}`);
  return { sent, failed };
};

/**
 * Send complaint resolution email to the original reporter.
 */
const sendResolutionEmail = async ({ to, name, report, proofUrl }) => {
  try {
    const transporter = createTransporter();
    if (!transporter) return false;

    const resolvedDate = new Date().toLocaleString('en-IN', {
      weekday: 'long', day: 'numeric', month: 'long',
      year: 'numeric', hour: '2-digit', minute: '2-digit',
      timeZone: 'Asia/Kolkata',
    });

    const mailOptions = {
      from:    `"ZeroX Waste" <${process.env.EMAIL_USER}>`,
      to,
      subject: `✅ Your Complaint Has Been Resolved — ZeroX Waste`,
      html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f0fdf4;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0fdf4;padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
        <tr>
          <td style="background:linear-gradient(135deg,#166534 0%,#16a34a 60%,#0d9488 100%);padding:36px 40px;text-align:center;">
            <p style="margin:0;font-size:48px;">✅</p>
            <h1 style="margin:12px 0 4px;color:#fff;font-size:26px;font-weight:800;">Complaint Resolved!</h1>
            <p style="margin:0;color:rgba(255,255,255,0.8);font-size:14px;">ZeroX Waste Management Platform</p>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px;">
            <p style="margin:0 0 16px;font-size:16px;color:#374151;">Hi <strong>${name}</strong> 👋</p>
            <p style="margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.7;">
              Great news! Your waste complaint has been <strong style="color:#166534;">successfully resolved</strong>. 
              Our team has cleaned up the area and uploaded proof of completion.
            </p>
            <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:24px;margin-bottom:24px;">
              <h2 style="margin:0 0 16px;color:#166534;font-size:18px;">Complaint Details</h2>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td style="padding:6px 0;"><span style="font-size:13px;color:#6b7280;font-weight:600;">CATEGORY</span></td>
                    <td style="padding:6px 0;"><span style="font-size:14px;color:#111827;text-transform:capitalize;">${report.category}</span></td></tr>
                <tr><td style="padding:6px 0;"><span style="font-size:13px;color:#6b7280;font-weight:600;">RESOLVED ON</span></td>
                    <td style="padding:6px 0;"><span style="font-size:14px;color:#111827;">${resolvedDate}</span></td></tr>
                <tr><td style="padding:6px 0;"><span style="font-size:13px;color:#6b7280;font-weight:600;">LOCATION</span></td>
                    <td style="padding:6px 0;"><span style="font-size:14px;color:#111827;">${report.location?.address || 'Your reported location'}</span></td></tr>
              </table>
            </div>
            ${proofUrl ? `
            <div style="margin-bottom:24px;text-align:center;">
              <p style="font-size:14px;color:#374151;font-weight:600;margin-bottom:12px;">📸 Proof of Cleanup</p>
              <img src="${proofUrl}" alt="Cleaned area" style="width:100%;max-width:480px;border-radius:12px;border:2px solid #bbf7d0;"/>
            </div>` : ''}
            <div style="text-align:center;margin:28px 0;">
              <a href="${process.env.FRONTEND_URL || 'http://localhost:5173'}/myreports" 
                 style="display:inline-block;background:linear-gradient(135deg,#166534,#16a34a);color:#fff;font-size:15px;font-weight:700;text-decoration:none;padding:14px 36px;border-radius:50px;letter-spacing:0.3px;">
                View Resolved Complaint →
              </a>
            </div>
            <p style="margin:0;font-size:14px;color:#6b7280;text-align:center;line-height:1.6;">
              Thank you for helping keep your city clean! 🌿<br>You've earned <strong style="color:#166534;">25 bonus points</strong> for this resolved complaint.
            </p>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:20px 40px;text-align:center;">
            <p style="margin:0;font-size:12px;color:#9ca3af;">© ${new Date().getFullYear()} ZeroX Waste Management Platform</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`[Email] Resolution email sent to ${to}`);
    return true;
  } catch (error) {
    console.error(`[Email] Resolution email failed to ${to}:`, error.message);
    return false;
  }
};

/**
 * Send task assignment email to worker
 */
const sendWorkerAssignmentEmail = async ({ to, workerName, report }) => {
  try {
    const transporter = createTransporter();
    if (!transporter) return false;

    const reportDate = new Date(report.createdAt).toLocaleString('en-IN', {
      day: 'numeric', month: 'long', year: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Kolkata',
    });

    const mailOptions = {
      from: `"ZeroX Waste" <${process.env.EMAIL_USER}>`,
      to,
      subject: `🧹 New Cleanup Task Assigned — ${report.category} Waste`,
      html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f0fdf4;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0fdf4;padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
        <tr>
          <td style="background:linear-gradient(135deg,#1a6b45 0%,#276749 50%,#2c7a7b 100%);padding:36px 40px;text-align:center;">
            <p style="margin:0;font-size:40px;">🧹</p>
            <h1 style="margin:12px 0 4px;color:#fff;font-size:24px;font-weight:800;">New Task Assigned!</h1>
            <p style="margin:0;color:rgba(255,255,255,0.8);font-size:13px;">ZeroX Waste Worker Portal</p>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px;">
            <p style="margin:0 0 20px;font-size:16px;color:#374151;">Hi <strong>${workerName}</strong> 👋</p>
            <p style="margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.7;">
              A new waste cleanup task has been assigned to you. Please review the details below and proceed to the location as soon as possible.
            </p>
            <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:24px;margin-bottom:24px;">
              <h2 style="margin:0 0 16px;color:#166534;font-size:18px;">Task Details</h2>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:6px 0;width:120px;"><span style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;">Category</span></td>
                  <td style="padding:6px 0;"><span style="font-size:14px;color:#111827;text-transform:capitalize;font-weight:600;">${report.category} Waste</span></td>
                </tr>
                <tr>
                  <td style="padding:6px 0;"><span style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;">Priority</span></td>
                  <td style="padding:6px 0;"><span style="font-size:14px;color:${report.priorityLevel === 'High' ? '#dc2626' : report.priorityLevel === 'Medium' ? '#d97706' : '#16a34a'};font-weight:700;">${report.priorityLevel || 'Pending Analysis'} ${report.priorityScore ? `(${report.priorityScore}/100)` : ''}</span></td>
                </tr>
                <tr>
                  <td style="padding:6px 0;"><span style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;">Location</span></td>
                  <td style="padding:6px 0;"><span style="font-size:14px;color:#111827;">${report.location?.address || 'GPS coordinates provided below'}</span></td>
                </tr>
                <tr>
                  <td style="padding:6px 0;"><span style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;">GPS</span></td>
                  <td style="padding:6px 0;"><span style="font-size:14px;color:#2563eb;">${report.location?.coordinates?.[1]?.toFixed(6) || 'N/A'}, ${report.location?.coordinates?.[0]?.toFixed(6) || 'N/A'}</span></td>
                </tr>
                <tr>
                  <td style="padding:6px 0;"><span style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;">Reported On</span></td>
                  <td style="padding:6px 0;"><span style="font-size:14px;color:#111827;">${reportDate}</span></td>
                </tr>
                <tr>
                  <td style="padding:6px 0;vertical-align:top;"><span style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;">Description</span></td>
                  <td style="padding:6px 0;"><span style="font-size:14px;color:#374151;line-height:1.6;">${report.description}</span></td>
                </tr>
              </table>
            </div>
            <div style="background:#fef3c7;border:1px solid #fcd34d;border-radius:10px;padding:16px 20px;margin-bottom:24px;">
              <p style="margin:0;font-size:13px;color:#92400e;font-weight:600;">⚠️ Important Instructions:</p>
              <ul style="margin:8px 0 0 0;padding-left:20px;color:#78350f;font-size:13px;line-height:1.8;">
                <li>Reach the location as soon as possible</li>
                <li>Take a clear photo of the area BEFORE cleaning</li>
                <li>After cleanup, upload proof photo via Worker Portal</li>
                <li>Your GPS must be within 500m of the complaint location</li>
              </ul>
            </div>
            <div style="text-align:center;margin:24px 0;">
              <a href="${process.env.FRONTEND_URL || 'http://localhost:5173'}/worker-portal"
                 style="display:inline-block;background:linear-gradient(135deg,#1a6b45,#2c7a7b);color:#fff;font-size:15px;font-weight:700;text-decoration:none;padding:14px 36px;border-radius:50px;">
                Open Worker Portal →
              </a>
            </div>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:20px 40px;text-align:center;">
            <p style="margin:0;font-size:12px;color:#9ca3af;">© ${new Date().getFullYear()} ZeroX Waste Management Platform</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`[Email] Worker assignment email sent to ${to}`);
    return true;
  } catch (error) {
    console.error(`[Email] Worker assignment email failed to ${to}:`, error.message);
    return false;
  }
};

module.exports = { sendCampaignEmail, sendCampaignEmailBatch, sendResolutionEmail, sendWorkerAssignmentEmail };