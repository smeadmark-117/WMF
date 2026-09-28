import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

function sameSecret(actual: string, expected: string): boolean {
    const digest = (value: string) => createHash('sha256').update(value).digest();
    return timingSafeEqual(digest(actual), digest(expected));
}

const COOKIE_NAME = 'wmf_audit_session';
const SESSION_SECONDS = 8 * 60 * 60;

function signature(expires: string, password: string): string {
    return createHmac('sha256', password).update(`wmf-audit:${expires}`).digest('base64url');
}

function authorized(cookieHeader: string, password: string): boolean {
    const cookie = cookieHeader.split(';').map(value => value.trim())
        .find(value => value.startsWith(`${COOKIE_NAME}=`));
    if (!cookie) return false;
    const token = cookie.slice(COOKIE_NAME.length + 1);
    const match = /^(\d+)\.([A-Za-z0-9_-]+)$/.exec(token);
    if (!match) return false;
    const now = Math.floor(Date.now() / 1000);
    const expires = Number(match[1]);
    return expires > now && expires <= now + SESSION_SECONDS
        && sameSecret(match[2], signature(match[1], password));
}

function sessionCookie(req: IncomingMessage, value: string, maxAge: number): string {
    const secure = process.env.VERCEL === '1' || req.headers['x-forwarded-proto'] === 'https';
    return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

async function formData(req: IncomingMessage & { body?: unknown }): Promise<URLSearchParams> {
    // Vercel may parse form bodies before invoking the function.
    if (typeof req.body === 'string') {
        if (Buffer.byteLength(req.body) > 4096) throw new Error('Form too large');
        return new URLSearchParams(req.body);
    }
    if (req.body && typeof req.body === 'object') {
        const body = req.body as Record<string, unknown>;
        return new URLSearchParams({
            password: typeof body.password === 'string' ? body.password : '',
            action: typeof body.action === 'string' ? body.action : '',
        });
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
        const buffer = Buffer.from(chunk);
        size += buffer.length;
        if (size > 4096) throw new Error('Form too large');
        chunks.push(buffer);
    }
    return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('Vercel-CDN-Cache-Control', 'no-store');
    res.setHeader('Vary', 'Cookie');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; img-src 'self'; frame-src https://airtable.com; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");

    if (!['GET', 'HEAD', 'POST'].includes(req.method || '')) {
        res.setHeader('Allow', 'GET, HEAD, POST');
        res.statusCode = 405;
        res.end('Method not allowed.');
        return;
    }
    const password = process.env.AUDIT_PASSWORD;
    if (!password || password.trim().length < 8) {
        res.statusCode = 503;
        res.end('Auditor access is not configured yet.');
        return;
    }

    if (req.method === 'POST') {
        // Browser fetch metadata survives preview proxies that rewrite Host.
        const fetchSite = req.headers['sec-fetch-site'];
        if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
            res.statusCode = 403;
            res.end('Request not allowed.');
            return;
        }
        let form: URLSearchParams;
        try {
            form = await formData(req);
        } catch {
            res.statusCode = 413;
            res.end('Form too large.');
            return;
        }
        if (form.get('action') === 'logout') {
            res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
        } else if (sameSecret(form.get('password') || '', password)) {
            const expires = String(Math.floor(Date.now() / 1000) + SESSION_SECONDS);
            res.setHeader('Set-Cookie', sessionCookie(req, `${expires}.${signature(expires, password)}`, SESSION_SECONDS));
        } else {
            res.statusCode = 403;
            res.end(page(false, true));
            return;
        }
        res.statusCode = 303;
        res.setHeader('Location', '/audit');
        res.end();
        return;
    }
    res.statusCode = 200;
    res.end(req.method === 'HEAD' ? '' : page(authorized(req.headers.cookie || '', password)));
}

function page(authenticated: boolean, incorrect = false): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auditor | White Mountain Farm</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header><a class="logo" href="/"><img src="/images/Logo.png" alt="White Mountain Farm home"></a></header>
    <main class="audit-content">
        ${authenticated ? `
        <div class="audit-heading">
            <div>
                <p class="audit-eyebrow">WHITE MOUNTAIN FARM</p>
                <h1>Auditor resources</h1>
            </div>
            <div class="audit-actions">
                <a class="audit-home-link" href="/">Return to the farm website</a>
                <form method="post" action="/audit">
                    <input type="hidden" name="action" value="logout">
                    <button class="audit-button" type="submit">Sign out</button>
                </form>
            </div>
        </div>
        <section class="audit-view" aria-labelledby="documents-title">
            <h2 id="documents-title">Documents</h2>
            <iframe
                class="audit-embed"
                title="White Mountain Farm Documents"
                src="https://airtable.com/embed/appNLZRem7rgH92dh/shrixJ3vwwE3dgayq?viewControls=on"
                loading="lazy"
                referrerpolicy="no-referrer"
                allow="fullscreen">
            </iframe>
        </section>` : `
        <div class="audit-login">
            <p class="audit-eyebrow">WHITE MOUNTAIN FARM</p>
            <h1>Audit Portal</h1>
            <p>Enter the audit password to access the farm’s records.</p>
            <form method="post" action="/audit" class="audit-login-form">
                <label for="audit-password">Password</label>
                <input id="audit-password" name="password" type="password" autocomplete="current-password" required autofocus>
                ${incorrect ? '<p class="audit-error" role="alert">Incorrect password. Please try again.</p>' : ''}
                <button class="audit-button" type="submit">Enter audit portal</button>
            </form>
            <a href="/">Return to the farm website</a>
        </div>`}
    </main>
    <footer><p>&copy; 2026 White Mountain Farm. All rights reserved.</p></footer>
</body>
</html>`;
}
