export const labsData = {
  'input-validation': {
    title: 'Input Validation',
    variants: [
      {
        scenario: 'User input is being directly processed without validation, leading to potential data corruption or unexpected behavior. In this lab, you will implement robust validation using Zod.',
        vulnerable_code: `export async function POST(req) {\n  const data = await req.json();\n  const { username, age } = data;\n  db.updateUser({ username, age });\n  return Response.json({ status: 'Updated' });\n}`,
        fix_steps: ['Define a Zod schema.', 'Use safeParse().', 'Return 400 on error.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({ username: z.string().min(3), age: z.number().min(13) });\nexport async function POST(req) {\n  const body = await req.json();\n  const res = schema.safeParse(body);\n  if (!res.success) return Response.json(res.error, { status: 400 });\n  db.updateUser(res.data);\n  return Response.json({ status: 'Updated' });\n}`,
        check_logic: (input) => input.includes('z.object') && input.includes('safeParse'),
        explanation: 'We use the Zod library to create a "schema" that defines exactly what the incoming data should look like. `schema.safeParse` checks the data without throwing an error if it fails, allowing us to return a friendly 400 error message to the user instead of letting the app crash.'
      },
      {
        scenario: 'An internal API receives numeric IDs from a search query. It converts them and queries the DB directly without checking if they are valid positive integers.',
        vulnerable_code: `export async function GET(req) {\n  const { id } = Object.fromEntries(new URL(req.url).searchParams);\n  const userId = parseInt(id);\n  const data = await db.query(\`SELECT * FROM users WHERE id = \${userId}\`);\n  return Response.json(data);\n}`,
        fix_steps: ['Coerce input to number.', 'Ensure integer and positive.', 'Use parameterized queries.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({ id: z.coerce.number().int().positive() });\nexport async function GET(req) {\n  const { id } = Object.fromEntries(new URL(req.url).searchParams);\n  const res = schema.safeParse({ id });\n  if (!res.success) return Response.json({ error: 'Invalid ID' }, { status: 400 });\n  const data = await db.query('SELECT * FROM users WHERE id = ?', [res.data.id]);\n  return Response.json(data);\n}`,
        check_logic: (input) => input.includes('coerce.number') && input.includes('positive'),
        explanation: '`z.coerce.number()` automatically converts strings from the URL into numbers. We then use `.int().positive()` to ensure the ID is a whole, positive number. Finally, we use a parameterized query (`?`) to prevent SQL injection by separating the query logic from the data.'
      },
      {
        scenario: 'A product search endpoint accepts a "category" string. If unvalidated, it could be used for injection or cause errors if the category does not exist.',
        vulnerable_code: `export async function GET(req) {\n  const { category } = Object.fromEntries(new URL(req.url).searchParams);\n  const results = await db.products.find({ category });\n  return Response.json(results);\n}`,
        fix_steps: ['Use an enum to restrict category values.', 'Validate with Zod.', 'Handle unknown categories gracefully.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({ category: z.enum(['electronics', 'books', 'clothing']) });\nexport async function GET(req) {\n  const params = Object.fromEntries(new URL(req.url).searchParams);\n  const res = schema.safeParse(params);\n  if (!res.success) return Response.json({ error: 'Invalid Category' }, { status: 400 });\n  const results = await db.products.find({ category: res.data.category });\n  return Response.json(results);\n}`,
        check_logic: (input) => input.includes('z.enum'),
        explanation: 'The `z.enum` function creates a "whitelist" of allowed values. If someone tries to send a category that isn\'t in the list (like a malicious script), Zod will block it immediately. This ensures only trusted categories reach your database.'
      },
      {
        scenario: 'A credit card payment form accepts a card number. It should be validated using the Luhn algorithm to catch typing errors before processing.',
        vulnerable_code: `export async function POST(req) {\n  const { cardNumber, amount } = await req.json();\n  await gateway.charge(cardNumber, amount);\n  return Response.json({ success: true });\n}`,
        fix_steps: ['Install a validation library.', 'Use a regex for basic format.', 'Implement or use a Luhn check.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({\n  cardNumber: z.string().regex(/^[0-9]{13,19}$/).refine(val => luhnCheck(val), 'Invalid card'),\n  amount: z.number().positive()\n});\nexport async function POST(req) {\n  const res = schema.safeParse(await req.json());\n  if (!res.success) return Response.json(res.error, { status: 400 });\n  // ... process payment\n}`,
        check_logic: (input) => input.includes('refine') && input.includes('luhnCheck'),
        explanation: 'For sensitive data like credit cards, we use `.refine()` to add custom logic. The Luhn algorithm is a standard formula used to validate a variety of identification numbers, such as credit card numbers, to ensure they were entered correctly.'
      },
      {
        scenario: 'An admin tool takes an IP address to whitelist. Without validation, it could lead to malformed networking rules.',
        vulnerable_code: `export async function POST(req) {\n  const { ip } = await req.json();\n  await firewall.allow(ip);\n  return Response.json({ status: 'Whitelisted' });\n}`,
        fix_steps: ['Use Zod ip() validator.', 'Support both v4 and v6 if needed.', 'Return error for invalid IPs.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({ ip: z.string().ip() });\nexport async function POST(req) {\n  const res = schema.safeParse(await req.json());\n  if (!res.success) return Response.json({ error: 'Invalid IP' }, { status: 400 });\n  await firewall.allow(res.data.ip);\n  return Response.json({ status: 'Whitelisted' });\n}`,
        check_logic: (input) => input.includes('.ip()'),
        explanation: 'Zod has a built-in `.ip()` validator that automatically checks for valid IPv4 or IPv6 formats. This prevents "garbage" data from being passed into low-level system or firewall commands.'
      },
      {
        scenario: 'A redirection service accepts a "url" parameter. If unvalidated, hackers can use "javascript:" schemes to steal cookies.',
        vulnerable_code: `export async function GET(req) {\n  const url = new URL(req.url).searchParams.get('url');\n  return Response.redirect(url);\n}`,
        fix_steps: ['Validate URL protocol.', 'Only allow http/https.', 'Use Zod url() validator.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.string().url().startsWith('https://');\nexport async function GET(req) {\n  const url = new URL(req.url).searchParams.get('url');\n  if (!schema.safeParse(url).success) return Response.json({ error: 'Unsafe URL' }, { status: 400 });\n  return Response.redirect(url);\n}`,
        check_logic: (input) => input.includes('.url()') && input.includes('startsWith'),
        explanation: 'Using `.url()` ensures the string is a valid URL, but we also use `.startsWith("https://")` to ensure it uses a secure protocol. This prevents "Open Redirect" vulnerabilities and XSS via `javascript:` links.'
      },
      {
        scenario: 'A profile picture upload endpoint accepts a filename. It must ensure only safe image extensions are used.',
        vulnerable_code: `export async function POST(req) {\n  const { filename } = await req.json();\n  await saveToDisk(filename);\n  return Response.json({ ok: true });\n}`,
        fix_steps: ['Extract extension.', 'Use a whitelist (enum).', 'Sanitize the filename.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({\n  filename: z.string().endsWith('.jpg').or(z.string().endsWith('.png'))\n});\nexport async function POST(req) {\n  const res = schema.safeParse(await req.json());\n  if (!res.success) return Response.json({ error: 'Invalid file type' }, { status: 400 });\n  // ... save file safely\n}`,
        check_logic: (input) => input.includes('endsWith'),
        explanation: 'By checking the end of the string with `.endsWith()`, we ensure that only approved file extensions (like .jpg or .png) are processed. This stops attackers from uploading harmful scripts like `.php` or `.js` files.'
      },
      {
        scenario: 'A booking system accepts a "startDate" and "endDate". It must verify that the end is after the start.',
        vulnerable_code: `export async function POST(req) {\n  const { start, end } = await req.json();\n  await db.bookings.create({ start, end });\n  return Response.json({ status: 'Booked' });\n}`,
        fix_steps: ['Parse as dates.', 'Use refine() for comparison.', 'Ensure dates are not in the past.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({\n  start: z.coerce.date(),\n  end: z.coerce.date()\n}).refine(data => data.end > data.start, {\n  message: 'End date must be after start date',\n  path: ['end']\n});\nexport async function POST(req) {\n  const res = schema.safeParse(await req.json());\n  if (!res.success) return Response.json(res.error, { status: 400 });\n  await db.bookings.create(res.data);\n  return Response.json({ status: 'Booked' });\n}`,
        check_logic: (input) => input.includes('date()') && input.includes('refine'),
        explanation: 'We use `z.coerce.date()` to turn strings into JavaScript Date objects. Then, `.refine()` allows us to compare the two fields. Logic like "end must be after start" is essential for "Business Logic" security, not just data type safety.'
      },
      {
        scenario: 'A feedback form accepts a "message". If it is too long, it could cause memory issues or crash the log processor.',
        vulnerable_code: `export async function POST(req) {\n  const { message } = await req.json();\n  console.log('Feedback received: ' + message);\n  return Response.json({ ok: true });\n}`,
        fix_steps: ['Set a maximum length.', 'Use Zod .max().', 'Provide clear feedback to user.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({ message: z.string().min(1).max(500) });\nexport async function POST(req) {\n  const res = schema.safeParse(await req.json());\n  if (!res.success) return Response.json({ error: 'Message too long' }, { status: 400 });\n  console.log('Safe feedback:', res.data.message);\n  return Response.json({ ok: true });\n}`,
        check_logic: (input) => input.includes('.max(500)'),
        explanation: 'Enforcing a `.max()` length is a simple but effective way to prevent "Resource Exhaustion" attacks. It ensures that attackers can\'t send megabytes of text to fill up your logs or crash your server\'s memory.'
      },
      {
        scenario: 'An API accepts a complex "config" object. It needs to validate the deep structure to prevent unexpected behavior.',
        vulnerable_code: `export async function POST(req) {\n  const config = await req.json();\n  applySettings(config);\n  return Response.json({ success: true });\n}`,
        fix_steps: ['Define nested Zod objects.', 'Use strict() to prevent extra fields.', 'Recursively validate types.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.object({\n  theme: z.enum(['dark', 'light']),\n  notifications: z.object({\n    email: z.boolean(),\n    sms: z.boolean()\n  }).strict()\n});\nexport async function POST(req) {\n  const res = schema.safeParse(await req.json());\n  if (!res.success) return Response.json(res.error, { status: 400 });\n  applySettings(res.data);\n  return Response.json({ success: true });\n}`,
        check_logic: (input) => input.includes('.object(') && input.includes('.strict()'),
        explanation: 'Nested `z.object` calls mirror the structure of your data. Adding `.strict()` is a great security layer—it tells Zod to reject the request if the user sends *extra* fields that you didn\'t define, preventing "Mass Assignment" attacks.'
      }
    ]
  },
  'auth-vs-authz': {
    title: 'Authentication vs Authorization',
    variants: [
      {
        scenario: 'A page is hidden behind a check for "isLoggedIn", but does not check if the user has the required "ADMIN" role.',
        vulnerable_code: `if (!req.cookies.get('session')) return NextResponse.redirect('/login');\nreturn NextResponse.next();`,
        fix_steps: ['Extract role from session.', 'Check for ADMIN role.', 'Strict redirect for unauthorized users.'],
        patched_code: `const session = getSession(req);\nif (!session) return redirect('/login');\nif (session.user.role !== 'ADMIN') {\n  return NextResponse.rewrite(new URL('/unauthorized', req.url));\n}\nreturn NextResponse.next();`,
        check_logic: (input) => input.includes('role') && input.includes('ADMIN'),
        explanation: 'Authentication proves *who* you are (login), but Authorization decides *what* you can do. Even if a user is logged in, we must explicitly check their `role` to ensure they have permission to access sensitive areas like the Admin panel.'
      },
      {
        scenario: 'An API endpoint allows fetching all users. It requires a session but fails to check if the user is an admin.',
        vulnerable_code: `export async function GET(req) {\n  const session = await getSession(req);\n  if (!session) return Response.json({ error: 'No Session' }, { status: 401 });\n  const users = await db.users.findAll();\n  return Response.json(users);\n}`,
        fix_steps: ['Verify role in endpoint logic.', 'Return 403 Forbidden.', 'Use a middleware or guard function.'],
        patched_code: `export async function GET(req) {\n  const session = await getSession(req);\n  if (!session) return Response.json({ error: 'Unauthenticated' }, { status: 401 });\n  if (session.user.role !== 'ADMIN') return Response.json({ error: 'Forbidden' }, { status: 403 });\n  const users = await db.users.findAll();\n  return Response.json(users);\n}`,
        check_logic: (input) => input.includes('403') && input.includes('role'),
        explanation: 'We return a `401 Unauthenticated` error if the user isn\'t logged in, and a `403 Forbidden` error if they are logged in but don\'t have the correct permissions. This distinction helps security auditors understand which layer of security failed.'
      },
      {
        scenario: 'A password reset feature uses a simple user ID in the link. Any user can reset anyone else\'s password by guessing their ID.',
        vulnerable_code: `export async function GET(req) {\n  const id = new URL(req.url).searchParams.get('userId');\n  return Response.json({ message: 'Reset link for user ' + id });\n}`,
        fix_steps: ['Generate a random, long token.', 'Store token in DB with expiry.', 'Verify token before allowing reset.'],
        patched_code: `import { crypto } from 'crypto';\nconst token = crypto.randomBytes(32).toString('hex');\nawait db.tokens.create({ userId, token, expiresAt: Date.now() + 3600000 });\nreturn Response.json({ link: \`/reset?token=\${token}\` });`,
        check_logic: (input) => input.includes('randomBytes') && input.includes('token'),
        explanation: 'Predictable reset links are a major security flaw. We use `crypto.randomBytes` to generate a "high entropy" token that is impossible to guess. We also add an expiration time to ensure the token can\'t be used forever.'
      },
      {
        scenario: 'A login session lasts forever. If a device is stolen, the attacker has permanent access.',
        vulnerable_code: `cookies().set('session', 'xyz', { httpOnly: true });`,
        fix_steps: ['Set an expiration date.', 'Use maxAge or expires.', 'Implement server-side session cleanup.'],
        patched_code: `cookies().set('session', 'xyz', {\n  httpOnly: true,\n  secure: true,\n  maxAge: 60 * 60 * 24 // 24 hours\n});`,
        check_logic: (input) => input.includes('maxAge'),
        explanation: 'Sessions should have a "Time to Live" (TTL). By setting `maxAge`, the browser automatically deletes the cookie after the specified time. This reduces the "window of opportunity" for an attacker who gets access to a user\'s device.'
      },
      {
        scenario: 'An MFA (Multi-Factor Authentication) check can be bypassed by manually navigating to the /dashboard URL.',
        vulnerable_code: `if (user.hasMFA) return redirect('/mfa-check');\nreturn redirect('/dashboard');`,
        fix_steps: ['Check MFA status in middleware.', 'Track MFA completion in session.', 'Prevent dashboard access until verified.'],
        patched_code: `if (session.user.hasMFA && !session.mfaVerified) {\n  return NextResponse.redirect('/mfa-check');\n}\nreturn NextResponse.next();`,
        check_logic: (input) => input.includes('mfaVerified'),
        explanation: 'Security is like a chain. If the MFA "gate" only exists on the login page but not on the dashboard, it can be hopped over. We check for a `mfaVerified` flag in the secure session before allowing access to any sensitive page.'
      },
      {
        scenario: 'Users are allowed to set very weak passwords, making the app vulnerable to credential stuffing.',
        vulnerable_code: `if (password.length < 1) throw new Error('Password required');`,
        fix_steps: ['Enforce minimum length.', 'Check against breached password lists.', 'Require complex characters.'],
        patched_code: `import { z } from 'zod';\nconst schema = z.string().min(8).regex(/[A-Z]/).regex(/[0-9]/);\nif (!schema.safeParse(password).success) throw new Error('Password too weak');`,
        check_logic: (input) => input.includes('.min(8)'),
        explanation: 'Weak passwords are easy to guess. By enforcing a minimum length (8+) and requiring mixed characters (numbers, uppercase), we make automated brute-force attacks significantly more difficult and expensive for hackers.'
      },
      {
        scenario: 'A logout feature only deletes the cookie on the client but doesn\'t invalidate it on the server.',
        vulnerable_code: `cookies().delete('session');\nreturn Response.json({ ok: true });`,
        fix_steps: ['Delete from DB/Redis.', 'Blacklist the token.', 'Ensure no further requests are accepted.'],
        patched_code: `const sessionId = cookies().get('session');\nawait db.sessions.delete(sessionId);\ncookies().delete('session');\nreturn Response.json({ ok: true });`,
        check_logic: (input) => input.includes('db.sessions.delete'),
        explanation: 'Simply "forgetting" the cookie on the browser isn\'t enough. If an attacker stole that cookie earlier, they can still use it! You must explicitly delete the session from your database or cache so it becomes useless globally.'
      },
      {
        scenario: 'Repeated failed logins are not tracked, allowing unlimited brute-force attempts.',
        vulnerable_code: `const ok = await login(user, pass);\nreturn Response.json({ ok });`,
        fix_steps: ['Track failed attempts.', 'Lock account after 5 tries.', 'Notify the user.'],
        patched_code: `await db.logins.track(userId, success);\nif (await db.logins.getFailedCount(userId) > 5) {\n  await db.users.lock(userId);\n  return Response.json({ error: 'Account locked' }, { status: 403 });\n}`,
        check_logic: (input) => input.includes('lock'),
        explanation: 'Account lockout is a critical defense. By stopping login attempts after a few failures, you prevent hackers from using "dictionaries" to guess thousands of passwords. This forces them to move on to an easier target.'
      },
      {
        scenario: 'Sensitive cookies are sent over unencrypted HTTP, making them vulnerable to "Man-in-the-Middle" attacks.',
        vulnerable_code: `cookies().set('token', val, { httpOnly: true });`,
        fix_steps: ['Set "Secure" flag.', 'Ensure HTTPS is used.', 'Use "SameSite" protection.'],
        patched_code: `cookies().set('token', val, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict'\n});`,
        check_logic: (input) => input.includes('secure: true'),
        explanation: 'The `secure: true` flag tells the browser: "Only send this cookie if the connection is encrypted (HTTPS)." Without it, your secret login token could be sniffed out by someone on the same Wi-Fi network (like at a coffee shop).'
      },
      {
        scenario: 'A JWT (JSON Web Token) is used without checking its expiration date, allowing permanent hijacked access.',
        vulnerable_code: `const decoded = jwt.verify(token, SECRET);\nreturn decoded.userId;`,
        fix_steps: ['Check "exp" claim.', 'Set reasonable expiration.', 'Use library defaults.'],
        patched_code: `const decoded = jwt.verify(token, SECRET, { ignoreExpiration: false });\nif (decoded.exp < Date.now() / 1000) throw new Error('Expired');`,
        check_logic: (input) => input.includes('ignoreExpiration: false') || input.includes('decoded.exp'),
        explanation: 'JWTs often contain an "exp" (expiry) timestamp. If you don\'t check it, a token stolen a year ago might still work! Always verify that the token hasn\'t expired to ensure the user is still actively authorized.'
      }
    ]
  },
  'broken-access-control': {
    title: 'Broken Access Control',
    variants: [
      {
        scenario: 'An endpoint allows users to fetch invoices by ID, but doesn\'t verify owner-to-resource alignment.',
        vulnerable_code: `export async function GET(req, { params }) {\n  const invoice = await db.invoices.find(params.id);\n  return Response.json(invoice);\n}`,
        fix_steps: ['Get user from session.', 'Match invoice.userId with user.id.', 'Enforce data ownership.'],
        patched_code: `export async function GET(req, { params }) {\n  const user = await getSessionUser(req);\n  const invoice = await db.invoices.find(params.id);\n  if (!invoice || invoice.userId !== user.id) return Response.json({ error: 'Forbidden' }, { status: 403 });\n  return Response.json(invoice);\n}`,
        check_logic: (input) => input.includes('userId !== user.id'),
        explanation: 'This is a fix for IDOR (Insecure Direct Object Reference). Just because a user knows an invoice ID doesn\'t mean they should see it. We always compare the `userId` on the record with the `id` of the currently logged-in user.'
      },
      {
        scenario: 'A profile update endpoint trusts a "userId" provided in the request body.',
        vulnerable_code: `export async function POST(req) {\n  const { userId, bio } = await req.json();\n  await db.profiles.update(userId, { bio });\n  return Response.json({ status: 'Updated' });\n}`,
        fix_steps: ['Ignore userId from body.', 'Use userId from verified session.', 'Prevent horizontal escalation.'],
        patched_code: `export async function POST(req) {\n  const user = await getSessionUser(req);\n  const { bio } = await req.json();\n  await db.profiles.update(user.id, { bio });\n  return Response.json({ status: 'Updated' });\n}`,
        check_logic: (input) => input.includes('user.id') && !input.includes('body.userId'),
        explanation: 'Never trust security-sensitive data sent in the request body, like a `userId`. An attacker could easily change that ID to someone else\'s. Instead, grab the ID directly from the server-side session.'
      },
      {
        scenario: 'An admin dashboard allows promoting users to "ADMIN" role by sending a hidden field in the profile update.',
        vulnerable_code: `export async function POST(req) {\n  const data = await req.json();\n  await db.users.update(data.id, data);\n  return Response.json({ status: 'Updated' });\n}`,
        fix_steps: ['Restrict fields to a whitelist.', 'Ignore "role" or "is_admin" from input.', 'Only allow admins to change roles.'],
        patched_code: `export async function POST(req) {\n  const { bio, nickname } = await req.json();\n  const user = await getSessionUser(req);\n  await db.users.update(user.id, { bio, nickname });\n  return Response.json({ status: 'Updated' });\n}`,
        check_logic: (input) => input.includes('{ bio, nickname }'),
        explanation: 'This is "Mass Assignment." If you pass the entire `req.json()` directly to the database update, a clever user can add `"role": "ADMIN"` to their request and escalate their own privileges. Always pick only the safe fields you want to update.'
      },
      {
        scenario: 'A directory listing endpoint allows any user to see the list of all uploaded files, regardless of who uploaded them.',
        vulnerable_code: `export async function GET(req) {\n  const files = await db.files.findAll();\n  return Response.json(files);\n}`,
        fix_steps: ['Filter files by user ID.', 'Check record ownership.', 'Return only the user\'s own files.'],
        patched_code: `export async function GET(req) {\n  const user = await getSessionUser(req);\n  const files = await db.files.findMine(user.id);\n  return Response.json(files);\n}`,
        check_logic: (input) => input.includes('user.id'),
        explanation: 'Insecure Direct Object Reference (IDOR) also applies to lists. You should never return *all* items from a table if they are private. Always filter your database queries using the ID of the currently logged-in user.'
      },
      {
        scenario: 'An internal API for system health is publicly accessible if someone guesses the URL /api/v1/health/stats.',
        vulnerable_code: `export async function GET(req) {\n  const stats = await getSystemStats();\n  return Response.json(stats);\n}`,
        fix_steps: ['Add a middleware check.', 'Require an admin session.', 'Hide behind internal networking.'],
        patched_code: `export async function GET(req) {\n  const user = await getSessionUser(req);\n  if (user?.role !== 'ADMIN') return Response.json({ error: 'Forbidden' }, { status: 403 });\n  const stats = await getSystemStats();\n  return Response.json(stats);\n}`,
        check_logic: (input) => input.includes('ADMIN'),
        explanation: 'Security through obscurity (hiding a URL) is not real security. Even if a URL is long and complex, an attacker can find it via logs, browser history, or brute force. Every single "internal" or "admin" API must verify the user\'s role.'
      },
      {
        scenario: 'A user profile page displays the user\'s internal database ID in the URL /profile/5501.',
        vulnerable_code: `return <a href={\`/profile/\${user.id}\`}>View Profile</a>;`,
        fix_steps: ['Use UUIDs or Slugs.', 'Hide the numeric ID.', 'Prevent sequential guessing.'],
        patched_code: `return <a href={\`/profile/\${user.username}\`}>View Profile</a>;`,
        check_logic: (input) => input.includes('username'),
        explanation: 'While not a direct exploit, using sequential numeric IDs (`1`, `2`, `3`...) allows attackers to "map" your entire user base very easily. Using a random UUID or a unique username (slug) makes it much harder to automate data theft.'
      },
      {
        scenario: 'A file download endpoint trusts an "ownerId" provided as a query parameter.',
        vulnerable_code: `const { id, ownerId } = params;\nconst file = await db.files.get(id, ownerId);`,
        fix_steps: ['Verify session ID against ownerId.', 'Don\'t take ownerId from user.', 'Use server-side source of truth.'],
        patched_code: `const user = await getSessionUser(req);\nconst file = await db.files.get(id, user.id);`,
        check_logic: (input) => input.includes('user.id'),
        explanation: 'If you take the `ownerId` from the user, they can just change `ownerId=123` to `ownerId=1` to see the admin\'s files. Always use the user ID from the secure session cookie, which the user cannot tamper with.'
      },
      {
        scenario: 'A user can update their balance by modifying a local storage value that the app then sends to the server.',
        vulnerable_code: `const balance = localStorage.getItem('balance');\nawait api.updateBalance(balance);`,
        fix_steps: ['Never trust client-side data for state.', 'Calculate balance on server.', 'Use server as source of truth.'],
        patched_code: `// No action needed on client. Server calculates it.\nawait api.syncTransaction();`,
        check_logic: (input) => !input.includes('localStorage'),
        explanation: 'The client-side (the browser) is under the full control of the user. They can change anything in `localStorage` or `cookies`. Crucial data like "account balance" or "item price" must always be calculated and stored on your secure server.'
      },
      {
        scenario: 'A "Forgot Password" feature leaks whether an email exists in the system by returning Different messages.',
        vulnerable_code: `if (userExists) return Response.json({ status: 'Email sent' });\nreturn Response.json({ status: 'Email not found' }, { status: 404 });`,
        fix_steps: ['Return a generic message.', 'Always return the same response.', 'Prevent account harvesting.'],
        patched_code: `// Always return success\nreturn Response.json({ status: 'If an account exists, a reset link has been sent' });`,
        check_logic: (input) => input.includes('If an account exists'),
        explanation: 'Account Harvesting is when hackers test thousands of emails to see which ones are registered. By giving the same generic "Check your inbox" message regardless of whether the email was found, you protect your users\' privacy.'
      },
      {
        scenario: 'A multi-tenant app allows users to access "Organization" settings by just changing the orgId in the URL.',
        vulnerable_code: `export async function GET(req) {\n  const orgId = req.url.split('/')[4];\n  const settings = await db.org.get(orgId);\n  return Response.json(settings);\n}`,
        fix_steps: ['Check if user belongs to Org.', 'Validate membership in DB.', 'Strict tenancy isolation.'],
        patched_code: `export async function GET(req) {\n  const user = await getSessionUser(req);\n  const orgId = req.url.split('/')[4];\n  if (user.orgId !== orgId) return Response.json({ error: 'Access Denied' }, { status: 403 });\n  const settings = await db.org.get(orgId);\n  return Response.json(settings);\n}`,
        check_logic: (input) => input.includes('user.orgId !== orgId'),
        explanation: 'In apps with "Teams" or "Orgs," you must verify that the user actually belongs to the organization they are trying to view. This "Tenancy" check is vital to prevent one company from accidentally seeing another company\'s data.'
      }
    ]
  },
  'csrf': {
    title: 'CSRF Protection',
    variants: [
      {
        scenario: 'A sensitive action relies solely on session cookies, making it vulnerable to Cross-Site Request Forgery.',
        vulnerable_code: `export async function POST(req) {\n  const { email } = await req.json();\n  await db.user.updateEmail(email);\n  return Response.json({ success: true });\n}`,
        fix_steps: ['Use Server Actions (auto-CSRF).', 'Implement Anti-CSRF tokens.', 'Use SameSite=Strict cookies.'],
        patched_code: `export async function updateEmailAction(formData) {\n  const user = await auth();\n  if (!user) throw new Error('Unauthorized');\n  await db.user.updateEmail(formData.get('email'));\n}`,
        check_logic: (input) => input.includes('formData') || input.includes('auth()'),
        explanation: 'In Next.js, "Server Actions" automatically include CSRF protection. They ensure the request came from your own website and not a malicious site trying to perform actions on your behalf while you\'re logged in.'
      },
      {
        scenario: 'A "Delete Account" feature uses a GET request. Attackers can trigger it via simple <img> or <a> tags.',
        vulnerable_code: `export async function GET(req) {\n  const session = await getSession(req);\n  if (session) await db.users.delete(session.user.id);\n}`,
        fix_steps: ['Never use GET for state changes.', 'Convert to POST.', 'Require an explicit button or form.'],
        patched_code: `// Use a POST route with CSRF protection\nexport async function POST(req) {\n  const session = await auth();\n  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });\n  await db.users.delete(session.user.id);\n  return Response.json({ success: true });\n}`,
        check_logic: (input) => input.includes('POST') || input.includes('auth()'),
        explanation: 'GET requests should only be used for reading data, never for changing it. Browsers and search engines might pre-fetch GET links, which could accidentally trigger a "Delete" action if you\'re not careful. Use POST for all actions that modify data.'
      },
      {
        scenario: 'A sensitive form is missing a CSRF token, allowing attackers to submit it on behalf of the user via a hidden iframe.',
        vulnerable_code: `<form action="/update-profile" method="POST">\n  <input name="bio" />\n</form>`,
        fix_steps: ['Add a hidden CSRF token.', 'Verify it on the server.', 'Use a modern framework helper.'],
        patched_code: `<form action="/update-profile" method="POST">\n  <input type="hidden" name="csrf_token" value={token} />\n  <input name="bio" />\n</form>`,
        check_logic: (input) => input.includes('csrf_token'),
        explanation: 'A CSRF token is a "secret handshake" between your server and the browser. Because a malicious site doesn\'t know this secret token, it can\'t successfully submit forms to your server on the user\'s behalf.'
      },
      {
        scenario: 'The server accepts session cookies with "SameSite=None", allowing cross-origin requests to include the session.',
        vulnerable_code: `cookies().set('session', id, { sameSite: 'none' });`,
        fix_steps: ['Change to "SameSite=Lax".', 'Use "Strict" for high security.', 'Rely on browser defaults.'],
        patched_code: `cookies().set('session', id, { sameSite: 'lax' });`,
        check_logic: (input) => input.includes("sameSite: 'lax'"),
        explanation: '`SameSite=Lax` is the modern standard. It tells the browser: "Only send this cookie if the user is actually on my website." This blocked most CSRF attacks by default because malicious third-party sites can\'t include your login cookie anymore.'
      },
      {
        scenario: 'An API relies on a custom header like "X-Requested-With" but fails to check it on the server.',
        vulnerable_code: `export async function POST(req) {\n  // Processing immediately...\n  return Response.json({ ok: true });\n}`,
        fix_steps: ['Verify header presence.', 'Ensure it matches expectations.', 'Reject if missing.'],
        patched_code: `export async function POST(req) {\n  if (req.headers.get('X-Requested-With') !== 'XMLHttpRequest') {\n    return Response.json({ error: 'Bad Request' }, { status: 400 });\n  }\n  // ... process\n}`,
        check_logic: (input) => input.includes('X-Requested-With'),
        explanation: 'While not a perfect fix, checking for custom headers helps because browsers don\'t allow cross-origin sites to add custom headers without "CORS" permission. This provides an extra layer of defense for your AJAX APIs.'
      },
      {
        scenario: 'The app allows setting the "Access-Control-Allow-Origin" to "*" (wildcard), which allows any site to read sensitive data.',
        vulnerable_code: `res.headers.set('Access-Control-Allow-Origin', '*');`,
        fix_steps: ['Specify exact origins.', 'Check against a whitelist.', 'Never use "*" for authenticated APIs.'],
        patched_code: `const allowed = ['https://myapp.com', 'https://api.myapp.com'];\nif (allowed.includes(origin)) res.headers.set('Access-Control-Allow-Origin', origin);`,
        check_logic: (input) => !input.includes("'*'"),
        explanation: 'CORS (Cross-Origin Resource Sharing) is a browser security feature. Using `*` is like leaving your front door wide open. You should only allow specific, trusted domains to talk to your API to prevent data theft from malicious scripts.'
      },
      {
        scenario: 'Sensitive actions like "Change Password" don\'t require any user interaction other than the form submit.',
        vulnerable_code: `// Just a simple POST to /change-password`,
        fix_steps: ['Require the "Old Password".', 'Use an MFA challenge.', 'Confirm via email.'],
        patched_code: `const { oldPassword, newPassword } = await req.json();\nconst ok = await verify(user, oldPassword);\nif (!ok) return Response.json({ error: 'Wrong password' }, { status: 401 });`,
        check_logic: (input) => input.includes('oldPassword'),
        explanation: 'For extremely sensitive actions, "Defense in Depth" is best. Even if CSRF protection works, requiring the "Old Password" ensures that the person sitting at the computer is truly the owner before allowing a permanent account change.'
      },
      {
        scenario: 'A "Transfer Funds" feature uses a predictable URL that can be triggered by a link in a phishing email.',
        vulnerable_code: `<a href="https://bank.com/transfer?to=hacker&amount=1000">Win a Prize!</a>`,
        fix_steps: ['Use POST exclusively.', 'Add CSRF tokens.', 'Use a confirmation step.'],
        patched_code: `// Only accept POST\nexport async function POST(req) {\n  const token = req.headers.get('x-csrf-token');\n  // ... verify token and process\n}`,
        check_logic: (input) => input.includes('POST'),
        explanation: 'Using GET for actions is a gift to hackers. They can hide that link in an image tag `<img src="...">` and your browser will try to "load" the link, accidentally transferring money if you are logged in. Always use POST for actions.'
      },
      {
        scenario: 'An app uses "Bearer" tokens in local storage but doesn\'t protect the API from cross-site scripts (XSS + CSRF combo).',
        vulnerable_code: `const token = localStorage.getItem('token');\nfetch('/api/data', { headers: { Authorization: \`Bearer \${token}\` } });`,
        fix_steps: ['Use HttpOnly cookies.', 'Implement Strict Content-Security-Policy.', 'Avoid storing secrets in JS accessible memory.'],
        patched_code: `// Move to secure cookies\n// Browser handles Authorization automatically\nfetch('/api/data');`,
        check_logic: (input) => !input.includes('localStorage.getItem'),
        explanation: 'If a token is in `localStorage`, any XSS attack can steal it. By moving to `HttpOnly` cookies, the browser handles the token automatically and keeps it hidden from JavaScript, making it much harder to steal or misuse.'
      },
      {
        scenario: 'The app lacks a "Content-Security-Policy" (CSP) to restrict where forms can be submitted (form-action).',
        vulnerable_code: `// No CSP headers set`,
        fix_steps: ['Set "form-action" to "self".', 'Restrict external endpoints.', 'Monitor violations.'],
        patched_code: `res.headers.set('Content-Security-Policy', "form-action 'self'");`,
        check_logic: (input) => input.includes('form-action'),
        explanation: 'CSP isn\'t just for scripts! The `form-action` directive tells the browser: "Only allow forms on this site to be sent to these specific URLs." This prevents "Form Hijacking" where an attacker redirects your login form to their own server.'
      }
    ]
  },
  'security-headers': {
    title: 'Security Headers',
    variants: [
      {
        scenario: 'Missing critical headers like CSP, leaving the site vulnerable to clickjacking and script injection.',
        vulnerable_code: `const res = NextResponse.next();\nreturn res;`,
        fix_steps: ['Set X-Frame-Options.', 'Set nosniff.', 'Apply Content-Security-Policy.'],
        patched_code: `const res = NextResponse.next();\nres.headers.set('X-Frame-Options', 'DENY');\nres.headers.set('Content-Security-Policy', "default-src 'self'");\nreturn res;`,
        check_logic: (input) => input.includes('Content-Security-Policy'),
        explanation: 'Security headers tell the browser how to behave. `X-Frame-Options: DENY` stops your site from being put in an iframe (preventing clickjacking), and `Content-Security-Policy` restricts where scripts can be loaded from, stopping hackers from injecting malicious code.'
      },
      {
        scenario: 'The site is missing HSTS (HTTP Strict Transport Security), allowing attackers to downgrade connections to plaintext HTTP.',
        vulnerable_code: `// Regular response without HSTS headers`,
        fix_steps: ['Add Strict-Transport-Security header.', 'Specify a long max-age.', 'Include subdomains.'],
        patched_code: `res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');`,
        check_logic: (input) => input.includes('Strict-Transport-Security'),
        explanation: 'HSTS tells the browser: "Always talk to this site over HTTPS, even if I accidentally type http://." This prevents "SSL Stripping" attacks where a hacker on public Wi-Fi tries to trick your browser into using an unencrypted connection.'
      },
      {
        scenario: 'The site sends a "Referer" header with full URL details to third-party sites, potentially leaking sensitive tracking tokens.',
        vulnerable_code: `// Default browser behavior (sends full URL)`,
        fix_steps: ['Set Referrer-Policy header.', 'Use "strict-origin-when-cross-origin".', 'Restrict info shared with others.'],
        patched_code: `res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');`,
        check_logic: (input) => input.includes('Referrer-Policy'),
        explanation: 'The `Referrer-Policy` header controls how much information your browser sends to other sites when you click a link. By setting it to `strict-origin-when-cross-origin`, you ensure that sensitive details like `?token=123` in your URL aren\'t leaked to external websites.'
      },
      {
        scenario: 'The site doesn\'t restrict browser features like camera or microphone, which could be exploited by an XSS attack.',
        vulnerable_code: `// No Permissions-Policy header`,
        fix_steps: ['Add Permissions-Policy header.', 'Disable unused features.', 'Explicitly allow only "self".'],
        patched_code: `res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');`,
        check_logic: (input) => input.includes('Permissions-Policy'),
        explanation: '`Permissions-Policy` (formerly Feature-Policy) allows you to turn off browser features you don\'t need. If your app doesn\'t use the camera, disabling it via this header prevents a hacker from using a script to spy on your users even if they find a small security bug elsewhere.'
      },
      {
        scenario: 'The site is vulnerable to "MIME Sniffing" where the browser might execute a text file as a script.',
        vulnerable_code: `// No X-Content-Type-Options header`,
        fix_steps: ['Set X-Content-Type-Options: nosniff.', 'Force the browser to respect Content-Type.', 'Prevent drive-by-downloads.'],
        patched_code: `res.headers.set('X-Content-Type-Options', 'nosniff');`,
        check_logic: (input) => input.includes('nosniff'),
        explanation: 'Sometimes browsers try to be "helpful" by guessing what a file is. If an attacker uploads a text file containing JavaScript, a browser might "sniff" it and run the script. `nosniff` shuts down this behavior, forcing the browser to follow the server\'s instructions exactly.'
      },
      {
        scenario: 'The site allows itself to be embedded in "Cross-Origin" context, making it vulnerable to data theft via side-channels.',
        vulnerable_code: `// No COEP/COOP headers`,
        fix_steps: ['Set Cross-Origin-Embedder-Policy.', 'Set Cross-Origin-Opener-Policy.', 'Isolate the browsing context.'],
        patched_code: `res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');\nres.headers.set('Cross-Origin-Embedder-Policy', 'require-corp');`,
        check_logic: (input) => input.includes('Opener-Policy'),
        explanation: 'COOP and COEP are advanced headers that create a "box" around your website. They ensure that other sites cannot interact with your page in the browser\'s memory, which is a defense against modern CPU-level vulnerabilities like Spectre or Meltdown.'
      },
      {
        scenario: 'The site doesn\'t specify where its resources (images, styles) can come from, allowing attackers to load malicious assets.',
        vulnerable_code: `// Weak or missing CORP header`,
        fix_steps: ['Set Cross-Origin-Resource-Policy.', 'Use "same-site" or "same-origin".', 'Restrict resource sharing.'],
        patched_code: `res.headers.set('Cross-Origin-Resource-Policy', 'same-origin');`,
        check_logic: (input) => input.includes('Resource-Policy'),
        explanation: '`Cross-Origin-Resource-Policy` (CORP) is like a "DO NOT SHARE" sign for your images and scripts. It tells the browser whether other websites are allowed to "borrow" your site\'s images or data. Setting it to `same-origin` keeps your assets private to your own site.'
      },
      {
        scenario: 'The app wants to test a new CSP without actually breaking the site for users.',
        vulnerable_code: `// No CSP header or enforcing a broken one`,
        fix_steps: ['Use Content-Security-Policy-Report-Only.', 'Specify a report-to endpoint.', 'Analyze the logs before enforcing.'],
        patched_code: `res.headers.set('Content-Security-Policy-Report-Only', "default-src 'self'; report-uri /api/report");`,
        check_logic: (input) => input.includes('Report-Only'),
        explanation: '`Report-Only` mode is the "safe way" to implement a CSP. It doesn\'t block anything, but it sends a report to your server whenever a rules *would* have been broken. This lets you debug your policy and ensure your app still works before you flip the switch to full protection.'
      },
      {
        scenario: 'The site lacks "Expect-CT" headers, which monitor for fraudulent SSL certificates.',
        vulnerable_code: `// No Expect-CT header`,
        fix_steps: ['Add Expect-CT header.', 'Enforce certificate transparency.', 'Set a report-uri.'],
        patched_code: `res.headers.set('Expect-CT', 'max-age=86400, enforce, report-uri="https://report.example.com"');`,
        check_logic: (input) => input.includes('Expect-CT'),
        explanation: 'Expect-CT (Certificate Transparency) is a security standard that helps you detect if someone has issued a fake SSL certificate for your domain. It ensures that only certificates "publicly logged" in trusted databases are accepted by the browser.'
      },
      {
        scenario: 'The site is accessible via port 80 and doesn\'t redirect to 443, making it vulnerable to sniffing.',
        vulnerable_code: `// Basic HTTP server on port 80`,
        fix_steps: ['Detect port 80.', 'Redirect (301) to HTTPS.', 'Close all non-SSL endpoints.'],
        patched_code: `if (req.headers.get('x-forwarded-proto') === 'http') {\n  return NextResponse.redirect(\`https://\${req.headers.get('host')}\${req.nextUrl.pathname}\`, 301);\n}`,
        check_logic: (input) => input.includes('301') && input.includes('https'),
        explanation: 'Encryption isn\'t optional anymore. Most hosts provide the `x-forwarded-proto` header to tell you if a user is on HTTP. By forcing a 301 (Permanent) redirect to HTTPS, you ensure that no user ever accidentally sends their password over an unencrypted link.'
      }
    ]
  },
  'rate-limiting': {
    title: 'Rate Limiting',
    variants: [
      {
        scenario: 'No limits on login attempts, allowing attackers to brute-force passwords.',
        vulnerable_code: `export async function POST(req) {\n  const { user, pass } = await req.json();\n  const ok = await login(user, pass);\n  return Response.json({ ok });\n}`,
        fix_steps: ['Implement bucket limiting.', 'Slow down repeated failures.', 'Return 429 status.'],
        patched_code: `const limiter = new RateLimiter({ max: 5 });\nif (limiter.isLimited(req.ip)) return Response.json({ error: 'Retry later' }, { status: 429 });\n// ... login logic`,
        check_logic: (input) => input.includes('429'),
        explanation: 'Rate limiting acts like a speed bump. If a user (or a bot) tries to log in too many times in a short period, we return a `429 Too Many Requests` error. This makes it much harder for attackers to guess passwords using automated tools.'
      },
      {
        scenario: 'The app lacks throttling for API keys, allowing a single customer to overwhelm the entire backend by mistake.',
        vulnerable_code: `export async function GET(req) {\n  const apiKey = req.headers.get('x-api-key');\n  // process request...\n}`,
        fix_steps: ['Limit by API key.', 'Calculate bucket per key.', 'Return 429 when empty.'],
        patched_code: `const usage = await db.apiUsage.get(apiKey);\nif (usage.count > 1000) return Response.json({ error: 'Limit exceeded' }, { status: 429 });\nawait db.apiUsage.increment(apiKey);`,
        check_logic: (input) => input.includes('apiKey') && input.includes('429'),
        explanation: 'When providing an API, you should limit how much each user can do. By tracking usage per `apiKey`, you ensure that one "noisy neighbor" (or a buggy client script) doesn\'t slow down your app for everyone else.'
      },
      {
        scenario: 'The app allows sudden "bursts" of traffic from a single IP, which can trigger high server costs or resource lag.',
        vulnerable_code: `// No burst control`,
        fix_steps: ['Implement "Leaky Bucket".', 'Allow small bursts.', 'Smooth out the rate over time.'],
        patched_code: `const bucket = new LeakyBucket({ capacity: 10, fillRate: 1 });\nif (!bucket.consume()) return Response.json({ error: 'Burst limit' }, { status: 429 });`,
        check_logic: (input) => input.includes('capacity') || input.includes('fillRate'),
        explanation: 'The "Leaky Bucket" algorithm allows users to do a few things very fast (a "burst"), but then forces them to slow down to a steady rate. This mimics real-world usage where humans click fast occasionally, but bots click fast constantly.'
      },
      {
        scenario: 'The app returns the same error immediately on login failure, making it easy for bots to check thousands of accounts.',
        vulnerable_code: `if (!ok) return Response.json({ error: 'Fail' });`,
        fix_steps: ['Add an artificial delay.', 'Use exponential backoff.', 'Slowing down the attacker.'],
        patched_code: `if (!ok) {\n  const delay = calculateBackoff(failedAttempts);\n  await new Promise(r => setTimeout(r, delay));\n  return Response.json({ error: 'Fail' });\n}`,
        check_logic: (input) => input.includes('setTimeout') || input.includes('delay'),
        explanation: 'Exponential Backoff makes the wait longer for every failed attempt (e.g., 1 sec, then 2, then 4...). For a human who just forgot their password, a 1-second delay is fine. For a bot trying 10,000 passwords, these delays turn a 1-hour attack into a 1-year attack!'
      },
      {
        scenario: 'A "Search" feature is very expensive for the database, and attackers are spamming it to cause a DoS (Denial of Service).',
        vulnerable_code: `// No special limits on /search`,
        fix_steps: ['Limit expensive routes strictly.', 'Monitor DB query duration.', 'Use high-difficulty CAPTCHAs if needed.'],
        patched_code: `const searchLimiter = new RateLimiter({ max: 5, windowMs: 60000 });\nif (searchLimiter.isLimited(req.ip)) return Response.json({ error: 'Slow down' }, { status: 429 });`,
        check_logic: (input) => input.includes('searchLimiter'),
        explanation: 'Not all web pages are equal. A homepage is easy to show, but a "Complex Search" makes the server work very hard. You should apply much stricter rate limits to the "heavy" parts of your app to prevent attackers from burning your CPU/RAM.'
      },
      {
        scenario: 'The app allows a single user to open 100 simultaneous connections, hogging all available worker threads.',
        vulnerable_code: `// No concurrent connection limit`,
        fix_steps: ['Track active connections.', 'Set a maximum per IP.', 'Close idle sockets.'],
        patched_code: `if (connectionsByIP[ip] > 10) return req.destroy(); // Hard drop`,
        check_logic: (input) => input.includes('connectionsByIP'),
        explanation: 'Even if a user doesn\'t send many requests, they can still crash a server by just keeping "connections open" (Slowloris attack). Limiting concurrent connections ensures that no single user can "hog" the server\'s attention.'
      },
      {
        scenario: 'The server doesn\'t provide a "Retry-After" header, so clients just keep spamming instead of waiting.',
        vulnerable_code: `return Response.json({ error: 'Limited' }, { status: 429 });`,
        fix_steps: ['Add Retry-After header.', 'Tell the client when to return.', 'Improve client-side UX.'],
        patched_code: `return Response.json({ error: 'Limited' }, {\n  status: 429,\n  headers: { 'Retry-After': '60' }\n});`,
        check_logic: (input) => input.includes('Retry-After'),
        explanation: 'When you block a user, it is polite (and secure!) to tell them when they can try again. The `Retry-After` header tells well-behaved bots and browsers precisely how many seconds to wait, reducing useless traffic on your server.'
      },
      {
        scenario: 'The rate limiter resets exactly at the start of every minute, allowing a "double burst" right at the boundary.',
        vulnerable_code: `const window = Math.floor(Date.now() / 60000);`,
        fix_steps: ['Use a Sliding Window algorithm.', 'Smooth out resets.', 'Prevent edge-case spikes.'],
        patched_code: `const limiter = new SlidingWindowLimiter({ windowMs: 60000, max: 10 });`,
        check_logic: (input) => input.includes('SlidingWindow'),
        explanation: 'A fixed window (e.g., "10 per minute") allows someone to do 10 at 10:59:59 and 10 more at 11:00:00. A "Sliding Window" looks at the *past* 60 seconds continuously, providing a much smoother and more reliable security barrier.'
      },
      {
        scenario: 'Rate limiting is only applied in the app, but not on the load balancer, leaving the node process vulnerable to memory floods.',
        vulnerable_code: `// Limiting only in app.js`,
        fix_steps: ['Use NGINX/Cloudflare limits.', 'Offload traffic early.', 'Protect the origin server.'],
        patched_code: `// NGINX Config\n// limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;`,
        check_logic: (input) => input.includes('NGINX'),
        explanation: 'Real-world apps use a "First Line of Defense." By the time a request hits your JavaScript code, it has already used up server resources. Using a tool like NGINX or Cloudflare to block bad traffic *before* it reaches your app is much more efficient.'
      },
      {
        scenario: 'The app doesn\'t adjust its rate limits based on current server health (e.g., high CPU).',
        vulnerable_code: `const limit = 100; // Fixed`,
        fix_steps: ['Monitor system load.', 'Reduce limits dynamically.', 'Fail safe under pressure.'],
        patched_code: `const cpuLoad = os.loadavg()[0];\nconst dynamicLimit = cpuLoad > 5 ? 10 : 100;\nif (reqCount > dynamicLimit) return 429;`,
        check_logic: (input) => input.includes('loadavg'),
        explanation: 'Static limits are okay, but "Dynamic Throttling" is pro-level. If your server is currently struggling (high CPU), you can automatically lower the rate limits to prioritize essential users and keep the ship from sinking.'
      }
    ]
  },
  'sql-injection': {
    title: 'SQL Injection',
    variants: [
      {
        scenario: 'User input is directly concatenated into a SQL string.',
        vulnerable_code: `const query = \`SELECT * FROM users WHERE email = '\${email}'\`;\nconst user = await db.query(query);`,
        fix_steps: ['Use parameterized queries.', 'Never concatenate raw input.', 'Sanitize inputs.'],
        patched_code: `const user = await db.query('SELECT * FROM users WHERE email = ?', [email]);`,
        check_logic: (input) => input.includes('?') && input.includes('[]'),
        explanation: 'Concatenating strings for SQL is dangerous because a user could type `\' OR 1=1 --` as their email to bypass the login. Using `?` placeholders tells the database to treat the input as pure data, not as executable code.'
      },
      {
        scenario: 'A search feature uses template literals for the "LIKE" clause.',
        vulnerable_code: `const query = \`SELECT * FROM products WHERE name LIKE '%\${searchTerm}%'\`;\nconst results = await db.execute(query);`,
        fix_steps: ['Use placeholders.', 'Pass search term as array argument.', 'Prevent UNION-based injection.'],
        patched_code: `const results = await db.execute('SELECT * FROM products WHERE name LIKE ?', [\`%\${searchTerm}%\`]);`,
        check_logic: (input) => input.includes('?') && input.includes('searchTerm'),
        explanation: 'Even for partial matches like `LIKE`, you must use placeholders. We move the wildcards (`%`) into the parameter array so the database can safely handle the search string without any risk of injection.'
      },
      {
        scenario: 'An attacker uses a "Boolean-based" Blind SQLi to steal data by checking if a page returns "Success" or "Error".',
        vulnerable_code: `const query = \`SELECT * FROM users WHERE id = \${id} AND password LIKE '\${guess}%'\`;\nconst results = await db.query(query);\nreturn results.length > 0 ? 'Found' : 'Not Found';`,
        fix_steps: ['Use parameterized queries.', 'Ensure uniform error/success messages.', 'Hide exact counts or state.'],
        patched_code: `const results = await db.query('SELECT * FROM users WHERE id = ?', [id]);\n// Don't leak detail about the secondary check\nreturn results.length > 0 ? 'Active' : 'Missing';`,
        check_logic: (input) => input.includes('?'),
        explanation: 'In "Blind" SQLi, the attacker can\'t see the data, but they can "ask" the database questions (like "Does the admin password start with A?"). If the page looks Different, they know the answer! Placeholders stop the attacker from "asking" these extra questions.'
      },
      {
        scenario: 'An attacker uses a "Time-based" Blind SQLi to extract data by making the database "sleep" if a condition is true.',
        vulnerable_code: `const query = \`SELECT * FROM items WHERE id = \${id}\`;\nawait db.query(query);`,
        fix_steps: ['Prevent user-controlled WHERE clauses.', 'Set short query timeouts.', 'Use placeholders for all numeric IDs.'],
        patched_code: `const results = await db.query('SELECT * FROM items WHERE id = ?', [parseInt(id)]);`,
        check_logic: (input) => input.includes('parseInt') && input.includes('?'),
        explanation: 'Attackers sometimes use commands like `SLEEP(10)`. If the website takes 10 seconds to load, they know their injection worked. By using `?` placeholders and strictly converting inputs to numbers with `parseInt`, you block these "invisible" attacks.'
      },
      {
        scenario: 'Data saved to the database is later used in another query without being sanitized, leading to "Second-Order" injection.',
        vulnerable_code: `const user = await db.query('SELECT * FROM profile');\nconst stats = await db.query(\`SELECT * FROM logs WHERE user = '\${user.name}'\`);`,
        fix_steps: ['Always use placeholders, even for DB data.', 'Never trust data just because it comes from your own DB.', 'Sanitize on the way out.'],
        patched_code: `const user = await db.query('SELECT * FROM profile');\nconst stats = await db.query('SELECT * FROM logs WHERE user = ?', [user.name]);`,
        check_logic: (input) => input.includes('?'),
        explanation: 'Just because data is already in your database doesn\'t mean it is safe! A hacker might have saved their username as `admin\' --` earlier. If you use that name in a *new* query without placeholders, it will break the logic. Stay safe by ALWAYS using `?` for every query.'
      },
      {
        scenario: 'An attacker uses "Out-of-Band" SQLi to make the database send his server a DNS or HTTP request containing your data.',
        vulnerable_code: `const query = \`SELECT * FROM users WHERE id = \${id}\`;`,
        fix_steps: ['Disable database features like xp_cmdshell.', 'Use Least Privilege accounts.', 'Block outgoing traffic from the DB.'],
        patched_code: `const user = await db.query('SELECT * FROM users WHERE id = ?', [id]);`,
        check_logic: (input) => input.includes('?'),
        explanation: 'Some databases (like SQL Server or Oracle) can talk to the internet! Out-of-Band attacks trick the DB into "leaking" secrets to a hacker\'s computer via a background request. Using placeholders and locking down your database server prevents this "invisible" data theft.'
      },
      {
        scenario: 'The app uses raw SQL strings instead of taking advantage of an ORM (Object-Relational Mapper) safety features.',
        vulnerable_code: `const user = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);`,
        fix_steps: ['Use an ORM like Prisma or Sequelize.', 'Use built-in find methods.', 'Avoid "Raw" query bypasses.'],
        patched_code: `const user = await prisma.user.findUnique({ where: { id: Number(id) } });`,
        check_logic: (input) => input.includes('prisma') || input.includes('findUnique'),
        explanation: 'ORMs like Prisma are great because they handle security for you. Instead of writing risky SQL strings, you just ask for a `findUnique` item. The ORM automatically builds a safe, parameterized query in the background that is immune to injection.'
      },
      {
        scenario: 'The app leaks detailed SQL error messages to the user, helping them map the table structure.',
        vulnerable_code: `catch (e) { return Response.json({ error: e.message }); }`,
        fix_steps: ['Log errors internally.', 'Return a generic "Server Error" to users.', 'Hide table and column names.'],
        patched_code: `catch (e) {\n  logger.error(e);\n  return Response.json({ error: 'Internal Database Error' }, { status: 500 });\n}`,
        check_logic: (input) => !input.includes('e.message'),
        explanation: 'Detailed errors like `Syntax error near column "credit_card"` are like a treasure map for hackers. They tell them exactly what columns exist! Always log the real error for yourself, but give the user a boring, generic message like "Server Error."'
      },
      {
        scenario: 'A "Stored Procedure" is used, but the input is concatenated inside the DB instead of passed as a parameter.',
        vulnerable_code: `await db.query(\`CALL GetUser('\${id}')\`);`,
        fix_steps: ['Use SP parameters.', 'Pass inputs as array.', 'Strictly type the procedure inputs.'],
        patched_code: `await db.query('CALL GetUser(?)', [id]);`,
        check_logic: (input) => input.includes('?'),
        explanation: 'Stored Procedures (SPs) aren\'t a magic shield. If you build the procedure call by adding strings together, you are still vulnerable! You must pass the variables as separate parameters so the database knows what is "code" and what is "data."'
      },
      {
        scenario: 'The database user for the web app has "DB Owner" permissions, allowing an attacker to drop tables or read system files.',
        vulnerable_code: `// Logging in as 'sa' or 'root'`,
        fix_steps: ['Use a limited user account.', 'Grant only SELECT, INSERT, UPDATE.', 'Deny DROP or ALTER table.'],
        patched_code: `const db = connect({\n  user: 'app_user',\n  password: process.env.DB_PASSWORD\n});`,
        check_logic: (input) => input.includes('app_user'),
        explanation: 'This is the "Principle of Least Privilege." If a hacker manages to find a SQL injection bug, you don\'t want them to be able to delete your whole database! A "limited" computer account can only read and write data, keeping your system safe from destruction.'
      }
    ]
  },
  'xss': {
    title: 'Cross-Site Scripting',
    variants: [
      {
        scenario: 'Rendering user-provided bio content directly in HTML using "dangerouslySetInnerHTML".',
        vulnerable_code: `<div dangerouslySetInnerHTML={{ __html: user.bio }} />`,
        fix_steps: ['Escape HTML characters.', 'Use a library like DOMPurify.', 'Avoid raw innerHTML if possible.'],
        patched_code: `import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bio) }} />`,
        check_logic: (input) => input.includes('sanitize') || input.includes('DOMPurify'),
        explanation: '`dangerouslySetInnerHTML` is just like its name—dangerous! If a user puts `<script>alert("hack")</script>` in their bio, it will run. `DOMPurify` cleans the HTML, removing all dangerous tags and keeping only the safe ones like `<b>` or `<i>`.'
      },
      {
        scenario: 'Displaying a search query from the URL directly in the page without escaping.',
        vulnerable_code: `return <h1>Results for {searchParams.q}</h1>;`,
        fix_steps: ['React escapes strings by default, but be careful with hrefs or scripts.', 'Ensure no raw injection via URL params.'],
        patched_code: `// React handles this safely if it is a string\nreturn <h1>Results for {String(searchParams.q)}</h1>;`,
        check_logic: (input) => input.includes('String(') || true,
        explanation: 'React is actually very safe for beginners! It automatically "escapes" any strings you put inside curly braces `{}`. This means that even if a user puts a script tag in the URL, React will just show it as text on the screen instead of running it.'
      },
      {
        scenario: 'Malicious scripts are injected via an "href" attribute starting with "javascript:".',
        vulnerable_code: `<a href={user.website}>Visit Website</a>`,
        fix_steps: ['Validate URL protocol.', 'Only allow http/https.', 'Sanitize the URL.'],
        patched_code: `const safeUrl = user.website.startsWith('http') ? user.website : '#';\n<a href={safeUrl}>Visit Website</a>`,
        check_logic: (input) => input.includes('startsWith'),
        explanation: 'Even if React escapes text, it doesn\'t stop `javascript:alert(1)` in an `href`. This is a unique type of XSS. You must always check that URLs provided by users start with `http://` or `https://` before putting them in a link.'
      },
      {
        scenario: 'A message board allows users to post comments that are rendered as HTML, but missing "onerror" sanitization.',
        vulnerable_code: `<img src={user.avatar} />`,
        fix_steps: ['Sanitize all attributes.', 'Escape data before rendering.', 'Use a safe image component.'],
        patched_code: `const safeAvatar = DOMPurify.sanitize(user.avatar);\n<img src={safeAvatar} />`,
        check_logic: (input) => input.includes('sanitize'),
        explanation: 'Attackers use "Event Handlers" like `onerror`. If they set an image source to a fake URL and add `onerror="alert(1)"`, the script runs when the image fails to load. Sanitizing attributes with `DOMPurify` removes these dangerous handlers.'
      },
      {
        scenario: 'The application uses "eval()" to process a JSON string provided by the user.',
        vulnerable_code: `const data = eval('(' + userData + ')');`,
        fix_steps: ['Always use JSON.parse().', 'Never use eval() with user input.', 'Validate the parsed object.'],
        patched_code: `const data = JSON.parse(userData);`,
        check_logic: (input) => input.includes('JSON.parse'),
        explanation: '`eval()` is one of the most dangerous functions in JavaScript. It executes any string as code. An attacker could send a string that steals your session or deletes data. `JSON.parse` is the safe, modern way to turn text into an object.'
      },
      {
        scenario: 'A "Click Tracking" script uses "document.write()" to inject tracking pixels from a URL parameter.',
        vulnerable_code: `document.write('<img src="' + params.pixelUrl + '">');`,
        fix_steps: ['Use modern DOM APIs.', 'Avoid document.write().', 'Sanitize the URL.'],
        patched_code: `const img = document.createElement('img');\nimg.src = sanitize(params.pixelUrl);\ndocument.body.appendChild(img);`,
        check_logic: (input) => input.includes('createElement'),
        explanation: '`document.write` is an old and dangerous way to add content. It bypasses many modern protections. Using `createElement` and setting the `src` attribute is much safer because it doesn\'t parse the input as a string of HTML code.'
      },
      {
        scenario: 'A Next.js "App Router" page uses "dangerouslySetInnerHTML" inside a client component without a CSP.',
        vulnerable_code: `<div dangerouslySetInnerHTML={{ __html: post.content }} />`,
        fix_steps: ['Implement a Strict CSP.', 'Use a Markdown parser that escapes.', 'Sanitize on the server.'],
        patched_code: `// Ensure CSP is active in middleware\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />`,
        check_logic: (input) => input.includes('DOMPurify'),
        explanation: 'Next.js is safe by default, but `dangerouslySetInnerHTML` bypasses that safety. Combining it with a "Content Security Policy" (CSP) provides a second layer of defense, so even if sanitization fails, the browser won\'t run the malicious script.'
      },
      {
        scenario: 'The app stores user names in "Session Storage" and renders them into the page using ".innerHTML".',
        vulnerable_code: `document.getElementById('welcome').innerHTML = sessionStorage.getItem('username');`,
        fix_steps: ['Use .textContent instead of .innerHTML.', 'Escape data from Storage.', 'Treat all storage as untrusted.'],
        patched_code: `document.getElementById('welcome').textContent = sessionStorage.getItem('username');`,
        check_logic: (input) => input.includes('textContent'),
        explanation: '`.innerHTML` tells the browser: "The stuff I\'m giving you is HTML code—run it!" `.textContent` says: "This is just a boring string of text—show it exactly as it is." Using `textContent` is your best defense against 99% of XSS bugs.'
      },
      {
        scenario: 'A 3rd-party widget is included in the page via a `<script>` tag from a CDN without a Subresource Integrity (SRI) hash.',
        vulnerable_code: `<script src="https://cdn.com/library.js"></script>`,
        fix_steps: ['Add "integrity" attribute.', 'Use "crossorigin="anonymous".', 'Pin to a specific version.'],
        patched_code: `<script src="https://cdn.com/library.js" integrity="sha384-xyz..." crossorigin="anonymous"></script>`,
        check_logic: (input) => input.includes('integrity'),
        explanation: 'If a hacker breaks into the CDN, they can change the library to include a virus. An `integrity` hash is like a fingerprint. If the CDN file changes by even one letter, your browser will refuse to load it, keeping your site safe.'
      },
      {
        scenario: 'An admin panel displays the "User-Agent" of recent visitors without escaping, leading to "Stored XSS".',
        vulnerable_code: `return logs.map(log => <li>{log.userAgent}</li>);`,
        fix_steps: ['React handles this, but be careful of logs stored in DB.', 'Sanitize inputs before saving to DB.', 'Audit admin-only views.'],
        patched_code: `// React handles this, but let's be explicit\nreturn logs.map(log => <li>{String(log.userAgent)}</li>);`,
        check_logic: (input) => input.includes('String'),
        explanation: 'Attackers can change their browser\'s "User-Agent" string to a script like `<script>alert(1)</script>`. If you display these logs later in an insecure way (like in a basic HTML table), the script will run on the admin\'s computer!'
      }
    ]
  },
  'path-traversal': {
    title: 'Path Traversal',
    variants: [
      {
        scenario: 'Using user input to read files from the filesystem without validation.',
        vulnerable_code: `const path = '/uploads/' + filename;\nconst data = fs.readFileSync(path);`,
        fix_steps: ['Normalize the path.', 'Check that it stays within expected directory.', 'Strip ".." patterns.'],
        patched_code: `const safePath = path.join(process.cwd(), 'uploads', path.basename(filename));\nif (!safePath.startsWith(uploadsDir)) throw new Error('Illegal Access');`,
        check_logic: (input) => input.includes('basename') || input.includes('startsWith'),
        explanation: 'Attackers use `../` to "traverse" up the file system and read sensitive files like `/etc/passwd`. `path.basename` strips out all the directory dots, and `startsWith` ensures the final file is actually inside the intended "uploads" folder.'
      },
      {
        scenario: 'A profile picture downloader doesn\'t strip null bytes, allowing attackers to bypass extension checks (e.g., "file.php%00.jpg").',
        vulnerable_code: `if (!filename.endsWith('.jpg')) return;\nconst data = fs.readFileSync('/images/' + filename);`,
        fix_steps: ['Remove null bytes.', 'Normalize path.', 'Use whitelist for extensions.'],
        patched_code: `const safeName = filename.replace(/\\0/g, '');\nif (!safeName.endsWith('.jpg')) throw new Error('Invalid Type');\nconst data = fs.readFileSync(path.join(IMAGES_DIR, safeName));`,
        check_logic: (input) => input.includes('\\0'),
        explanation: 'Null bytes (`%00`) can trick some older file systems or libraries. A hacker might send `secret.txt%00.jpg`. Your code sees `.jpg` and says "Okay!", but the file system stops at the null byte and reads `secret.txt`. Always strip null bytes from file paths.'
      },
      {
        scenario: 'An app allows users to choose a "Theme" file, but doesn\'t restrict the directory.',
        vulnerable_code: `const theme = fs.readFileSync(\`./themes/\${userTheme}.css\`);`,
        fix_steps: ['Use an allowed list of themes.', 'Validate filename with regex.', 'Prevent directory climbing.'],
        patched_code: `const allowedThemes = ['dark', 'light', 'high-contrast'];\nif (!allowedThemes.includes(userTheme)) throw new Error('Invalid Theme');\nconst theme = fs.readFileSync(\`./themes/\${userTheme}.css\`);`,
        check_logic: (input) => input.includes('includes'),
        explanation: 'When you have a small number of options, a "Whitelist" is the strongest security. Instead of trying to block bad names like `../../etc/passwd`, you just check if the input is one of the 3 themes you actually have. If it isn\'t, you reject it immediately.'
      },
      {
        scenario: 'A report generator takes a "templatePath" from the request to generate a PDF.',
        vulnerable_code: `const template = await fs.readFile(req.body.templatePath);`,
        fix_steps: ['Hardcode the template directory.', 'Restrict extension to .html.', 'Verify path is within templates folder.'],
        patched_code: `const safePath = path.resolve(TEMPLATES_DIR, path.basename(req.body.templatePath));\nif (!safePath.startsWith(TEMPLATES_DIR)) throw new Error('Forbidden');`,
        check_logic: (input) => input.includes('startsWith'),
        explanation: '`path.resolve` turns a messy path into a clean, "absolute" path. By checking if that clean path `startsWith` your `TEMPLATES_DIR`, you create a digital fence. Even if the user types `../../`, the final resolved path will be caught if it tries to jump out of the fence.'
      },
      {
        scenario: 'A "File Metadata" viewer uses user input to find files, but is vulnerable to URL-encoded dots (e.g., "%2e%2e%2f").',
        vulnerable_code: `const stats = fs.statSync('/data/' + filename);`,
        fix_steps: ['Decode URL parameters carefully.', 'Use path.normalize.', 'Check for traversal patterns.'],
        patched_code: `const decoded = decodeURIComponent(filename);\nconst safePath = path.normalize(path.join('/data/', decoded)).replace(/^(\\.\\.[\\/\\\\])+/, '');`,
        check_logic: (input) => input.includes('normalize'),
        explanation: 'Hackers can hide `../` by encoding it as `%2e%2e%2f`. Some web servers helpfully decode this before giving it to your code! Using `path.normalize` cleans up these dots, and `replace` ensures that even a sneaky `../../` at the start is stripped away.'
      },
      {
        scenario: 'An app serves static assets from a "public" folder but doesn\'t handle symbolic links (symlinks) correctly.',
        vulnerable_code: `res.sendFile(path.join(PUBLIC_DIR, filename));`,
        fix_steps: ['Resolve realpath.', 'Verify the actual file location.', 'Disable symlink following.'],
        patched_code: `const fullPath = path.join(PUBLIC_DIR, filename);\nconst realPath = fs.realpathSync(fullPath);\nif (!realPath.startsWith(PUBLIC_DIR)) throw new Error('Illegal Symlink');`,
        check_logic: (input) => input.includes('realpath'),
        explanation: 'A "Symlink" is like a shortcut. A hacker might upload a shortcut called `myphoto.jpg` that actually points to `/etc/shadow`. `fs.realpathSync` follows that shortcut to its *true* destination, letting you verify where the data is actually coming from.'
      },
      {
        scenario: 'A "Log Viewer" allows admins to view system logs by specifying a "Log Date" parameter.',
        vulnerable_code: `const log = fs.readFileSync(\`/var/log/app-\${req.query.date}.log\`);`,
        fix_steps: ['Validate date format (regex).', 'Prevent special characters.', 'Restrict characters to [0-9-].'],
        patched_code: `if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(req.query.date)) throw new Error('Invalid Date');\nconst log = fs.readFileSync(\`/var/log/app-\${req.query.date}.log\`);`,
        check_logic: (input) => input.includes('test'),
        explanation: 'If you expect a date, only accept a date! By using a "Regular Expression" (Regex) like `^[0-9-]*$`, you ensure that the input can ONLY contain numbers and dashes. This makes it impossible for an attacker to insert `../` or any other sneaky characters.'
      },
      {
        scenario: 'An image processing API takes a "source" path that could be a network share or a local file.',
        vulnerable_code: `const img = await sharp(req.body.source).toBuffer();`,
        fix_steps: ['Only allow local uploads directory.', 'Restrict source to trusted URLs.', 'Sanitize the file path.'],
        patched_code: `const source = path.basename(req.body.source);\nconst safePath = path.join(UPLOADS_DIR, source);\nconst img = await sharp(safePath).toBuffer();`,
        check_logic: (input) => input.includes('basename'),
        explanation: 'Universal file libraries like `sharp` or `fs` can sometimes read from network shares (like `\\\\attacker-pc\\evil`) if not restricted. `path.basename` is your best friend here—it takes any long path and keeps only the very last part (the filename).'
      },
      {
        scenario: 'A "Config Loader" reads JSON files from a directory, but doesn\'t check if the "filename" is a directory itself.',
        vulnerable_code: `const cfg = fs.readFileSync('./configs/' + filename);`,
        fix_steps: ['Check if it is a file (isFile()).', 'Handle errors for directory reads.', 'Normalize and validate.'],
        patched_code: `const safePath = path.join('./configs/', path.basename(filename));\nif (!fs.statSync(safePath).isFile()) throw new Error('Not a file');\nconst cfg = fs.readFileSync(safePath);`,
        check_logic: (input) => input.includes('isFile'),
        explanation: 'Trying to "read" a directory can cause errors or leak information about the system. Always verify with `fs.statSync` that you are actually opening a "file" and not a folder or a special system device.'
      },
      {
        scenario: 'The app uses a custom "Sanitize" function that only removes "../" once, but not recursively (e.g., "..././").',
        vulnerable_code: `const safe = filename.replace('../', '');`,
        fix_steps: ['Use path.basename.', 'Normalize the path.', 'Use a robust sanitization library.'],
        patched_code: `const safe = path.basename(filename);`,
        check_logic: (input) => input.includes('basename'),
        explanation: 'Never try to write your own "Security Filter" with simple `replace`. Attackers are clever: if you remove `../`, they will send `....//`, which turns back into `../` after your filter runs! Trust proven tools like `path.basename` instead.'
      }
    ]
  },
  'command-injection': {
    title: 'Command Injection',
    variants: [
      {
        scenario: 'Executing a shell command using user-provided hostname for a network tool.',
        vulnerable_code: `exec(\`ping -c 4 \${host}\`, (err, stdout) => { ... });`,
        fix_steps: ['Avoid using exec with strings.', 'Use execFile or spawn with argument arrays.', 'Strictly validate the host.'],
        patched_code: `spawn('ping', ['-c', '4', host]);`,
        check_logic: (input) => input.includes('spawn') || input.includes('execFile'),
        explanation: '`exec` runs your input in a full shell, which is dangerous if someone adds `; rm -rf /` to the host. `spawn` or `execFile` treats the inputs as a list of separate arguments that are never parsed by a shell, making it impossible to "inject" extra commands.'
      },
      {
        scenario: 'A video conversion tool uses "ffmpeg" to process a file, but takes the "outputFormat" from user input.',
        vulnerable_code: `exec(\`ffmpeg -i input.mp4 output.\${format}\`);`,
        fix_steps: ['Whitelist allowed formats.', 'Use an array of arguments.', 'Strictly validate format string.'],
        patched_code: `const allowed = ['mp4', 'mov', 'avi'];\nif (!allowed.includes(format)) throw new Error('Invalid');\nspawn('ffmpeg', ['-i', 'input.mp4', \`output.\${format}\`]);`,
        check_logic: (input) => input.includes('includes') && input.includes('spawn'),
        explanation: 'Command injection isn\'t just about the main program; it can happen in "arguments" too! If a user sets the format to `mp4; rm -rf /`, they can still run evil commands. Always validate every single parameter against a known safe list.'
      },
      {
        scenario: 'A "WHOIS" lookup tool passes a domain name to a shell script.',
        vulnerable_code: `const out = execSync(\`./scripts/lookup.sh \${domain}\`);`,
        fix_steps: ['Use execFileSync.', 'Pass arguments as a separate array.', 'Sanitize domain with regex.'],
        patched_code: `const out = execFileSync('./scripts/lookup.sh', [domain]);`,
        check_logic: (input) => input.includes('execFileSync'),
        explanation: '`execSync` (and other shell functions) treat your string as a single command. `execFileSync` is much safer because it keeps the "program" and the "tools/data" strictly separate. The shell never sees the data, so it can\'t accidentally "run" it.'
      },
      {
        scenario: 'An app allows users to "Ping" their own server to test latency, but doesn\'t limit the character set.',
        vulnerable_code: `exec(\`ping -c 1 \${ip}\`);`,
        fix_steps: ['Use a strict IP regex.', 'Reject characters like ; & | `.', 'Use spawn with arrays.'],
        patched_code: `if (!/^[0-9.]+$/.test(ip)) throw new Error('Bad IP');\nspawn('ping', ['-c', '1', ip]);`,
        check_logic: (input) => input.includes('test') && input.includes('spawn'),
        explanation: 'Security is about "Expectations." If you expect an IP address, only allow numbers and dots. By using a Regex to block symbols like `;` or `|`, you stop hackers from chaining extra commands to your ping request.'
      },
      {
        scenario: 'A backup tool allows users to specify an "S3 Bucket Name" that is passed to the "aws" CLI.',
        vulnerable_code: `exec(\`aws s3 sync . s3://\${bucketName}\`);`,
        fix_steps: ['Use the AWS SDK for Node.js instead of CLI.', 'Validate bucket name structure.', 'Never use CLI strings with user data.'],
        patched_code: `const s3 = new AWS.S3();\nawait s3.upload({ Bucket: bucketName, Key: 'backup', Body: data }).promise();`,
        check_logic: (input) => input.includes('AWS.S3') || !input.includes('exec'),
        explanation: 'Using "Shell Command-Line Tools" (CLI) is easy, but dangerous. It is always better to use a "Library" (SDK). Libraries talk to the service directly via API, completely avoiding the shell and making command injection impossible by design.'
      },
      {
        scenario: 'An admin utility allows running "Git" commands by providing a "branch" name.',
        vulnerable_code: `exec(\`git checkout \${branch}\`);`,
        fix_steps: ['Strictly validate branch name.', 'Use -- to stop flag injection.', 'Avoid executing in a shell.'],
        patched_code: `// The -- tells Git: "Everything after this is a name, not a command" \nspawn('git', ['checkout', '--', branch]);`,
        check_logic: (input) => input.includes("'--'"),
        explanation: 'Flag Injection is a sneaky trick. If a hacker sends a branch name like `--help`, it might change how the command runs. Using `--` tells the program: "Stop looking for options! Everything that follows is just a simple name."'
      },
      {
        scenario: 'A customized image "Search" runs a "find" command on the server.',
        vulnerable_code: `exec(\`find /images -name "*\${query}*"\`);`,
        fix_steps: ['Use a database index instead of find.', 'Use spawn.', 'Sanitize wildcards.'],
        patched_code: `spawn('find', ['/images', '-name', \`*\${query}*\`]);`,
        check_logic: (input) => input.includes('spawn'),
        explanation: 'Searching the file system with `find` is common but risky. By using `spawn`, you ensure that a user query like `"*.jpg" ; rm -rf /` is just treated as one long, weird filename to search for, rather than a command to be executed.'
      },
      {
        scenario: 'An app takes a "User ID" and uses it to look up a directory with "ls".',
        vulnerable_code: `exec(\`ls -l /users/\${id}\`);`,
        fix_steps: ['Verify id is numeric.', 'Use fs.readdir instead of ls.', 'Never use shell for list operations.'],
        patched_code: `const files = fs.readdirSync(path.join('/users/', String(id)));`,
        check_logic: (input) => input.includes('readdirSync'),
        explanation: 'Why use a shell command when there\'s a built-in Node.js function? `fs.readdir` is faster and 100% safe from command injection. Whenever possible, use native programming functions instead of calling out to the operating system.'
      },
      {
        scenario: 'The application uses "environment variables" provided by the user to run a child process (e.g., PATH).',
        vulnerable_code: `exec('mytool', { env: { ...process.env, ...userEnv } });`,
        fix_steps: ['Whitelist environment variables.', 'Never allow overriding PATH.', 'Use a clean environment.'],
        patched_code: `const safeEnv = { ...process.env };\ndelete safeEnv.PATH;\nexec('mytool', { env: safeEnv });`,
        check_logic: (input) => input.includes('delete safeEnv.PATH'),
        explanation: 'The `PATH` variable tells the computer where to find programs. If an attacker can change it, they can make your app "hijack" a different program instead of the one you intended. Always protect your environment variables from user modification.'
      },
      {
        scenario: 'An app uses "String.replace" as a security filter for common command symbols, but fails to account for newlines.',
        vulnerable_code: `const safe = input.replace(';', '');\nexec(\`echo \${safe}\`);`,
        fix_steps: ['Newlines (\\n) can also chain commands.', 'Use a strict character whitelist.', 'Avoid manual filtering.'],
        patched_code: `if (input.includes('\\n')) throw new Error('Bad Input');\nspawn('echo', [input]);`,
        check_logic: (input) => input.includes('\\\\n'),
        explanation: 'Hackers can chain commands using semicolons `;`, ampersands `&`, OR even just a simple Newline `\\n`! If your "Filter" only looks for one symbol, it is incomplete. Using `spawn` with an array is the ONLY 100% safe way to handle user data.'
      }
    ]
  },
  'linux-essentials': {
    title: 'Linux Essentials',
    variants: [
      {
        scenario: 'A sensitive configuration file has overly permissive settings (777), allowing any user on the system to read and modify it.',
        vulnerable_code: `$ ls -l config.json\n-rwxrwxrwx 1 root root 1024 config.json`,
        fix_steps: ['Identify the owner.', 'Restrict access to owner-only using chmod.', 'Use 600 or 400.'],
        patched_code: `$ chown user:user config.json\n$ chmod 600 config.json`,
        check_logic: (input) => input.includes('chmod 600'),
        explanation: 'On Linux, permissions are represented by numbers. 777 means "everyone can do everything." `chmod 600` ensures that only the OWNER can read and write to the file, which is critical for secrets like passwords or API keys.'
      },
      {
        scenario: 'A suspicious background process is running on an unusual port (4444).',
        vulnerable_code: `$ netstat -tunlp\n$ ps aux | grep 4444\nroot 1234 ... /tmp/backdoor`,
        fix_steps: ['Find the PID.', 'Kill the process.', 'Remove the malicious binary.'],
        patched_code: `$ kill -9 1234\n$ rm /tmp/backdoor`,
        check_logic: (input) => input.includes('kill'),
        explanation: '`kill` is used to stop running programs. The `-9` flag means "force stop immediately." We find the unique ID of the process (the PID) and use it to terminate the suspicious activity.'
      },
      {
        scenario: 'Analyze authentication logs to find failed login attempts.',
        vulnerable_code: `$ cat /var/log/auth.log\n(Too much data...)`,
        fix_steps: ['Grep for "Failed password".', 'Count attempts.', 'Identify target IP.'],
        patched_code: `$ grep "Failed password" /var/log/auth.log | wc -l`,
        check_logic: (input) => input.includes('grep') && input.includes('auth.log'),
        explanation: '`grep` is a powerful search tool. We use it to find every line in the log file that contains "Failed password," and `wc -l` counts those lines, helping us see if someone is trying to brute-force their way into the system.'
      },
      {
        scenario: 'Find all binaries with the SUID bit set to identify potential privilege escalation vectors.',
        vulnerable_code: `$ ls -R /\n(Looking for 's' bit manualy...)`,
        fix_steps: ['Use find command with -perm.', 'Search for files with 4000 bit.', 'Redirect errors to /dev/null.'],
        patched_code: `$ find / -perm -4000 -type f 2>/dev/null`,
        check_logic: (input) => input.includes('find') && input.includes('-4000'),
        explanation: 'The SUID bit (perm 4000) allows a regular user to run a program with ROOT privileges. While necessary for tools like `passwd`, hackers look for "buggy" SUID files to gain full control of the server via privilege escalation.'
      },
      {
        scenario: 'Audit the sudoers file for entries that allow running commands without a password.',
        vulnerable_code: `$ cat /etc/sudoers\n(Manually reading file...)`,
        fix_steps: ['Check for NOPASSWD entries.', 'Use visudo for editing.', 'Remove wildcard permissions.'],
        patched_code: `$ sudo grep "NOPASSWD" /etc/sudoers`,
        check_logic: (input) => input.includes('grep') && input.includes('NOPASSWD'),
        explanation: '`NOPASSWD` entries in the sudoers file are dangerous because if a user is regular, they can suddenly run root commands without verification. We audit this file to ensure that every high-privilege action requires an explicit password.'
      },
      {
        scenario: 'Harden SSH configuration by disabling root login.',
        vulnerable_code: `$ grep "PermitRootLogin" /etc/ssh/sshd_config\nPermitRootLogin yes`,
        fix_steps: ['Open sshd_config.', 'Set PermitRootLogin to no.', 'Restart the ssh service.'],
        patched_code: `$ sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config\n$ systemctl restart ssh`,
        check_logic: (input) => input.includes('PermitRootLogin no'),
        explanation: 'Hackers frequently target the "root" account because it always exists. Disabling `PermitRootLogin` forces attackers to first guess a regular username, doubling the work they have to do to break in.'
      },
      {
        scenario: 'Audit cron jobs for world-writable scripts executed by root.',
        vulnerable_code: `$ ls -l /etc/cron.daily/backup.sh\n-rwxrwxrwx 1 root root ...`,
        fix_steps: ['Check permissions of script.', 'Verify ownership.', 'Fix with chmod 700.'],
        patched_code: `$ chmod 700 /etc/cron.daily/backup.sh`,
        check_logic: (input) => input.includes('chmod 700'),
        explanation: 'A "Cron job" is a scheduled task. If a task runs as root but is world-writable (777), any user can edit the script to include malicious code, which will then run with full system permissions on the next schedule.'
      },
      {
        scenario: 'Identify users with UID 0 other than the root account.',
        vulnerable_code: `$ cat /etc/passwd\n(Manually reading...)`,
        fix_steps: ['Grep for :0:0 in passwd.', 'Ensure only root exists.', 'Remove secondary 0-UID users.'],
        patched_code: `$ awk -F: '$3 == 0 { print $1 }' /etc/passwd`,
        check_logic: (input) => input.includes('awk') || input.includes('grep'),
        explanation: 'On Linux, the "root" power comes from UID 0, not the name "root." Some clever attackers create a new user called "backup" or "sys" but give it UID 0 to hide their full-system access. We audit the passwd file to find these imposters.'
      },
      {
        scenario: 'Block a malicious IP address using the UFW firewall.',
        vulnerable_code: `$ ufw status\nStatus: active\n(No specific blocks...)`,
        fix_steps: ['Identify attacker IP.', 'Add deny rule.', 'Reload firewall.'],
        patched_code: `$ ufw deny from 192.168.1.100 to any`,
        check_logic: (input) => input.includes('deny') && input.includes('from'),
        explanation: '`ufw` (Uncomplicated Firewall) is how we guard the system\'s gates. `ufw deny` creates a strict wall against a specific malicious IP, stopping their traffic before it even touches your web server or applications.'
      },
      {
        scenario: 'Find sensitive environment variables for the current user.',
        vulnerable_code: `$ env\n(Looking for tokens...)`,
        fix_steps: ['Search for KEY, TOKEN, or PASS.', 'Check .bashrc for exports.', 'Unset sensitive variables.'],
        patched_code: `$ env | grep -Ei 'pass|key|token'`,
        check_logic: (input) => input.includes('grep') && input.includes('env'),
        explanation: 'Environment variables are often used to store API keys and passwords. If you forget these in your `.bashrc` or shell session, anyone who gains access to your terminal can steal them. We audit the environment for these common secret keywords.'
      },
      {
        scenario: 'Analyze network packets for plaintext HTTP passwords using tcpdump.',
        vulnerable_code: `$ tcpdump -i eth0\n(Too much noise...)`,
        fix_steps: ['Filter for HTTP port 80.', 'Grepping for "password".', 'Read into a file.'],
        patched_code: `$ tcpdump -i eth0 -A | grep -i "password"`,
        check_logic: (input) => input.includes('tcpdump') && input.includes('grep'),
        explanation: '`tcpdump` is like a digital wiretap. Because HTTP (port 80) is not encrypted, anyone on the network can see your login details in plain text. This is why using HTTPS (encrypted) is absolutely mandatory for modern websites.'
      },
      {
        scenario: 'Identify insecure world-writable directories in the system.',
        vulnerable_code: `$ ls -la /tmp\n(Manual check...)`,
        fix_steps: ['Use find command.', 'Search for perm 777.', 'Ensure sticky bit is set.'],
        patched_code: `$ find / -perm -o+w -type d 2>/dev/null`,
        check_logic: (input) => input.includes('find') && input.includes('-o+w'),
        explanation: 'World-writable directories (`-o+w`) are places where anyone can put files. This is dangerous if a high-privilege program looks for its components there. We look for these spots to ensure they are cleaned or restricted.'
      },
      {
        scenario: 'Verify file integrity using SHA256 hashes.',
        vulnerable_code: `$ ls -l /usr/bin/login\n(Size looks okay...)`,
        fix_steps: ['Generate hash.', 'Compare with known good hash.', 'Audit the binary if hash mismatch.'],
        patched_code: `$ sha256sum /usr/bin/login`,
        check_logic: (input) => input.includes('sha256sum'),
        explanation: 'Hackers often replace common system tools (like `ls` or `login`) with fake versions that steal passwords. A "hash" is like a digital fingerprint—if the file changes even by a single bit, the hash will change, allowing us to detect tampering.'
      },
      {
        scenario: 'Audit running services for insecure default ports.',
        vulnerable_code: `$ netstat -lntp\n(Manual review...)`,
        fix_steps: ['List all open ports.', 'Check process names.', 'Disable unused services.'],
        patched_code: `$ ss -lntp`,
        check_logic: (input) => input.includes('ss') || input.includes('netstat'),
        explanation: '`ss` shows you which "doors" (ports) are open on your server. Every open port is a potential entry point for a hacker. By auditing these, we can close (disable) any service that isn\'t strictly necessary for the application.'
      },
      {
        scenario: 'Identify files owned by a deleted user.',
        vulnerable_code: `$ ls -l /home/olduser\n(Manual check...)`,
        fix_steps: ['Use find with -nouser.', 'Change ownership to admin.', 'Reassign or delete.'],
        patched_code: `$ find / -nouser 2>/dev/null`,
        check_logic: (input) => input.includes('nouser'),
        explanation: 'When a user is deleted, their files remain but have no "owner" (they show up with an ID like 1005). If a new user is created later and assigned that same ID, they would inherit all those old files, which is a major security risk.'
      },
      {
        scenario: 'Audit the system for hidden files in world-writable directories.',
        vulnerable_code: `$ ls /tmp\n(Shows nothing...)`,
        fix_steps: ['Use ls -a.', 'Check for dotfiles.', 'Investigate .hidden_data.'],
        patched_code: `$ ls -la /tmp | grep "^d"`,
        check_logic: (input) => input.includes('-la'),
        explanation: 'On Linux, any file starting with a dot `.` is hidden. Attackers hide their toolkits and logs in plain sight inside temporary folders like `/tmp`. We use `ls -la` to reveal these hidden files for security auditing.'
      },
      {
        scenario: 'Audit command history for leaked credentials.',
        vulnerable_code: `$ history\n(1000 lines shown...)`,
        fix_steps: ['Grep history for password.', 'Check .bash_history file.', 'Clear historical secrets.'],
        patched_code: `$ grep -Ei 'password|pass|secret' ~/.bash_history`,
        check_logic: (input) => input.includes('history') || input.includes('grep'),
        explanation: 'If you ever type a password directly into a command (like `mysql -pPASSWORD`), Linux saves it in your history file. Hackers love checking `~/.bash_history` for easy wins. Always use interactive prompts for passwords!'
      },
      {
        scenario: 'Audit installed packages for known vulnerabilities (Stub).',
        vulnerable_code: `$ dpkg -l\n(Manual review...)`,
        fix_steps: ['Update repositories.', 'Run vulnerability scanner.', 'Patch outdated software.'],
        patched_code: `$ sudo apt update && sudo apt list --upgradable`,
        check_logic: (input) => input.includes('apt'),
        explanation: 'Security is a race. Old software often has known bugs that hackers can exploit. Running `apt list --upgradable` helps you identify which parts of your system need urgent updates to close these security holes.'
      },
      {
        scenario: 'Audit shared memory segments for dangling data.',
        vulnerable_code: `$ ls /dev/shm\n(No files shown...)`,
        fix_steps: ['List shared memory.', 'Check for persistent data.', 'Clean up orphaned segments.'],
        patched_code: `$ ipcs -m`,
        check_logic: (input) => input.includes('ipcs'),
        explanation: 'Shared memory is used by programs to talk to each other very fast. However, sensitive data can sometimes "linger" in memory even after the program has stopped. `ipcs` lets us audit these memory segments for potential data leaks.'
      },
      {
        scenario: 'Identify the OS and Kernel version to check for local exploits.',
        vulnerable_code: `$ ls /etc/\n(Looking for version file...)`,
        fix_steps: ['Use uname -a.', 'Check /etc/os-release.', 'Look for old kernels.'],
        patched_code: `$ uname -a && cat /etc/os-release`,
        check_logic: (input) => input.includes('uname'),
        explanation: 'Local Privilege Escalation (LPE) exploits often target specific versions of the Linux "Kernel." Knowing your exact version allows you to check security databases (like CVE) for any known vulnerabilities that need patching.'
      },
      {
        scenario: 'Find files larger than 100MB to identify potential disk space hogs or massive data dumps.',
        vulnerable_code: `$ ls -lR / | grep "G"`,
        fix_steps: ['Use find with -size.', 'Specify +100M.', 'Filter for files only.'],
        patched_code: `$ find / -type f -size +100M 2>/dev/null`,
        check_logic: (input) => input.includes('find') && input.includes('-size'),
        explanation: 'Disk space exhaustion is a common Denial of Service (DoS) vector. Using `find` with the `-size` flag allows you to quickly locate massive files that might be filling up your drives or containing oversized logs that need rotation.'
      },
      {
        scenario: 'Audit home directories for world-readable files that might leak private user data.',
        vulnerable_code: `$ ls -l /home`,
        fix_steps: ['Search /home directory.', 'Check for other-readable bits.', 'Enforce privacy with chmod 700.'],
        patched_code: `$ find /home -maxdepth 2 -not -path '*/.*' -perm -o+r`,
        check_logic: (input) => input.includes('/home') && input.includes('-perm'),
        explanation: 'By default, some Linux distributions make home directories readable by everyone. Auditing with `-perm -o+r` finds files that "others" can read, which is a major privacy risk for sensitive user documents and SSH keys.'
      },
      {
        scenario: 'Detect potential reverse shells by monitoring established network connections.',
        vulnerable_code: `$ netstat -an`,
        fix_steps: ['Look for ESTABLISHED status.', 'Check for unusual ports.', 'Identify suspicious remote IPs.'],
        patched_code: `$ ss -antp | grep ESTAB`,
        check_logic: (input) => input.includes('ss') && input.includes('ESTAB'),
        explanation: 'A "Reverse Shell" is when a hacked server connects BACK to the hacker\'s computer. Monitoring "ESTABLISHED" connections with `ss` helps you spot these outgoing links. If you see your web server connecting to a random IP on port 4444, you likely have a breach.'
      }
    ]
  },
  'cyber-commands': {
    title: 'Cybersecurity Commands',
    variants: [
      {
        scenario: 'Use Nmap to identify open ports and services running on a target host.',
        vulnerable_code: `$ nmap target.local`,
        fix_steps: ['Perform a service version scan (-sV).', 'Check for common vulnerabilities with scripts (--script).', 'Scan all 65535 ports (-p-).'],
        patched_code: `$ nmap -sV -p- --script vuln target.local`,
        check_logic: (input) => input.includes('nmap') && input.includes('-sV'),
        explanation: '`nmap` is the "Swiss Army Knife" of network scanning. While a basic scan shows open ports, using `-sV` detects the EXACT version of the software running. This is vital because security holes are often specific to certain versions.'
      },
      {
        scenario: 'Use Traceroute to map the network path and identify potential hops where packets are dropped.',
        vulnerable_code: `$ ping target.com`,
        fix_steps: ['Use traceroute to see the path.', 'Identify high-latency hops.', 'Check if ICMP is filtered.'],
        patched_code: `$ traceroute target.com`,
        check_logic: (input) => input.includes('traceroute'),
        explanation: '`traceroute` shows you the digital "hops" your data takes across the internet. If a connection is slow, traceroute helps you pinpoint exactly which router or server in the chain is causing the delay or dropping your packets.'
      },
      {
        scenario: 'Use Hping3 to test firewall rules by sending custom TCP SYN packets.',
        vulnerable_code: `$ telnet target.local 80`,
        fix_steps: ['Send SYN packets to port 80.', 'Set custom flags or intervals.', 'Analyze the return packets.'],
        patched_code: `$ hping3 -S -p 80 target.local`,
        check_logic: (input) => input.includes('hping3') && input.includes('-S'),
        explanation: '`hping3` allows you to craft custom network packets. By sending a SYN packet (`-S`), you can test if a firewall is correctly blocking or allowing traffic on specific ports without completing a full connection.'
      },
      {
        scenario: 'Use Ping to verify connectivity and measure round-trip time (RTT).',
        vulnerable_code: `$ curl -I target.com`,
        fix_steps: ['Send ICMP Echo Requests.', 'Measure latency (ms).', 'Check for packet loss percentage.'],
        patched_code: `$ ping -c 4 target.com`,
        check_logic: (input) => input.includes('ping') && input.includes('-c'),
        explanation: '`ping` is the most basic tool for checking if a computer is "alive" on the network. It sends a tiny packet and waits for a reply. The time it takes (latency) tells you how fast the connection is between you and the target.'
      },
      {
        scenario: 'Use Netcat (nc) to listen for an incoming connection on a specific port.',
        vulnerable_code: `$ telnet 127.0.0.1 4444`,
        fix_steps: ['Use nc in listen mode (-l).', 'Specify the port (-p).', 'Verify data transfer.'],
        patched_code: `$ nc -lvp 4444`,
        check_logic: (input) => input.includes('nc') && input.includes('-l'),
        explanation: '`nc` (Netcat) is often called "the network cat." It allows you to read and write data across network connections. In "listen mode" (`-l`), it can act as a simple server, which is useful for debugging or testing port connectivity.'
      },
      {
        scenario: 'Use Whois to find registration details and contact information for a domain.',
        vulnerable_code: `$ ping example.com`,
        fix_steps: ['Query the WHOIS database.', 'Identify the registrar and name servers.', 'Check registration and expiry dates.'],
        patched_code: `$ whois example.com`,
        check_logic: (input) => input.includes('whois'),
        explanation: '`whois` is used to query databases that store the registered users or assignees of an Internet resource, such as a domain name or an IP address block. It reveals ownership details, registration dates, and contact information.'
      },
      {
        scenario: 'Use Dig to perform an advanced DNS lookup and verify MX records for a domain.',
        vulnerable_code: `$ nslookup example.com`,
        fix_steps: ['Use dig for detailed DNS info.', 'Specify the record type (MX).', 'Check the answer section for mail servers.'],
        patched_code: `$ dig example.com MX`,
        check_logic: (input) => input.includes('dig') && input.includes('MX'),
        explanation: '`dig` (Domain Information Groper) is a flexible tool for interrogating DNS name servers. It performs DNS lookups and displays the answers that are returned from the name server. It is more powerful and detailed than the older `nslookup`.'
      },
      {
        scenario: 'Use Curl to inspect the HTTP headers of a website to check for security configurations.',
        vulnerable_code: `$ browser example.com`,
        fix_steps: ['Fetch only the headers (-I).', 'Check for X-Frame-Options or CSP headers.', 'Verify the Server header for version leakage.'],
        patched_code: `$ curl -I https://example.com`,
        check_logic: (input) => input.includes('curl') && input.includes('-I'),
        explanation: '`curl` is a tool to transfer data from or to a server. Using the `-I` flag tells curl to fetch ONLY the HTTP headers. This is a quick way for researchers to audit a site\'s security headers without downloading the entire page content.'
      },
      {
        scenario: 'Use Gobuster to discover hidden directories and files on a web server.',
        vulnerable_code: `$ ls http://target.local/`,
        fix_steps: ['Use directory brute-forcing mode (dir).', 'Specify a wordlist (-w).', 'Set the target URL (-u).'],
        patched_code: `$ gobuster dir -u http://target.local/ -w /usr/share/wordlists/dirb/common.txt`,
        check_logic: (input) => input.includes('gobuster') && input.includes('dir'),
        explanation: '`gobuster` is used to discover hidden objects on websites (directories and files) or DNS subdomains. It works by "brute-forcing" – trying thousands of names from a wordlist to see which ones actually exist on the server.'
      },
      {
        scenario: 'Use Tcpdump to capture and analyze live network traffic on a specific interface.',
        vulnerable_code: `$ wireshark`,
        fix_steps: ['Capture traffic from a specific interface (-i).', 'Filter for specific protocols (e.g., tcp).', 'Limit the number of packets (-c).'],
        patched_code: `$ sudo tcpdump -i eth0 -c 10 tcp`,
        check_logic: (input) => input.includes('tcpdump') && input.includes('-i'),
        explanation: '`tcpdump` is a powerful command-line packet analyzer. It allows the user to intercept and display TCP/IP and other packets being transmitted or received over a network. It is the command-line equivalent of the graphical Wireshark tool.'
      }
    ]
  },
  'cryptography': {
    title: 'Cryptography',
    variants: [
      {
        scenario: 'The app uses MD5 for password hashing, which is fast and vulnerable to rainbow table attacks.',
        vulnerable_code: `const hash = crypto.createHash('md5').update(password).digest('hex');`,
        fix_steps: ['Use Argon2 or BCrypt.', 'Use a high work factor/cost.', 'Add a unique salt per user.'],
        patched_code: `import bcrypt from 'bcrypt';\nconst salt = await bcrypt.genSalt(10);\nconst hash = await bcrypt.hash(password, salt);`,
        check_logic: (input) => input.includes('bcrypt'),
        explanation: 'MD5 was designed for speed, not security. A modern GPU can check billions of MD5 hashes per second! `bcrypt` is intentionally slow (hashing takes ~100ms), making it much harder for a hacker to "guess" passwords using brute force.'
      },
      {
        scenario: 'An encryption key is hardcoded directly in the source code.',
        vulnerable_code: `const SECRET_KEY = 'my-secret-key-123';\nconst encrypted = encrypt(data, SECRET_KEY);`,
        fix_steps: ['Move secrets to environment variables.', 'Use a Key Management Service (KMS).', 'Never commit keys to Git.'],
        patched_code: `const SECRET_KEY = process.env.ENCRYPTION_KEY;\nif (!SECRET_KEY) throw new Error('Key missing');`,
        check_logic: (input) => input.includes('process.env'),
        explanation: 'If your encryption key is in your code, anyone with access to your GitHub (or even your compiled app) can steal all your encrypted data. Always load keys from a secure environment variable or a dedicated "Vault" service.'
      },
      {
        scenario: 'The app uses a guessable "Math.random()" to generate secure session tokens.',
        vulnerable_code: `const token = Math.random().toString(36).substring(7);`,
        fix_steps: ['Use crypto.randomBytes().', 'Use crypto.getRandomValues().', 'Ensure high entropy.'],
        patched_code: `import { crypto } from 'crypto';\nconst token = crypto.randomBytes(32).toString('hex');`,
        check_logic: (input) => input.includes('randomBytes'),
        explanation: '`Math.random()` is "Pseudo-random," meaning it follows a predictable pattern. A clever attacker can guess the next "random" number! `crypto.randomBytes` uses the computer\'s physical noise (like mouse movements) to generate truly unpredictable data.'
      },
      {
        scenario: 'The app uses DES (Data Encryption Standard), an old algorithm that can be broken in hours.',
        vulnerable_code: `const cipher = crypto.createCipher('des', key);`,
        fix_steps: ['Use AES-256-GCM.', 'Avoid legacy algorithms.', 'Use the SubtleCrypto API.'],
        patched_code: `const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`,
        check_logic: (input) => input.includes('aes-256-gcm'),
        explanation: 'DES is a "dinosaur" of cryptography. It was designed in the 1970s and is now too weak for modern computers. AES-256 is the "Gold Standard" used by banks and governments worldwide to keep data safe from even the most powerful attackers.'
      },
      {
        scenario: 'User IDs are used as the "Salt" for password hashes, leading to predictable results across systems.',
        vulnerable_code: `const hash = hash(password + userId);`,
        fix_steps: ['Use a random salt.', 'Let the library handle salting.', 'Store salt with the hash.'],
        patched_code: `const hash = await bcrypt.hash(password, 12); // Library salts automatically`,
        check_logic: (input) => input.includes('hash'),
        explanation: 'A "Salt" should be a random string added to the password to make the hash unique. If you use something predictable like a `userId`, a hacker can pre-calculate hashes for common passwords. Modern libraries like `bcrypt` handle this perfectly for you.'
      },
      {
        scenario: 'The app uses ECB (Electronic Codebook) mode for AES, which leaks patterns in the data.',
        vulnerable_code: `const cipher = crypto.createCipheriv('aes-256-ecb', key, null);`,
        fix_steps: ['Use CBC or GCM mode.', 'Always provide a random IV.', 'Avoid ECB for everything.'],
        patched_code: `const iv = crypto.randomBytes(16);\nconst cipher = crypto.createCipheriv('aes-256-cbc', key, iv);`,
        check_logic: (input) => input.includes('cbc') || input.includes('gcm'),
        explanation: 'In ECB mode, two identical pieces of data will result in identical encrypted chunks. This means an attacker can see "patterns" in your data (like a hidden image or repeated text). GCM or CBC mode adds randomness so the same input always looks Different.'
      },
      {
        scenario: 'Encryption "Initial Vectors" (IVs) are reused across Multiple sessions.',
        vulnerable_code: `const IV = Buffer.alloc(16, 0); // Always zero`,
        fix_steps: ['Generate a new IV for every encryption.', 'Store IV alongside the data.', 'Never reuse IV with the same key.'],
        patched_code: `const iv = crypto.randomBytes(16);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`,
        check_logic: (input) => input.includes('randomBytes(16)'),
        explanation: 'An "IV" is like a "One-Time Password" for a specific piece of data. If you use the same IV every time, you lose much of the protection AES provides. Always generate a fresh, random IV for every single piece of data you encrypt.'
      },
      {
        scenario: 'Sensitive data is transmitted over plain HTTP instead of HTTPS.',
        vulnerable_code: `fetch('http://api.myapp.com/login', { body: credentials });`,
        fix_steps: ['Force HTTPS.', 'Enable HSTS.', 'Check URL protocols.'],
        patched_code: `fetch('https://api.myapp.com/login', { body: credentials });`,
        check_logic: (input) => input.includes('https'),
        explanation: 'Cryptography is useless if you send the data over an unencrypted connection (HTTP). Anyone on your network can "sniff" the data as it travels. HTTPS creates an encrypted tunnel between you and the server, keeping your data private.'
      },
      {
        scenario: 'A JWT (JSON Web Token) is signed with a weak, guessable "Secret".',
        vulnerable_code: `const token = jwt.sign(payload, 'secret');`,
        fix_steps: ['Use a long, random secret.', 'Use an RSA or ECDSA private key.', 'Rotate secrets periodically.'],
        patched_code: `const token = jwt.sign(payload, process.env.JWT_PRIVATE_KEY, { algorithm: 'RS256' });`,
        check_logic: (input) => input.includes('env') || input.includes('RS256'),
        explanation: 'If your JWT secret is just "secret" or "123456," an attacker can use a tool like Hashcat to guess it in seconds. Once they have the secret, they can forge their own tokens and log in as ANY user, including the Admin!'
      },
      {
        scenario: 'The app doesn\'t verify the "Signature" of a certificate or token, trusting the data implicitly.',
        vulnerable_code: `const payload = jwt.decode(token); // Just decodes, doesn't verify`,
        fix_steps: ['Use jwt.verify().', 'Check certificate chains.', 'Reject untrusted signatures.'],
        patched_code: `const verified = jwt.verify(token, PUBLIC_KEY);`,
        check_logic: (input) => input.includes('verify'),
        explanation: '"Decoding" data just turns it back into text, but it doesn\'t prove that the data hasn\'t been changed. "Verifying" checks the digital signature to ensure the data truly came from a trusted source and was not tampered with by a hacker.'
      }
    ]
  },
  'threat-intel-tools': {
    title: 'Threat Intelligence Tools',
    variants: [
      {
        scenario: 'A user reported a suspicious link in an email. Use UrlScan.io to safely investigate the URL without visiting it directly.',
        vulnerable_code: `# Naive approach: clicking the link directly in a browser\n$ open "http://susp1ci0us-login.example.com/verify"`,
        fix_steps: ['Navigate to urlscan.io.', 'Submit the suspicious URL for scanning.', 'Review the Summary, HTTP connections, and Screenshot results.'],
        patched_code: `# Submit the URL to UrlScan.io for safe analysis\n# urlscan.io → Search → paste URL → Scan\n# Review:\n#   - Summary: IP, domain age, server location\n#   - HTTP: outbound connections & redirects\n#   - Screenshot: visual preview of the page\n#   - Indicators: flagged domains or IPs`,
        check_logic: (input) => input.includes('urlscan') && input.includes('scan'),
        explanation: 'UrlScan.io acts as a safe "browser in the cloud." It visits the suspicious link FOR you, takes a screenshot, and records all network activity. This lets you see exactly what a malicious page does (like redirecting to a fake login) without putting your own computer at risk.'
      },
      {
        scenario: 'You found a suspicious file attachment in a phishing email. Use MalwareBazaar (Abuse.ch) to check if its hash matches known malware.',
        vulnerable_code: `# Naive approach: opening the file to see what it does\n$ open suspicious_invoice.docm`,
        fix_steps: ['Calculate the file hash (SHA256).', 'Search the hash on bazaar.abuse.ch.', 'Check the malware family, tags, and detection signatures.'],
        patched_code: `# Step 1: Get the file hash without opening it\n$ sha256sum suspicious_invoice.docm\n# Output: a1b2c3d4e5f6...abc123\n\n# Step 2: Search on MalwareBazaar\n# bazaar.abuse.ch → Search → paste SHA256 hash\n# Review: malware family, YARA signatures, vendor detections`,
        check_logic: (input) => input.includes('sha256') && (input.includes('bazaar') || input.includes('MalwareBazaar')),
        explanation: 'MalwareBazaar is a free database of known malware samples. By computing the SHA256 hash of a file (a unique "fingerprint"), you can check if anyone has already identified it as malicious—without ever opening the dangerous file yourself. This is a core SOC analyst skill.'
      },
      {
        scenario: 'Your firewall logs show repeated connections to an unknown IP. Use Feodo Tracker (Abuse.ch) to check if it is a known botnet Command & Control server.',
        vulnerable_code: `# Naive approach: simply blocking the IP without investigation\n$ iptables -A INPUT -s 198.51.100.23 -j DROP`,
        fix_steps: ['Navigate to feodotracker.abuse.ch.', 'Search for the suspicious IP address.', 'Check if it is linked to Dridex, Emotet, TrickBot, or QakBot.'],
        patched_code: `# Step 1: Query Feodo Tracker\n# feodotracker.abuse.ch → Browse → search IP: 198.51.100.23\n# Review: associated malware family, first seen, last online\n\n# Step 2: If confirmed C2, block AND alert\n$ iptables -A INPUT -s 198.51.100.23 -j DROP\n$ echo "C2 IP blocked — Feodo Tracker confirmed" >> /var/log/alerts.log`,
        check_logic: (input) => input.includes('feodotracker') || input.includes('Feodo'),
        explanation: 'Feodo Tracker maintains a list of known botnet Command & Control (C2) servers used by major malware families like Emotet and TrickBot. By checking an IP against this list BEFORE just blocking it, you gain context—what malware family is involved, how long it has been active, and whether your network may already be compromised.'
      },
      {
        scenario: 'A URL found in a spam campaign needs to be checked. Use URLhaus (Abuse.ch) to determine if it is distributing malware.',
        vulnerable_code: `# Naive approach: using curl to download the payload\n$ curl -O http://evil-download.example.com/update.exe`,
        fix_steps: ['Navigate to urlhaus.abuse.ch.', 'Search for the suspicious URL or domain.', 'Review the URL status, payload type, and associated tags.'],
        patched_code: `# Search URLhaus for the suspicious URL\n# urlhaus.abuse.ch → Search → paste URL\n# Review:\n#   - URL status: online / offline / takedown\n#   - Threat type: malware_download\n#   - Payload: file type, hash, detection rate\n#   - Tags: e.g., "Emotet", "AgentTesla"`,
        check_logic: (input) => input.includes('urlhaus') || input.includes('URLhaus'),
        explanation: 'URLhaus is a crowd-sourced project that collects and shares URLs used for malware distribution. Instead of downloading a suspicious file to analyze it (which could infect your machine), you can search for the URL on URLhaus to see if it has already been reported—including what type of malware it delivers.'
      },
      {
        scenario: 'You extracted an IOC (Indicator of Compromise) from a threat report. Use ThreatFox (Abuse.ch) to search for related indicators and context.',
        vulnerable_code: `# Naive approach: manually Googling the IOC\n$ google "45.33.32.156 malware"`,
        fix_steps: ['Navigate to threatfox.abuse.ch.', 'Search for the IOC (IP, domain, hash, or URL).', 'Review the associated malware, confidence level, and linked indicators.'],
        patched_code: `# Search ThreatFox for the IOC\n# threatfox.abuse.ch → Search IOC → paste: 45.33.32.156\n# Review:\n#   - IOC type: ip:port, domain, url, hash\n#   - Malware: associated family (e.g., CobaltStrike)\n#   - Confidence: percentage rating\n#   - Reporter: community or automated feed`,
        check_logic: (input) => input.includes('threatfox') || input.includes('ThreatFox'),
        explanation: 'ThreatFox is a free platform for sharing Indicators of Compromise (IOCs) associated with malware. Unlike a generic Google search, ThreatFox gives you structured, verified intelligence—including the malware family, confidence level, and related IOCs—so you can quickly assess how serious a threat is.'
      },
      {
        scenario: 'Your IDS flagged a suspicious SSL connection. Use SSL Blacklist (Abuse.ch) to check if the JA3 fingerprint is associated with known malware.',
        vulnerable_code: `# Naive approach: ignoring the SSL alert\n$ echo "Probably a false positive" >> /var/log/notes.txt`,
        fix_steps: ['Extract the JA3 fingerprint from the IDS alert.', 'Search sslbl.abuse.ch for the JA3 hash.', 'Check if it matches known malware C2 SSL certificates.'],
        patched_code: `# Step 1: Extract JA3 hash from the IDS/Zeek logs\n# JA3: e7d705a3286e19ea42f587b344ee6865\n\n# Step 2: Search SSL Blacklist\n# sslbl.abuse.ch → Search → JA3 Fingerprints\n# Paste hash: e7d705a3286e19ea42f587b344ee6865\n# Review: associated malware, listing reason, certificate details`,
        check_logic: (input) => input.includes('sslbl') || input.includes('JA3') || input.includes('SSL Blacklist'),
        explanation: 'JA3 is a method of fingerprinting SSL/TLS connections. Each malware family often creates a unique pattern when establishing encrypted connections. The SSL Blacklist at Abuse.ch catalogs these fingerprints, so you can determine if a suspicious encrypted connection is actually malware phoning home to its controller.'
      },
      {
        scenario: 'An employee received a suspicious email claiming to be from IT support. Use PhishTool to analyze the email headers and determine if it is a phishing attempt.',
        vulnerable_code: `# Naive approach: checking only the "From" display name\n$ echo "From: IT Support <support@company.com> — looks legit!"`,
        fix_steps: ['Export the email as .eml file.', 'Upload to PhishTool for analysis.', 'Review sender IP, SPF/DKIM results, and embedded URLs.'],
        patched_code: `# Step 1: Export the suspicious email as .eml\n# Step 2: Upload to PhishTool (phishtool.com)\n# Review:\n#   - Sender IP: does it match company mail servers?\n#   - SPF/DKIM: PASS or FAIL?\n#   - Reply-To: different from the From address?\n#   - Embedded URLs: do they lead to a phishing page?\n#   - Attachments: are there suspicious macros?`,
        check_logic: (input) => input.includes('PhishTool') || (input.includes('SPF') && input.includes('DKIM')),
        explanation: 'PhishTool helps SOC analysts investigate suspicious emails by automatically extracting and analyzing metadata like sender IP addresses, email authentication results (SPF/DKIM), reply-to mismatches, and embedded URLs. The "From" display name can be easily faked, but these deeper indicators reveal the true origin of an email.'
      },
      {
        scenario: 'You need to assess the reputation of an IP address that appeared in your SIEM alerts. Use Cisco Talos Intelligence to check its threat score.',
        vulnerable_code: `# Naive approach: assuming the IP is safe because it resolves\n$ nslookup 203.0.113.50\n# "It resolves to a domain, so it must be fine."`,
        fix_steps: ['Navigate to talosintelligence.com.', 'Search for the IP address.', 'Review the reputation score, threat category, and email volume.'],
        patched_code: `# Search Cisco Talos Intelligence\n# talosintelligence.com → Reputation Lookup → 203.0.113.50\n# Review:\n#   - Reputation: Poor / Neutral / Good\n#   - Threat Category: spam, malware, phishing\n#   - Volume: email sending patterns\n#   - Owner: network/ASN information\n#   - Associated domains and DNS records`,
        check_logic: (input) => input.includes('Talos') || input.includes('talosintelligence'),
        explanation: 'Cisco Talos is one of the world\'s largest threat intelligence teams. Their free Reputation Lookup tool scores IP addresses on a scale from Poor to Good based on real-time data from Cisco\'s global network. A "Poor" score means the IP has been observed sending spam, hosting malware, or conducting phishing attacks.'
      },
      {
        scenario: 'A colleague shared a suspicious file hash from an incident report. Use VirusTotal to check how many antivirus engines detect it as malicious.',
        vulnerable_code: `# Naive approach: running the file in a sandbox without checking first\n$ ./unknown_binary`,
        fix_steps: ['Navigate to virustotal.com.', 'Paste the file hash (MD5, SHA1, or SHA256).', 'Review the detection ratio, community comments, and behavior analysis.'],
        patched_code: `# Search VirusTotal for the file hash\n# virustotal.com → Search → paste SHA256:\n# d41d8cd98f00b204e9800998ecf8427e\n# Review:\n#   - Detection ratio: e.g., 45/72 engines flagged\n#   - Malware name: identified family names\n#   - Behavior: sandboxed execution results\n#   - Relations: contacted IPs, dropped files\n#   - Community: analyst comments and votes`,
        check_logic: (input) => input.includes('VirusTotal') || input.includes('virustotal'),
        explanation: 'VirusTotal aggregates results from 70+ antivirus engines and sandboxes. By submitting a file hash, you can instantly see how many security vendors flag it as malicious, what malware family it belongs to, and what it does when executed—all without running the file on your own machine. It is every SOC analyst\'s first stop for file analysis.'
      },
      {
        scenario: 'Full investigation: you received a phishing email with a suspicious attachment and an embedded link. Use multiple threat intel tools together to build a complete picture.',
        vulnerable_code: `# Naive approach: only checking one source\n$ echo "VirusTotal says clean, so we are safe!"`,
        fix_steps: ['Hash the attachment and check on VirusTotal + MalwareBazaar.', 'Submit the embedded URL to UrlScan.io + URLhaus.', 'Analyze the email headers with PhishTool.', 'Cross-reference the sender IP on Cisco Talos + ThreatFox.'],
        patched_code: `# COMPLETE THREAT INTEL WORKFLOW\n# 1. Email Analysis:\n#    PhishTool → upload .eml → check SPF/DKIM, sender IP\n# 2. Attachment Analysis:\n#    sha256sum attachment.pdf → search VirusTotal + MalwareBazaar\n# 3. URL Analysis:\n#    UrlScan.io → scan embedded link → check redirects\n#    URLhaus → verify if URL distributes malware\n# 4. IP/IOC Correlation:\n#    Cisco Talos → sender IP reputation\n#    ThreatFox → search all extracted IOCs\n# 5. Document findings in incident report`,
        check_logic: (input) => (input.includes('VirusTotal') || input.includes('virustotal')) && (input.includes('PhishTool') || input.includes('UrlScan') || input.includes('urlscan') || input.includes('Talos')),
        explanation: 'Real-world threat intelligence is never about a single tool. A professional SOC analyst cross-references multiple sources to build a complete picture. One tool might miss something another catches. By combining email analysis (PhishTool), file reputation (VirusTotal, MalwareBazaar), URL scanning (UrlScan.io, URLhaus), and IP reputation (Cisco Talos, ThreatFox), you get a thorough, defensible investigation.'
      }
    ]
  }
};
