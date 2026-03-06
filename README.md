# YazidSafeLab 🛡️

A local-only educational application to learn web security through defensive coding.

## How it Works
1. **Identify**: Read the vulnerable code snippets.
2. **Analyze**: Understand the security flaw and the defense strategy.
3. **Verify**: Study the patched implementation and run "Safety Checks" to verify secure patterns.

## Tech Stack
- **Next.js 15 (App Router)**
- **JavaScript**
- **Pure CSS**
- **Zod** (Validation)

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the development server:
   ```bash
   npm run dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Security Warning
This application is created for **educational purposes only**. The vulnerabilities demonstrated are intentional and should never be used in a production environment. The application is designed to run locally and does not contain any real authentication or database systems.

---

### Included Modules
- **Input Validation**: Sanitizing user input with Zod.
- **Auth vs Authz**: Implementing role-based access control.
- **Broken Access Control**: Ownership checks for object reference.
- **CSRF**: Understanding SameSite cookies and token patterns.
- **Security Headers**: Implementing CSP and security-related headers.
- **Rate Limiting**: Protecting routes from abuse.
