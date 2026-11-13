# Official Video Demonstration Script & Recording Guide

**Project:** Secure User Authentication System  
**Estimated Run Time:** 2 minutes 30 seconds  
**Target Video File Location:** `docs/demo/authentication_system_demo.mp4` (or uploaded video recording)  
**Resolution:** 1080p (1920x1080) or 720p (1280x720) at 60fps  

---

## Prerequisites Before Recording

1. Start the server in development mode:
   ```bash
   $env:USE_IN_MEMORY_DB="true"; npm start
   ```
2. Open Google Chrome or any modern browser at `http://localhost:5000`.
3. Open browser Developer Tools (Network tab & Application -> Cookies tab) to visibly demonstrate the `HttpOnly` security cookie during recording.

---

## Click-by-Click Demonstration Script (9 Required Steps)

### Step 1: Open Application (Timestamp: 0:00 – 0:15)
- **Action:** Open browser and navigate to `http://localhost:5000` (redirects automatically to `/login`).
- **Visual:** Display the frosted glassmorphism card, photorealistic sky and clouds background, 3D royal-blue cube & matte jack at top right, and 3D blue torus at bottom left.
- **Narrator Script:**  
  *"Welcome to the demonstration of the Secure User Authentication System. The application opens to our responsive login interface, designed with modern frosted glassmorphism, 3D claymorphism visual elements, and a cloud-themed sky background."*

---

### Step 2: Navigate to Registration & Inspect Validation (Timestamp: 0:15 – 0:35)
- **Action:** Click `"Create an account"`. The browser transitions smoothly to `http://localhost:5000/register`.
- **Visual:** Display the 4 input fields (`Username`, `Email Address`, `Password`, `Confirm Password`) and the real-time password requirement checklist on the right.
- **Narrator Script:**  
  *"Clicking 'Create an account' opens the registration interface. Notice our real-time password strength checklist enforcing 8+ characters, uppercase, lowercase, numbers, special characters, and maximum 72 UTF-8 bytes for bcrypt truncation protection."*

---

### Step 3: Register a New User Account (Timestamp: 0:35 – 0:55)
- **Action:** Enter valid credentials:
  - **Username:** `Anfas`
  - **Email Address:** `anfas@example.com`
  - **Password:** `StrongPassword#2026`
  - **Confirm Password:** `StrongPassword#2026`
- Click `"Create Account"`.
- **Visual:** An alert banner displays `"User registered successfully. Redirecting to sign in..."` and automatically redirects to `/login`.
- **Narrator Script:**  
  *"We register a new user named Anfas. Inputs are strictly sanitized on both client and server to prevent XSS and NoSQL injection attacks. The password is cryptographically hashed with bcrypt using 12 salt rounds before storage. The plaintext password is never stored or returned."*

---

### Step 4: Log In with Registered Credentials (Timestamp: 0:55 – 1:15)
- **Action:** On the Sign In page, enter:
  - **Email or Username:** `anfas@example.com`
  - **Password:** `StrongPassword#2026`
- Click `"Sign In"`.
- **Visual:** Success notification triggers and redirects to `/dashboard`.
- **Narrator Script:**  
  *"Now we log in using the newly created credentials. The backend verifies the password using constant-time hash comparison, issues an HMAC-SHA256 signed JWT, and delivers it securely in a signed HttpOnly cookie."*

---

### Step 5: Access Protected Dashboard (Timestamp: 1:15 – 1:35)
- **Action:** The authenticated `/dashboard` loads.
- **Visual:** Clean top bar with `"Dashboard"` title on the left and `"Logout"` button on the right. Main card displays dynamically retrieved user data:
  - `Welcome, Anfas`
  - `Email: anfas@example.com`
- **Narrator Script:**  
  *"Upon authentication, the user is redirected to the protected dashboard. Following minimal, production-grade principles, the dashboard dynamically displays only the authenticated user's name and email address, completely free of extraneous technical debug information or sensitive token leaks."*

---

### Step 6: Verify Route Protection against Unauthenticated Access (Timestamp: 1:35 – 1:50)
- **Action:** Open a new Incognito / Private window (or clear cookies) and attempt to directly navigate to `http://localhost:5000/dashboard`.
- **Visual:** The server immediately intercepts the request via `protectPage` middleware, blocks access, and redirects to `http://localhost:5000/?reason=auth_required` with an alert message: `"Authentication required. Please sign in to access your dashboard."`
- **Narrator Script:**  
  *"To verify backend route protection, an unauthenticated request to the dashboard URL is immediately blocked at the server boundary with anti-caching headers and redirected to the login page."*

---

### Step 7: Perform Secure Logout (Timestamp: 1:50 – 2:05)
- **Action:** In the authenticated window on `/dashboard`, click the `"Logout"` button.
- **Visual:** The user is logged out, redirected to `http://localhost:5000/?reason=logged_out`, and a success banner displays: `"You have been securely logged out."`
- **Narrator Script:**  
  *"Clicking Logout performs a dual-layer revocation: the client-side HttpOnly cookie is wiped, and the token's unique cryptographic ID (JTI) is recorded in the server-side revocation blacklist."*

---

### Step 8: Verify Session Invalidation (Timestamp: 2:05 – 2:15)
- **Action:** Press the browser's "Back" button or re-type `http://localhost:5000/dashboard`.
- **Visual:** The protected route guard immediately redirects back to `/login?reason=auth_required`. Replaying the previous session is completely impossible.
- **Narrator Script:**  
  *"Attempting to navigate back to the dashboard confirms the session is permanently invalidated on both client and server."*

---

### Step 9: Demonstrate Error Messages for Invalid Credentials (Timestamp: 2:15 – 2:30)
- **Action:** Enter a non-existent email or wrong password (`wrong_user@example.com` / `WrongPass#1234`) and click `"Sign In"`.
- **Visual:** Red frosted glass alert displays: `"Invalid email/username or password."`
- **Narrator Script:**  
  *"Finally, entering invalid credentials returns a normalized, safe error message that protects user privacy by preventing account harvesting and username enumeration. The demonstration is complete."*

