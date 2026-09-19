from .base_agent import BaseAgent


class FileUploadAgent(BaseAgent):
    """Agent for detecting file upload and file handling vulnerabilities."""
    name = "file_upload"

    tactical_guide = """
1. Note the upload's declared Content-Type vs the filename extension vs any
   magic-byte hint in the (truncated) body -- a mismatch is the first signal.
2. Check whether the response reveals WHERE the file lands (a returned URL/
   path) -- that's what makes an upload bypass exploitable at all.
3. Look for weak extension filtering (blocklist-shaped: rejects `.php` but
   not `.phtml`/`.php5`/double extensions) versus a real allowlist +
   content-type re-validation.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
File upload and file handling vulnerabilities. Look for:

FILE UPLOAD INDICATORS:
- Content-Type: multipart/form-data
- Request bodies with file parts (filename="...", Content-Type: application/octet-stream)
- Endpoints with upload, file, document, image, avatar in path
- Form fields of type file
- File size limits in responses or errors

FILE TYPE VALIDATION:
- Missing file type validation (accept any file)
- Client-side only validation (JavaScript checks that can be bypassed)
- File extension validation only (can be bypassed with double extensions)
- MIME type validation only (can be spoofed)
- Magic bytes/magic number validation missing
- Content validation missing or weak

FILE NAME ANALYSIS:
- Path traversal in filenames (/../ , ..\\, absolute paths)
- Null byte injection in filenames (%00)
- Special characters in filenames (;, |, &, `, $, >)
- Double extensions (.php.jpg, .asp.png)
- Alternative data streams (file.txt:hidden)
- Windows alternate data streams (file.txt::$DATA)

FILE CONTENT ANALYSIS:
- Files served from user-controllable paths
- Uploaded files accessible via direct URL
- Files executed server-side (PHP, ASP, JSP, Node.js, Python, etc.)
- SVG files with JavaScript (XSS via SVG)
- HTML files with JavaScript
- XML files (XXE potential)

SERVER CONFIGURATION:
- Upload directory is web-accessible
- Upload directory has execute permissions
- Missing size limits on uploads
- Missing virus scanning
- Files retain original permissions

RESPONSE INDICATORS:
- File URL returned in response
- File accessible at predictable path
- File executed when accessed
- Error messages revealing upload path
- Directory listing of upload directory

For suggested_test, propose:
- Upload PHP file with <?php system($_GET['cmd']); ?>
- Upload ASP file with <% Response.Write("test") %>
- Upload JSP file with <%= "test" %>
- Test path traversal: filename="../../malicious.php"
- Test double extension: filename="shell.php.jpg"
- Test MIME type spoofing: Content-Type: image/jpeg with PHP content
- Test null byte: filename="shell.php%00.jpg"

suggested_test MUST be concrete and testable in Burp Repeater:
- "Upload PHP file with system command execution payload"
- "Test path traversal with ../ in filename"
- "Upload file with double extension .php.jpg"
- "Test MIME type spoofing with image/jpeg Content-Type"

CONTEXT MATTERS:
- Different servers execute different file types (.php, .asp, .jsp, .py, .node, etc.)
- Some servers only execute files with specific extensions
- SVG files can contain JavaScript and trigger XSS
- File upload + stored XSS is a common attack chain
"""
