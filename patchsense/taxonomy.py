"""Vulnerability family taxonomy — CWE-to-family mappings and descriptions.

This module is the single source of truth for:
  - CWE → vulnerability family classification
  - Family descriptions (generalized, no specific CVE data)
  - Family metadata used by detection, suggestion, and training
"""

from __future__ import annotations


# ============================================================================
# CWE → Family mappings
# ============================================================================

CWE_FAMILIES: dict[str, set[str]] = {
    "buffer-overflow": {
        "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787",
        "CWE-805", "CWE-806",
    },
    "use-after-free": {"CWE-416", "CWE-761"},
    "null-deref": {"CWE-476"},
    "integer-overflow": {
        "CWE-190", "CWE-191", "CWE-193", "CWE-129", "CWE-189",
        "CWE-681",  # Integer overflow to buffer overflow
    },
    "injection": {
        "CWE-78", "CWE-79", "CWE-89", "CWE-94",
        "CWE-77",   # Command injection (generic)
        "CWE-74",   # Improper neutralization of output
        "CWE-116",  # Improper encoding/escaping of output
        "CWE-90",   # LDAP injection
        "CWE-113",  # HTTP response splitting
    },
    "deserialization": {
        "CWE-502",  # Deserialization of untrusted data
    },
    "xxe": {
        "CWE-611",  # Improper restriction of XML external entity reference
        "CWE-776",  # Improper restriction of recursive entity references (XML)
    },
    "path-traversal": {"CWE-22", "CWE-23", "CWE-59"},
    "auth-bypass": {
        "CWE-798", "CWE-862", "CWE-287", "CWE-863",
        "CWE-264",  # Permissions, privileges, and access controls
        "CWE-284",  # Improper access control
        "CWE-285",  # Improper authorization
        "CWE-269",  # Improper privilege management
        "CWE-306",  # Missing authentication for critical function
        "CWE-307",  # Improper restriction of excessive auth attempts
        "CWE-521",  # Weak password requirements
        "CWE-613",  # Insufficient session expiration
        "CWE-732",  # Incorrect permission assignment
    },
    "csrf": {
        "CWE-352",  # Cross-site request forgery
    },
    "race-condition": {"CWE-362", "CWE-367"},
    "resource-mgmt": {
        "CWE-400", "CWE-770", "CWE-401", "CWE-835",
        "CWE-399",  # Resource management errors (generic)
        "CWE-754",  # Improper check for unusual/exceptional conditions
        "CWE-755",  # Improper handling of exceptional conditions
    },
    "info-leak": {
        "CWE-200", "CWE-209", "CWE-532",
        "CWE-203",  # Observable discrepancy (timing side-channels)
        "CWE-538",  # Insertion of sensitive info into externally-accessible file
    },
    "crypto-misuse": {
        "CWE-310",  # Cryptographic issues (generic)
        "CWE-295",  # Improper certificate validation
        "CWE-326",  # Inadequate encryption strength
        "CWE-327",  # Use of broken/risky crypto algorithm
        "CWE-330",  # Insufficient randomness
        "CWE-338",  # Use of weak PRNG
        "CWE-347",  # Improper verification of cryptographic signature
        "CWE-358",  # Improperly implemented security check for standard
        "CWE-916",  # Use of password hash with insufficient effort
    },
    "ssrf": {
        "CWE-918",  # Server-side request forgery
        "CWE-610",  # Externally controlled reference to resource
    },
    "uninitialized": {"CWE-457", "CWE-824", "CWE-908"},
    "type-confusion": {"CWE-843"},
    "double-free": {"CWE-415", "CWE-763"},
    "format-string": {"CWE-134"},
    "file-upload": {
        "CWE-434",  # Unrestricted upload of file with dangerous type
    },
}

# Reverse lookup: CWE → family
CWE_TO_FAMILY: dict[str, str] = {}
for _family, _cwes in CWE_FAMILIES.items():
    for _cwe in _cwes:
        CWE_TO_FAMILY[_cwe] = _family

# All known family names (including catch-all buckets)
ALL_FAMILIES = sorted(CWE_FAMILIES.keys()) + ["general-bugfix", "other", "unknown"]


def classify_family(cwe: str, source: str = "") -> str:
    """Map a CWE ID to its vulnerability family.

    Returns 'general-bugfix' for non-security bug datasets (ASE'20/Defects4J),
    'unknown' if cwe is empty/missing, 'other' if the CWE is valid but not
    in any defined family.
    """
    # ASE'20/Defects4J entries are general program bugs, not security vulns.
    # They're valuable for training fix-vs-suppress classification but must
    # not dilute security-specific family invariants.
    if source == "ase20" and not cwe:
        return "general-bugfix"

    if not cwe:
        return "unknown"
    cwe = cwe.strip().upper()
    if not cwe.startswith("CWE-"):
        return "unknown"
    return CWE_TO_FAMILY.get(cwe, "other")


# ============================================================================
# Generalized family descriptions (no specific CVE details)
# ============================================================================

FAMILY_DESCRIPTIONS: dict[str, str] = {
    "buffer-overflow": (
        "Buffer overflow vulnerability: Memory is written or read beyond the "
        "bounds of an allocated buffer. Common in C/C++ code involving memcpy, "
        "strcpy, array indexing, or pointer arithmetic. Root-cause fixes typically "
        "correct the allocation size, fix the copy length, or change the data type "
        "to prevent overflow. Symptom suppressions add bounds checks at call sites "
        "without fixing the underlying size mismatch."
    ),
    "use-after-free": (
        "Use-after-free vulnerability: Memory is accessed after it has been freed. "
        "Root-cause fixes restructure ownership so the pointer is not used after "
        "free, or nullify the pointer immediately after free. Symptom suppressions "
        "add null checks before use without ensuring the lifecycle is correct."
    ),
    "null-deref": (
        "Null pointer dereference: A pointer is dereferenced without checking for "
        "null. Root-cause fixes ensure the pointer is properly initialized or that "
        "the code path that leads to null is corrected. Symptom suppressions add "
        "a null guard that returns early without fixing why the pointer was null."
    ),
    "integer-overflow": (
        "Integer overflow vulnerability: An arithmetic operation produces a value "
        "outside the representable range, leading to wraparound or incorrect indexing. "
        "Root-cause fixes change the type to a wider integer, validate input ranges "
        "before arithmetic, or restructure the computation. Symptom suppressions "
        "add bounds checks on the result after overflow has already occurred."
    ),
    "injection": (
        "Code/command/SQL injection: Untrusted input is incorporated into a query, "
        "command, or code string without sanitization. Root-cause fixes add proper "
        "escaping, parameterized queries, or input encoding at the point of "
        "construction. Symptom suppressions add input validation at a different "
        "layer without fixing the unsafe construction."
    ),
    "path-traversal": (
        "Path traversal vulnerability: User-controlled input is used to construct "
        "a file path without sanitization, allowing access to files outside the "
        "intended directory. Root-cause fixes canonicalize the path and validate "
        "it against an allowed prefix. Symptom suppressions block specific patterns "
        "like '../' without comprehensive path normalization."
    ),
    "auth-bypass": (
        "Authentication/authorization bypass: A security check is missing or can "
        "be circumvented. Root-cause fixes add or correct the authentication/ "
        "authorization check at the enforcement point. Symptom suppressions add "
        "checks at peripheral locations without securing the core enforcement path."
    ),
    "race-condition": (
        "Race condition: Concurrent access to shared state without proper "
        "synchronization. Root-cause fixes add locks, atomic operations, or "
        "restructure to eliminate the shared mutable state. Symptom suppressions "
        "add retry logic or timing-dependent workarounds."
    ),
    "resource-mgmt": (
        "Resource management vulnerability: Resources (memory, file handles, "
        "connections) are not properly acquired, tracked, or released. Includes "
        "memory leaks, infinite loops, and resource exhaustion. Root-cause fixes "
        "correct the lifecycle management. Symptom suppressions add limits or "
        "timeouts without fixing the leak."
    ),
    "info-leak": (
        "Information disclosure: Sensitive data is exposed through error messages, "
        "logs, or uninitialized memory. Root-cause fixes remove the exposure at "
        "the source. Symptom suppressions filter output without addressing what "
        "is being leaked or why."
    ),
    "uninitialized": (
        "Uninitialized variable/memory: A variable or memory region is used before "
        "being initialized. Root-cause fixes add proper initialization at the "
        "declaration or allocation site. Symptom suppressions add checks for "
        "specific values without ensuring initialization."
    ),
    "double-free": (
        "Double-free vulnerability: Memory is freed more than once, corrupting "
        "the heap allocator. Root-cause fixes restructure ownership so each "
        "allocation has exactly one free, or nullify pointers after free. "
        "Symptom suppressions add a flag to track whether free was called."
    ),
    "type-confusion": (
        "Type confusion: An object is used as a different type than what it "
        "actually is. Root-cause fixes add type checking or correct the cast. "
        "Symptom suppressions add size checks without verifying the actual type."
    ),
    "format-string": (
        "Format string vulnerability: User input is passed as a format string "
        "argument. Root-cause fixes use a literal format string with the input "
        "as a parameter. Symptom suppressions filter specific format specifiers."
    ),
    "deserialization": (
        "Deserialization of untrusted data: An application deserializes data from "
        "an untrusted source without type restrictions, enabling remote code "
        "execution or object injection. Root-cause fixes add type allowlists, "
        "use safe deserialization APIs (e.g., JSON instead of native serialization), "
        "or validate the serialized data before deserialization. Symptom suppressions "
        "add input validation on the serialized bytes without restricting the types "
        "that can be instantiated."
    ),
    "xxe": (
        "XML External Entity (XXE) injection: An XML parser processes external "
        "entity references in untrusted input, allowing file disclosure, SSRF, "
        "or denial of service. Root-cause fixes disable external entity processing "
        "in the parser configuration (e.g., FEATURE_SECURE_PROCESSING, "
        "disallow-doctype-decl). Symptom suppressions filter specific entity "
        "patterns in the XML input without securing the parser itself."
    ),
    "csrf": (
        "Cross-Site Request Forgery: A web application performs state-changing "
        "operations on authenticated requests without verifying the request "
        "originated from the application itself. Root-cause fixes add anti-CSRF "
        "tokens validated on every state-changing request, or use SameSite cookie "
        "attributes. Symptom suppressions check the Referer header or add "
        "CORS restrictions without proper token validation."
    ),
    "crypto-misuse": (
        "Cryptographic misuse: Broken, weak, or improperly implemented cryptographic "
        "operations. Includes use of weak algorithms (MD5, SHA1 for security), "
        "insufficient key lengths, improper certificate validation, weak PRNGs, "
        "or incorrect signature verification. Root-cause fixes replace the weak "
        "primitive with a strong one (e.g., bcrypt, AES-256-GCM) or correct the "
        "validation logic. Symptom suppressions add length checks or format "
        "validation without fixing the underlying cryptographic weakness."
    ),
    "ssrf": (
        "Server-Side Request Forgery: An application makes HTTP/network requests "
        "using attacker-controlled URLs, allowing access to internal services or "
        "metadata endpoints. Root-cause fixes validate and restrict the target URL "
        "against an allowlist of permitted hosts/schemes, or use a proxy that "
        "enforces network boundaries. Symptom suppressions blocklist specific "
        "IP ranges (e.g., 169.254.x.x) without comprehensive URL validation."
    ),
    "file-upload": (
        "Unrestricted file upload: An application accepts file uploads without "
        "validating the file type, content, or storage location, enabling code "
        "execution or overwrite of critical files. Root-cause fixes validate "
        "both the file extension and content type (magic bytes), store uploads "
        "outside the web root with randomized names, and set proper permissions. "
        "Symptom suppressions check only the client-supplied Content-Type header "
        "or file extension without verifying actual content."
    ),
    "general-bugfix": (
        "General program bug (non-security): A functional defect such as incorrect "
        "logic, wrong return value, missing edge case, or broken algorithm. These "
        "are not security vulnerabilities but the fix-vs-suppress distinction still "
        "applies: root-cause fixes correct the defective logic, while symptom "
        "suppressions add guards or special cases that hide the incorrect behavior."
    ),
    "unknown": (
        "Vulnerability with unspecified CWE. Analyze the structural patterns "
        "in the code to determine whether a fix addresses a root cause or "
        "merely suppresses a symptom."
    ),
    "other": (
        "Vulnerability that does not fit standard CWE families. Analyze the "
        "structural patterns in the code to determine whether a fix addresses "
        "a root cause or merely suppresses a symptom."
    ),
}
