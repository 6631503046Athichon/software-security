# Threat Model — Sample Application

## 1. Data-flow diagram
(Insert your DFD image. Mark trust boundaries with dashed lines.)

[ Web Client ] --(HTTP Request)--> [ Trust Boundary: Internet / App ]
                                         |
                                         v
                                  ( Flask App: app.py )
                                    /              \
         (SQL Queries)             /                \ (File I/O)
                      v                              v
           [( SQLite DB: notes.db )]        [( uploads/ Store )]

![alt text](<Screenshot 2026-08-15 152950.png>)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → Application Tier) |
| Flask app (`app.py`) | process | yes (Application Tier → Data Tier) |
| SQLite DB (`notes.db`) | data store | no (Internal Data Tier) |
| `uploads/` store | data store | no (Internal Data Tier) |
| `/notes` flow | data flow | yes (Internet → Application Tier) |
| `/upload` flow | data flow | yes (Internet → Application Tier) |
| `/files/<name>` flow | data flow | yes (Internet → Application Tier) |

## 3. STRIDE analysis
| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes| High: Accepts client-supplied `owner` without auth, enabling identity spoofing. | High: Modifies or writes notes under any user due to missing ownership validation. | High: No audit logging to record note creation or retrieval. | High: Reads private notes of any user by changing the `owner` parameter. | Medium: Bulk requests with large payloads could exhaust database storage. | High: Allows unauthenticated users to perform actions as arbitrary user accounts. |
| /upload | Medium: Unauthenticated upload allows anonymous asset submission. | Critical: Unsanitized `f.filename` allows path traversal (`../`) and arbitrary file write. | High: No logging of uploader IP address or upload activity. | High: Returns absolute internal server disk path in the HTTP response. | High: Unrestricted file sizes allow disk space exhaustion attacks. | Critical: Overwriting system files or scripts enables Remote Code Execution (RCE). |
| /files/\<name\>| Low: No authentication required to request stored files. | Medium: Serves potentially altered files if directory contents are modified. | High: No access logs recorded when files are downloaded. | High: Path traversal enables reading sensitive system files outside `uploads/`. | Medium:Repeatedly fetching large files can exhaust network bandwidth. | High: Exfiltrating sensitive system configuration files elevates attacker privileges. |

## 4. Top 5 risks (likelihood × impact) + mitigation
1. Arbitrary File Write / Path Traversal via /upload (High × Critical)
   - Threat: Unsanitized f.filename allows path traversal (../), leading to arbitrary file overwrite and RCE.
   - Mitigation: Use secure_filename(), UUID file renaming, extension allowlists, and store files outside web root.

2. Owner Spoofing on /notes (High × High)
   - Threat: Missing authentication allows attackers to spoof owner parameters to read or modify arbitrary user notes.
   - Mitigation: Implement JWT/session-based authentication and derive user identity from verified tokens.

3. Internal Path Disclosure via /upload (High × Medium)
   - Threat: API responses return absolute server disk paths, exposing internal filesystem layout.
   - Mitigation: Remove raw filesystem paths from responses; return abstract file IDs or public URLs instead.

4. Absence of Audit Logging (High × Medium)
   - Threat: Lack of request logging prevents security monitoring, incident investigation, and non-repudiation.
   - Mitigation: Add logging middleware to record timestamps, client IPs, user IDs, endpoints, and actions.

5. Unrestricted Upload Size & Request Rate (Medium × High)
   - Threat: Uncapped payload sizes and request rates leave the server vulnerable to storage and resource exhaustion (DoS).
   - Mitigation: Enforce MAX_CONTENT_LENGTH in Flask (e.g., 5MB limit) and implement request rate limiting.
