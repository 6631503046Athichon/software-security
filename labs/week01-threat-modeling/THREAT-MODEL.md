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
| Element                            | Type            | Trust boundary crossed?                   |
|------------------------------------|-----------------|-------------------------------------------|
| Web client                         | external entity | No - sits in the public internet zone     |
| Flask app (`app.py`)               | process         | No - sits in the application tier         |
| SQLite DB (`notes.db`)             | data store      | No - sits in the data tier                |
| `uploads/` store                   | data store      | No - sits in the data tier                |
| `/notes` flow                      | data flow       | Yes - boundary 1, internet -> application |
| `/upload` flow                     | data flow       | Yes - boundary 1, internet -> application |
| `/files/<name>` flow               | data flow       | Yes - boundary 1, internet -> application |
| SQL query flow (app -> `notes.db`) | data flow       | Yes - boundary 2, application -> data     |
| File I/O flow (app -> `uploads/`)  | data flow       | Yes - boundary 2, application -> data     |

Note. Elements sit inside a zone; only flows cross a boundary, which is why every Yes row is a
flow. Boundary 2 is nominal in this build: `notes.db` and `uploads/` live in `/app` next to
`app.py`, so nothing actually separates the application tier from the data tier here.


## 3. STRIDE analysis

| Element              |   | Sev      | Threat                                            |
|----------------------|---|----------|---------------------------------------------------|
| `/notes` flow        | S | High     | `owner` taken from the request body (`app.py:23`) |
|                      | T | High     | rows inserted under any owner                     |
|                      | R | High     | no log ties a note to an actor                    |
|                      | I | High     | all rows returned, no `WHERE` (`app.py:27`)       |
|                      | D | Medium   | unbounded bodies grow the DB                      |
|                      | E | High     | acting as another user is the default             |
| `/upload` flow       | S | Medium   | uploads are anonymous                             |
|                      | T | Critical | raw filename joined onto the path (`app.py:34`)   |
|                      | R | High     | no record of who uploaded what                    |
|                      | I | Medium   | echoes the accepted name (`app.py:35`)            |
|                      | D | High     | no size cap, disk fills and stays full            |
|                      | E | Critical | write to `app.py`, runs as root on restart        |
| `/files/<name>` flow | S | Low      | no auth to fetch a file                           |
|                      | T | Low      | read-only; tampering is on the write side         |
|                      | R | High     | no download log                                   |
|                      | I | Low      | reads confined to `uploads/` by `safe_join()`     |
|                      | D | Medium   | large repeated fetches consume bandwidth          |
|                      | E | Low      | serves only what the write side stored            |
| Flask app (process)  | S | Medium   | no TLS, so the server can be impersonated         |
|                      | T | High     | `/app/app.py` is writable                         |
|                      | R | High     | no logging subsystem exists                       |
|                      | I | Medium   | plain HTTP in transit (`app.py:43`)               |
|                      | D | High     | dev server used in production                     |
|                      | E | Critical | runs as root, no `USER` in the image              |
| `notes.db` store     | S | n/a      | a store has no identity to spoof                  |
|                      | T | High     | any file write reaches it                         |
|                      | R | Medium   | no row history; a change looks original           |
|                      | I | High     | no file perms, no encryption at rest              |
|                      | D | High     | no volume, so it dies with the container          |
|                      | E | Medium   | planted rows are later served as trusted          |
| `uploads/` store     | S | n/a      | a store has no identity to spoof                  |
|                      | T | Critical | any client name becomes a path here               |
|                      | R | High     | no metadata on who wrote each file                |
|                      | I | Medium   | any file is readable if the name is known         |
|                      | D | High     | unbounded growth, no quota                        |
|                      | E | Critical | shares `/app` with `app.py`                       |
| Web client (entity)  | S | High     | no accounts, so any `owner` can be claimed        |
|                      | T | Medium   | controls every field sent, incl. the filename     |
|                      | R | High     | nothing links an action to a person               |
|                      | I | Low      | receives responses over plain HTTP                |
|                      | D | Low      | one client can trigger the DoS paths above        |
|                      | E | Medium   | already fully privileged, nothing to escalate     |

Note. The `n/a` cells follow the classic STRIDE-per-element chart: a data store has no identity
to spoof, because it is reached by path rather than by authenticating to it.

## 4. Top 5 risks (likelihood × impact) + mitigation

1. Arbitrary file write via /upload (High × Critical)
   - Threat: raw f.filename is joined onto uploads/ (app.py:34), so ../ overwrites /app/app.py,
     which runs as root because the image sets no USER.
   - Mitigation: server-generated name + extension allow-list, store outside /app, verify
     realpath() after resolving.

2. All notes readable by anyone via GET /notes (High × High)
   - Threat: app.py:27 selects the whole table with no WHERE and no parameter.
   - Mitigation: require a session, filter WHERE owner = ?.

3. Owner spoofing on POST /notes (High × High)
   - Threat: owner is taken straight from the body (app.py:23), so notes can be stored under
     anyone's name.
   - Mitigation: derive owner from the verified token, reject the client-supplied field.

4. No audit logging (High × Medium)
   - Threat: no logging call anywhere in app.py, so nothing can be attributed and repeated
     attempts leave no trace.
   - Mitigation: log timestamp, client IP, identity, method and path on every write.

5. Unrestricted upload size and rate (Medium × High)
   - Threat: no MAX_CONTENT_LENGTH and no rate limit; with no volume declared, the filled disk
     stays filled after the attacker stops.
   - Mitigation: MAX_CONTENT_LENGTH of 5 MB plus per-IP rate limiting.

Ranking note. Risk 1 leads because it becomes code execution as root, not just data exposure.
Risk 4 is Medium impact alone but raises the odds of everything above it succeeding unnoticed.