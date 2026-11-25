--------------------------------------------------------------------------------
-- grant_recon.sql
--
-- Replaces a broad read-only role (e.g. one holding SELECT ANY TABLE, or SELECT
-- on every table in a schema) with the specific object grants each user
-- actually needs. Works for any role / any schemas; nothing is hard-coded.
--
-- HOW IT DECIDES WHAT IS "ACTUALLY NEEDED" (evidence sources, combined):
--   CAPTURE    - Oracle Privilege Analysis (DBMS_PRIVILEGE_CAPTURE) records
--                every object a user touched *through the old role*. This is
--                the primary source. (Enterprise Edition, 12c+, no extra
--                license since 2018.)
--   AUDIT      - Alternative for SE2 / no PA: a unified-audit policy on the
--                role's ANY privileges (e.g. SELECT ANY TABLE). Records the
--                object each time the ANY privilege was actually exercised.
--   DEPENDENCY - Views/packages/procedures OWNED by the user that reference
--                other schemas (DBA_DEPENDENCIES, synonyms resolved). Stored
--                code ignores roles, so these are always granted DIRECTLY, and
--                WITH GRANT OPTION when the user's view is granted onward.
--   MANUAL     - Anything you know is needed but wasn't exercised during the
--                capture window (grant_recon.add_manual).
--
-- Each candidate is then filtered: objects the user owns, objects that no
-- longer exist, Oracle-maintained schemas, your owner include/exclude regex,
-- and anything the user ALREADY has (direct, PUBLIC, or via roles they keep).
-- What's left becomes the grant script.
--
-- PREREQUISITES - install into and run from a dedicated admin account:
--   CREATE USER grant_admin IDENTIFIED BY "..." QUOTA 200M ON users;
--   GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE PROCEDURE TO grant_admin;
--   GRANT SELECT ANY DICTIONARY TO grant_admin;   -- must be DIRECT (needed to compile)
--   GRANT GRANT ANY OBJECT PRIVILEGE, GRANT ANY ROLE, CREATE ROLE TO grant_admin;
--   GRANT CAPTURE_ADMIN TO grant_admin;           -- Privilege Analysis
--   GRANT AUDIT_ADMIN, AUDIT_VIEWER TO grant_admin;  -- only for METHOD => 'AUDIT'
-- The package is invoker-rights; run it connected as grant_admin (or with
-- ALTER SESSION SET CURRENT_SCHEMA = grant_admin).
--
-- WORKFLOW (example role APP_READONLY):
--   SET SERVEROUTPUT ON SIZE UNLIMITED
--   1. EXEC grant_recon.start_capture('APP_READONLY');           -- or ,'AUDIT' on SE2
--   2. Let it run a full business cycle (month-end, batch, quarterly reports...)
--   3. EXEC grant_recon.stop_capture('APP_READONLY');
--   4. VAR run NUMBER
--      EXEC :run := grant_recon.build_plan('APP_READONLY');
--      -- options: p_grantees=>'RPT_USER,ETL_USER', p_grant_mode=>'ROLE',
--      --          p_priv_style=>'READ', p_owner_include=>'^(HR|FIN)$', ...
--   5. Review:  SELECT * FROM gr_needed WHERE run_id = :run ORDER BY 2,3,4;
--      Missing something?  EXEC grant_recon.add_manual('RPT_USER','HR','EMP_V');
--      then rebuild (step 4) - every build is a new run_id; old runs are kept.
--   6. SPOOL change_ticket.sql
--      EXEC grant_recon.print_script(:run);
--      SPOOL OFF
--   7. EXEC grant_recon.execute_phase(:run, 'GRANTS');   -- additive, safe
--      ... test the applications ...
--      EXEC grant_recon.execute_phase(:run, 'REVOKES');  -- removes the old role
--   8. If something breaks: EXEC grant_recon.execute_phase(:run, 'ROLLBACK');
--   9. When done: EXEC grant_recon.drop_capture('APP_READONLY');
--      (drop_capture deletes the PA results - build your plan first)
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- Repository tables
--------------------------------------------------------------------------------
CREATE TABLE gr_capture (
  old_role      VARCHAR2(128) NOT NULL,
  method        VARCHAR2(10)  NOT NULL,          -- PA | AUDIT
  capture_name  VARCHAR2(128) NOT NULL,
  scope         VARCHAR2(10),                    -- ROLE | DATABASE (PA only)
  started_at    DATE,
  stopped_at    DATE,
  status        VARCHAR2(10),                    -- RUNNING | STOPPED | DROPPED
  CONSTRAINT gr_capture_pk PRIMARY KEY (old_role, method)
);

CREATE SEQUENCE gr_run_seq;

CREATE TABLE gr_run (
  run_id             NUMBER        PRIMARY KEY,
  old_role           VARCHAR2(128) NOT NULL,
  grant_mode         VARCHAR2(10)  NOT NULL,     -- DIRECT | ROLE
  role_pattern       VARCHAR2(128),
  priv_style         VARCHAR2(6)   NOT NULL,     -- SELECT | READ
  owner_include      VARCHAR2(400),
  owner_exclude      VARCHAR2(400),
  revoke_direct_any  CHAR(1)       NOT NULL,
  created_at         DATE          DEFAULT SYSDATE NOT NULL,
  created_by         VARCHAR2(128) DEFAULT USER NOT NULL
);

CREATE TABLE gr_run_grantee (
  run_id        NUMBER        NOT NULL,
  grantee       VARCHAR2(128) NOT NULL,
  direct_grant  CHAR(1),                         -- old role granted directly?
  admin_option  VARCHAR2(3),
  via_roles     VARCHAR2(4000),                  -- other roles that carry the old role
  new_role      VARCHAR2(128),                   -- ROLE mode only
  CONSTRAINT gr_run_grantee_pk PRIMARY KEY (run_id, grantee)
);

CREATE TABLE gr_kept_role (                      -- roles the user keeps after cut-over
  run_id   NUMBER        NOT NULL,
  grantee  VARCHAR2(128) NOT NULL,
  role     VARCHAR2(128) NOT NULL,
  CONSTRAINT gr_kept_role_pk PRIMARY KEY (run_id, grantee, role)
);

CREATE TABLE gr_evidence (                       -- raw evidence rows
  run_id           NUMBER        NOT NULL,
  grantee          VARCHAR2(128) NOT NULL,
  object_owner     VARCHAR2(128) NOT NULL,
  object_name      VARCHAR2(128) NOT NULL,
  object_type      VARCHAR2(30),
  privilege        VARCHAR2(40)  NOT NULL,
  source           VARCHAR2(12)  NOT NULL,       -- CAPTURE | AUDIT | DEPENDENCY | MANUAL
  needs_direct     CHAR(1)       DEFAULT 'N' NOT NULL,
  needs_grant_opt  CHAR(1)       DEFAULT 'N' NOT NULL,
  detail           VARCHAR2(1000)
);
CREATE INDEX gr_evidence_ix ON gr_evidence (run_id, grantee);

CREATE TABLE gr_needed (                         -- one row per grantee/object/privilege
  run_id           NUMBER        NOT NULL,
  grantee          VARCHAR2(128) NOT NULL,
  object_owner     VARCHAR2(128) NOT NULL,
  object_name      VARCHAR2(128) NOT NULL,
  object_type      VARCHAR2(30),
  privilege        VARCHAR2(40)  NOT NULL,
  needs_direct     CHAR(1),
  needs_grant_opt  CHAR(1),
  from_capture     CHAR(1),
  from_audit       CHAR(1),
  from_dependency  CHAR(1),
  from_manual      CHAR(1),
  evidence_rows    NUMBER,
  disposition      VARCHAR2(20),  -- GRANT | ALREADY_HAS | SUPERSEDED | OWN_OBJECT | MISSING | ORACLE_OWNED | FILTERED
  detail           VARCHAR2(1000),
  CONSTRAINT gr_needed_pk PRIMARY KEY (run_id, grantee, object_owner, object_name, privilege)
);

CREATE TABLE gr_manual (                         -- persistent manual additions
  grantee        VARCHAR2(128) NOT NULL,
  object_owner   VARCHAR2(128) NOT NULL,
  object_name    VARCHAR2(128) NOT NULL,
  privilege      VARCHAR2(40)  NOT NULL,
  needs_direct   CHAR(1)       DEFAULT 'N' NOT NULL,
  note           VARCHAR2(400),
  added_at       DATE          DEFAULT SYSDATE,
  CONSTRAINT gr_manual_pk PRIMARY KEY (grantee, object_owner, object_name, privilege)
);

CREATE TABLE gr_script (
  run_id       NUMBER         NOT NULL,
  seq          NUMBER         NOT NULL,
  grantee      VARCHAR2(128),
  phase        VARCHAR2(10)   NOT NULL,          -- INFO | GRANTS | REVOKES | ROLLBACK
  stmt         VARCHAR2(4000) NOT NULL,
  status       VARCHAR2(10)   DEFAULT 'PENDING' NOT NULL,  -- PENDING | DONE | ERROR | N/A
  error_msg    VARCHAR2(4000),
  executed_at  DATE,
  CONSTRAINT gr_script_pk PRIMARY KEY (run_id, seq)
);

--------------------------------------------------------------------------------
-- Package spec
--------------------------------------------------------------------------------
CREATE OR REPLACE PACKAGE grant_recon AUTHID CURRENT_USER AS

  -- Begin recording real usage of the old role.
  --   p_method: 'PA' (Privilege Analysis, default) or 'AUDIT' (unified audit, for SE2)
  --   p_scope : PA only. 'ROLE' (default) = only privileges used via p_old_role;
  --             'DATABASE' = all privilege use (use if users also hold ANY privs directly)
  PROCEDURE start_capture(p_old_role IN VARCHAR2,
                          p_method   IN VARCHAR2 DEFAULT 'PA',
                          p_scope    IN VARCHAR2 DEFAULT 'ROLE');

  -- Stop recording and (for PA) generate results into DBA_USED_PRIVS.
  PROCEDURE stop_capture(p_old_role IN VARCHAR2);

  -- Remove the capture / audit policy. PA results are deleted with it.
  PROCEDURE drop_capture(p_old_role IN VARCHAR2);

  -- Record an object you know a user needs (kept across runs).
  PROCEDURE add_manual(p_grantee      IN VARCHAR2,
                       p_object_owner IN VARCHAR2,
                       p_object_name  IN VARCHAR2,
                       p_privilege    IN VARCHAR2 DEFAULT 'SELECT',
                       p_needs_direct IN VARCHAR2 DEFAULT 'N',
                       p_note         IN VARCHAR2 DEFAULT NULL);

  -- Build the reconciliation plan and script. Returns the run_id.
  --   p_grantees          : comma list; NULL = every non-Oracle user holding the role
  --   p_grant_mode        : 'DIRECT' = grant to each user; 'ROLE' = grant to a new
  --                         per-user role named by p_role_pattern ({GRANTEE} replaced).
  --                         Code dependencies are always granted directly.
  --   p_priv_style        : 'SELECT' (same behaviour as before) or 'READ' (no
  --                         SELECT ... FOR UPDATE / LOCK TABLE - tighter)
  --   p_owner_include     : regex; only grant on these schemas (NULL = all)
  --   p_owner_exclude     : regex; never grant on these schemas
  --   p_revoke_direct_any : 'Y' also revokes ANY privileges (that the old role had)
  --                         granted directly to the users
  FUNCTION build_plan(p_old_role          IN VARCHAR2,
                      p_grantees          IN VARCHAR2 DEFAULT NULL,
                      p_grant_mode        IN VARCHAR2 DEFAULT 'DIRECT',
                      p_role_pattern      IN VARCHAR2 DEFAULT '{GRANTEE}_RO',
                      p_priv_style        IN VARCHAR2 DEFAULT 'SELECT',
                      p_owner_include     IN VARCHAR2 DEFAULT NULL,
                      p_owner_exclude     IN VARCHAR2 DEFAULT NULL,
                      p_revoke_direct_any IN VARCHAR2 DEFAULT 'N',
                      p_use_capture       IN VARCHAR2 DEFAULT 'Y',
                      p_use_dependencies  IN VARCHAR2 DEFAULT 'Y') RETURN NUMBER;

  PROCEDURE print_report(p_run_id IN NUMBER);

  -- Print a runnable script (spool it). p_phase NULL = everything.
  PROCEDURE print_script(p_run_id IN NUMBER, p_phase IN VARCHAR2 DEFAULT NULL);

  -- Execute one phase: 'GRANTS', 'REVOKES' or 'ROLLBACK'. Errors are logged
  -- to gr_script and execution continues; re-running retries failed lines.
  PROCEDURE execute_phase(p_run_id IN NUMBER, p_phase IN VARCHAR2);

END grant_recon;
/

--------------------------------------------------------------------------------
-- Package body
--------------------------------------------------------------------------------
CREATE OR REPLACE PACKAGE BODY grant_recon AS

  g_seq NUMBER := 0;

  ------------------------------------------------------------------ helpers --
  PROCEDURE say(p_text IN VARCHAR2) IS
  BEGIN
    DBMS_OUTPUT.PUT_LINE(p_text);
  END;

  FUNCTION norm(p_text IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN UPPER(TRIM(p_text));
  END;

  FUNCTION q(p_name IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN DBMS_ASSERT.ENQUOTE_NAME(p_name, FALSE);
  END;

  FUNCTION in_list(p_val IN VARCHAR2, p_list IN sys.odcivarchar2list) RETURN BOOLEAN IS
  BEGIN
    IF p_val IS NULL OR p_list IS NULL THEN
      RETURN FALSE;
    END IF;
    FOR i IN 1 .. p_list.COUNT LOOP
      IF p_list(i) = p_val THEN
        RETURN TRUE;
      END IF;
    END LOOP;
    RETURN FALSE;
  END;

  PROCEDURE assert_role(p_role IN VARCHAR2) IS
    l_cnt PLS_INTEGER;
  BEGIN
    SELECT COUNT(*) INTO l_cnt FROM dba_roles WHERE role = p_role;
    IF l_cnt = 0 THEN
      RAISE_APPLICATION_ERROR(-20001, 'Role ' || p_role || ' does not exist');
    END IF;
  END;

  FUNCTION capture_name(p_role IN VARCHAR2, p_method IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN SUBSTR('GR_' || CASE p_method WHEN 'AUDIT' THEN 'AUD_' ELSE 'PA_' END
                  || REGEXP_REPLACE(p_role, '[^A-Z0-9_]', '_'), 1, 128);
  END;

  -- The role plus every role nested inside it.
  FUNCTION role_tree(p_role IN VARCHAR2) RETURN sys.odcivarchar2list IS
    l_list sys.odcivarchar2list;
  BEGIN
    SELECT r BULK COLLECT INTO l_list
      FROM (SELECT p_role AS r FROM dual
            UNION
            SELECT granted_role
              FROM dba_role_privs
             START WITH grantee = p_role
           CONNECT BY NOCYCLE PRIOR granted_role = grantee);
    RETURN l_list;
  END;

  -- ANY system privileges held by the role tree. p_mappable_only = only the
  -- ones that translate to an object privilege.
  FUNCTION role_any_privs(p_role IN VARCHAR2, p_mappable_only IN BOOLEAN)
    RETURN sys.odcivarchar2list
  IS
    l_tree sys.odcivarchar2list := role_tree(p_role);
    l_list sys.odcivarchar2list;
    l_map  VARCHAR2(1) := CASE WHEN p_mappable_only THEN 'Y' ELSE 'N' END;
  BEGIN
    SELECT DISTINCT privilege BULK COLLECT INTO l_list
      FROM dba_sys_privs
     WHERE grantee IN (SELECT column_value FROM TABLE(l_tree))
       AND privilege LIKE '% ANY %'
       AND (l_map = 'N' OR privilege IN
             ('SELECT ANY TABLE','READ ANY TABLE','SELECT ANY SEQUENCE',
              'EXECUTE ANY PROCEDURE','EXECUTE ANY TYPE',
              'INSERT ANY TABLE','UPDATE ANY TABLE','DELETE ANY TABLE'));
    RETURN l_list;
  END;

  -- Translate a used privilege into the object privilege to grant.
  FUNCTION map_priv(p_sys_priv IN VARCHAR2, p_obj_priv IN VARCHAR2,
                    p_obj_type IN VARCHAR2, p_style    IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    IF p_sys_priv IS NOT NULL THEN
      RETURN CASE p_sys_priv
               WHEN 'SELECT ANY TABLE'      THEN p_style
               WHEN 'READ ANY TABLE'        THEN 'READ'
               WHEN 'SELECT ANY SEQUENCE'   THEN 'SELECT'
               WHEN 'EXECUTE ANY PROCEDURE' THEN 'EXECUTE'
               WHEN 'EXECUTE ANY TYPE'      THEN 'EXECUTE'
               WHEN 'INSERT ANY TABLE'      THEN 'INSERT'
               WHEN 'UPDATE ANY TABLE'      THEN 'UPDATE'
               WHEN 'DELETE ANY TABLE'      THEN 'DELETE'
               ELSE NULL
             END;
    ELSIF p_obj_priv IS NOT NULL THEN
      IF p_obj_priv = 'SELECT' AND p_obj_type IN ('TABLE','VIEW','MATERIALIZED VIEW') THEN
        RETURN p_style;
      END IF;
      RETURN p_obj_priv;
    END IF;
    RETURN NULL;
  END;

  FUNCTION priv_for_type(p_type IN VARCHAR2, p_style IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN CASE
             WHEN p_type IN ('TABLE','VIEW','MATERIALIZED VIEW')          THEN p_style
             WHEN p_type = 'SEQUENCE'                                     THEN 'SELECT'
             WHEN p_type IN ('PACKAGE','PROCEDURE','FUNCTION','TYPE')     THEN 'EXECUTE'
             ELSE NULL
           END;
  END;

  FUNCTION obj_type(p_owner IN VARCHAR2, p_name IN VARCHAR2) RETURN VARCHAR2 IS
    l_type VARCHAR2(30);
  BEGIN
    SELECT object_type INTO l_type
      FROM (SELECT object_type
              FROM dba_objects
             WHERE owner = p_owner
               AND object_name = p_name
               AND object_type IN ('MATERIALIZED VIEW','TABLE','VIEW','SEQUENCE','PACKAGE',
                                   'PROCEDURE','FUNCTION','TYPE','SYNONYM')
             ORDER BY CASE object_type WHEN 'MATERIALIZED VIEW' THEN 1
                                       WHEN 'TABLE' THEN 2 ELSE 3 END)
     WHERE ROWNUM = 1;
    RETURN l_type;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN RETURN NULL;
  END;

  -- Follow (public or private) synonym chains to the real object.
  PROCEDURE resolve(p_owner IN OUT VARCHAR2, p_name IN OUT VARCHAR2, p_type OUT VARCHAR2) IS
    l_link VARCHAR2(128);
  BEGIN
    FOR i IN 1 .. 10 LOOP
      p_type := obj_type(p_owner, p_name);
      EXIT WHEN p_type IS NULL OR p_type <> 'SYNONYM';
      BEGIN
        SELECT table_owner, table_name, db_link
          INTO p_owner, p_name, l_link
          FROM dba_synonyms
         WHERE owner = p_owner AND synonym_name = p_name;
      EXCEPTION
        WHEN NO_DATA_FOUND THEN p_type := NULL; RETURN;
      END;
      IF l_link IS NOT NULL THEN       -- remote object: out of scope
        p_type := NULL;
        RETURN;
      END IF;
    END LOOP;
    IF p_type = 'SYNONYM' THEN
      p_type := NULL;
    END IF;
  END;

  PROCEDURE add_ev(p_run IN NUMBER, p_grantee IN VARCHAR2, p_owner IN VARCHAR2,
                   p_name IN VARCHAR2, p_type IN VARCHAR2, p_priv IN VARCHAR2,
                   p_source IN VARCHAR2, p_direct IN VARCHAR2 DEFAULT 'N',
                   p_gopt IN VARCHAR2 DEFAULT 'N', p_detail IN VARCHAR2 DEFAULT NULL) IS
  BEGIN
    IF p_priv IS NULL OR p_owner IS NULL OR p_name IS NULL OR p_grantee IS NULL THEN
      RETURN;
    END IF;
    INSERT INTO gr_evidence (run_id, grantee, object_owner, object_name, object_type, privilege,
                             source, needs_direct, needs_grant_opt, detail)
    VALUES (p_run, p_grantee, p_owner, p_name, p_type, p_priv,
            p_source, p_direct, p_gopt, SUBSTR(p_detail, 1, 1000));
  END;

  PROCEDURE add_stmt(p_run IN NUMBER, p_grantee IN VARCHAR2, p_phase IN VARCHAR2, p_stmt IN VARCHAR2) IS
  BEGIN
    g_seq := g_seq + 1;
    INSERT INTO gr_script (run_id, seq, grantee, phase, stmt, status)
    VALUES (p_run, g_seq, p_grantee, p_phase, SUBSTR(p_stmt, 1, 4000),
            CASE WHEN p_stmt LIKE '--%' THEN 'N/A' ELSE 'PENDING' END);
  END;

  PROCEDURE info(p_run IN NUMBER, p_grantee IN VARCHAR2, p_text IN VARCHAR2) IS
  BEGIN
    add_stmt(p_run, p_grantee, 'INFO', '-- ' || p_text);
  END;

  ---------------------------------------------------------------- capture --
  PROCEDURE start_capture(p_old_role IN VARCHAR2,
                          p_method   IN VARCHAR2 DEFAULT 'PA',
                          p_scope    IN VARCHAR2 DEFAULT 'ROLE') IS
    l_role   VARCHAR2(128) := norm(p_old_role);
    l_method VARCHAR2(10)  := norm(p_method);
    l_scope  VARCHAR2(10)  := norm(p_scope);
    l_name   VARCHAR2(128);
    l_exists PLS_INTEGER;
    l_privs  sys.odcivarchar2list;
    l_list   VARCHAR2(4000);
  BEGIN
    assert_role(l_role);
    IF l_method NOT IN ('PA','AUDIT') THEN
      RAISE_APPLICATION_ERROR(-20002, 'p_method must be PA or AUDIT');
    END IF;
    IF l_scope NOT IN ('ROLE','DATABASE') THEN
      RAISE_APPLICATION_ERROR(-20002, 'p_scope must be ROLE or DATABASE');
    END IF;

    l_name := capture_name(l_role, l_method);
    SELECT COUNT(*) INTO l_exists
      FROM gr_capture
     WHERE old_role = l_role AND method = l_method AND status <> 'DROPPED';

    IF l_method = 'PA' THEN
      IF l_exists = 0 THEN
        IF l_scope = 'DATABASE' THEN
          EXECUTE IMMEDIATE
            'BEGIN DBMS_PRIVILEGE_CAPTURE.CREATE_CAPTURE(name => :n, description => :d, '
            || 'type => DBMS_PRIVILEGE_CAPTURE.G_DATABASE); END;'
            USING l_name, 'grant_recon: all privilege use (reconciling ' || l_role || ')';
        ELSE
          EXECUTE IMMEDIATE
            'BEGIN DBMS_PRIVILEGE_CAPTURE.CREATE_CAPTURE(name => :n, description => :d, '
            || 'type => DBMS_PRIVILEGE_CAPTURE.G_ROLE, roles => role_name_list(:r)); END;'
            USING l_name, 'grant_recon: privileges used via ' || l_role, l_role;
        END IF;
      END IF;
      EXECUTE IMMEDIATE 'BEGIN DBMS_PRIVILEGE_CAPTURE.ENABLE_CAPTURE(name => :n); END;'
        USING l_name;
    ELSE
      l_privs := role_any_privs(l_role, TRUE);
      IF l_privs.COUNT = 0 THEN
        RAISE_APPLICATION_ERROR(-20003, l_role || ' has no ANY privileges to audit; '
          || 'it is object-grant based, so use p_method => ''PA''');
      END IF;
      IF l_exists = 0 THEN
        FOR i IN 1 .. l_privs.COUNT LOOP
          l_list := l_list || CASE WHEN i > 1 THEN ', ' END || l_privs(i);
        END LOOP;
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ' || q(l_name) || ' PRIVILEGES ' || l_list;
      END IF;
      EXECUTE IMMEDIATE 'AUDIT POLICY ' || q(l_name) || ' BY USERS WITH GRANTED ROLES ' || q(l_role);
    END IF;

    MERGE INTO gr_capture c
    USING (SELECT l_role AS r, l_method AS m FROM dual) s
       ON (c.old_role = s.r AND c.method = s.m)
     WHEN MATCHED THEN UPDATE
          SET c.capture_name = l_name,
              c.scope        = l_scope,
              c.started_at   = CASE WHEN c.status = 'DROPPED' THEN SYSDATE ELSE c.started_at END,
              c.stopped_at   = NULL,
              c.status       = 'RUNNING'
     WHEN NOT MATCHED THEN
          INSERT (old_role, method, capture_name, scope, started_at, status)
          VALUES (l_role, l_method, l_name, l_scope, SYSDATE, 'RUNNING');
    COMMIT;
    say('Capture ' || l_name || ' (' || l_method || ') running for role ' || l_role || '.');
  END start_capture;

  PROCEDURE stop_capture(p_old_role IN VARCHAR2) IS
    l_role VARCHAR2(128) := norm(p_old_role);
  BEGIN
    FOR c IN (SELECT * FROM gr_capture WHERE old_role = l_role AND status = 'RUNNING') LOOP
      IF c.method = 'PA' THEN
        EXECUTE IMMEDIATE 'BEGIN DBMS_PRIVILEGE_CAPTURE.DISABLE_CAPTURE(name => :n); END;'
          USING c.capture_name;
        EXECUTE IMMEDIATE 'BEGIN DBMS_PRIVILEGE_CAPTURE.GENERATE_RESULT(name => :n); END;'
          USING c.capture_name;
      ELSE
        EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || q(c.capture_name)
                          || ' BY USERS WITH GRANTED ROLES ' || q(l_role);
      END IF;
      UPDATE gr_capture SET status = 'STOPPED', stopped_at = SYSDATE
       WHERE old_role = c.old_role AND method = c.method;
      say('Stopped ' || c.capture_name || '.');
    END LOOP;
    COMMIT;
  END stop_capture;

  PROCEDURE drop_capture(p_old_role IN VARCHAR2) IS
    l_role VARCHAR2(128) := norm(p_old_role);
  BEGIN
    FOR c IN (SELECT * FROM gr_capture WHERE old_role = l_role AND status <> 'DROPPED') LOOP
      IF c.method = 'PA' THEN
        IF c.status = 'RUNNING' THEN
          BEGIN
            EXECUTE IMMEDIATE 'BEGIN DBMS_PRIVILEGE_CAPTURE.DISABLE_CAPTURE(name => :n); END;'
              USING c.capture_name;
          EXCEPTION WHEN OTHERS THEN NULL;
          END;
        END IF;
        EXECUTE IMMEDIATE 'BEGIN DBMS_PRIVILEGE_CAPTURE.DROP_CAPTURE(name => :n); END;'
          USING c.capture_name;
      ELSE
        BEGIN
          EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || q(c.capture_name)
                            || ' BY USERS WITH GRANTED ROLES ' || q(l_role);
        EXCEPTION WHEN OTHERS THEN NULL;
        END;
        EXECUTE IMMEDIATE 'DROP AUDIT POLICY ' || q(c.capture_name);
      END IF;
      UPDATE gr_capture SET status = 'DROPPED', stopped_at = NVL(stopped_at, SYSDATE)
       WHERE old_role = c.old_role AND method = c.method;
      say('Dropped ' || c.capture_name || '.');
    END LOOP;
    COMMIT;
  END drop_capture;

  PROCEDURE add_manual(p_grantee      IN VARCHAR2,
                       p_object_owner IN VARCHAR2,
                       p_object_name  IN VARCHAR2,
                       p_privilege    IN VARCHAR2 DEFAULT 'SELECT',
                       p_needs_direct IN VARCHAR2 DEFAULT 'N',
                       p_note         IN VARCHAR2 DEFAULT NULL) IS
    l_g VARCHAR2(128) := norm(p_grantee);
    l_o VARCHAR2(128) := norm(p_object_owner);
    l_n VARCHAR2(128) := norm(p_object_name);
    l_p VARCHAR2(40)  := norm(p_privilege);
    l_d CHAR(1)       := CASE WHEN norm(p_needs_direct) = 'Y' THEN 'Y' ELSE 'N' END;
  BEGIN
    MERGE INTO gr_manual m
    USING (SELECT l_g g, l_o o, l_n n, l_p p FROM dual) s
       ON (m.grantee = s.g AND m.object_owner = s.o AND m.object_name = s.n AND m.privilege = s.p)
     WHEN MATCHED THEN UPDATE SET m.needs_direct = l_d, m.note = p_note
     WHEN NOT MATCHED THEN INSERT (grantee, object_owner, object_name, privilege, needs_direct, note)
                           VALUES (l_g, l_o, l_n, l_p, l_d, p_note);
    COMMIT;
  END add_manual;

  ------------------------------------------------------------- build_plan --
  FUNCTION build_plan(p_old_role          IN VARCHAR2,
                      p_grantees          IN VARCHAR2 DEFAULT NULL,
                      p_grant_mode        IN VARCHAR2 DEFAULT 'DIRECT',
                      p_role_pattern      IN VARCHAR2 DEFAULT '{GRANTEE}_RO',
                      p_priv_style        IN VARCHAR2 DEFAULT 'SELECT',
                      p_owner_include     IN VARCHAR2 DEFAULT NULL,
                      p_owner_exclude     IN VARCHAR2 DEFAULT NULL,
                      p_revoke_direct_any IN VARCHAR2 DEFAULT 'N',
                      p_use_capture       IN VARCHAR2 DEFAULT 'Y',
                      p_use_dependencies  IN VARCHAR2 DEFAULT 'Y') RETURN NUMBER
  IS
    l_role     VARCHAR2(128) := norm(p_old_role);
    l_mode     VARCHAR2(10)  := norm(p_grant_mode);
    l_style    VARCHAR2(6)   := norm(p_priv_style);
    l_revany   CHAR(1)       := CASE WHEN norm(p_revoke_direct_any) = 'Y' THEN 'Y' ELSE 'N' END;
    l_run      NUMBER;
    l_cnt      PLS_INTEGER;
    l_cnt2     PLS_INTEGER;
    l_tree     sys.odcivarchar2list;
    l_anymap   sys.odcivarchar2list;
    l_anyall   sys.odcivarchar2list;
    l_cur      SYS_REFCURSOR;
    l_captures PLS_INTEGER := 0;
    l_owner    VARCHAR2(128);
    l_name     VARCHAR2(128);
    l_type     VARCHAR2(30);
    l_newrole  VARCHAR2(128);
    l_direct   CHAR(1);
    l_admin    VARCHAR2(3);
    l_via      VARCHAR2(4000);
    l_to       VARCHAR2(128);
    r_user     VARCHAR2(128);
    r_owner    VARCHAR2(128);
    r_name     VARCHAR2(128);
    r_type     VARCHAR2(128);
    r_sys      VARCHAR2(4000);
    r_obj      VARCHAR2(128);
    r_urole    VARCHAR2(128);
  BEGIN
    ---------------------------------------------------------------- validate
    assert_role(l_role);
    IF l_mode NOT IN ('DIRECT','ROLE') THEN
      RAISE_APPLICATION_ERROR(-20004, 'p_grant_mode must be DIRECT or ROLE');
    END IF;
    IF l_style NOT IN ('SELECT','READ') THEN
      RAISE_APPLICATION_ERROR(-20004, 'p_priv_style must be SELECT or READ');
    END IF;

    l_tree   := role_tree(l_role);
    l_anymap := role_any_privs(l_role, TRUE);
    l_anyall := role_any_privs(l_role, FALSE);

    SELECT gr_run_seq.NEXTVAL INTO l_run FROM dual;
    INSERT INTO gr_run (run_id, old_role, grant_mode, role_pattern, priv_style,
                        owner_include, owner_exclude, revoke_direct_any)
    VALUES (l_run, l_role, l_mode, p_role_pattern, l_style,
            p_owner_include, p_owner_exclude, l_revany);
    g_seq := 0;

    info(l_run, NULL, 'grant_recon run ' || l_run || ' for role ' || l_role
                      || ' built ' || TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI') || ' by ' || USER);
    SELECT COUNT(*) INTO l_cnt FROM dba_tab_privs
     WHERE grantee IN (SELECT column_value FROM TABLE(l_tree));
    info(l_run, NULL, l_role || ' (incl. nested roles) carries ' || l_anyall.COUNT
                      || ' ANY system privilege(s) and ' || l_cnt || ' object grant(s)');
    FOR i IN 1 .. l_anyall.COUNT LOOP
      info(l_run, NULL, '   ' || l_anyall(i));
    END LOOP;

    ---------------------------------------------------------------- grantees
    IF p_grantees IS NULL THEN
      INSERT INTO gr_run_grantee (run_id, grantee)
      SELECT DISTINCT l_run, rp.grantee
        FROM (SELECT grantee
                FROM dba_role_privs
               START WITH granted_role = l_role
             CONNECT BY NOCYCLE PRIOR grantee = granted_role) rp
       WHERE EXISTS (SELECT 1 FROM dba_users u
                      WHERE u.username = rp.grantee AND u.oracle_maintained = 'N');
    ELSE
      FOR x IN (SELECT DISTINCT UPPER(TRIM(REGEXP_SUBSTR(p_grantees, '[^,]+', 1, LEVEL))) AS g
                  FROM dual
               CONNECT BY LEVEL <= REGEXP_COUNT(p_grantees, ',') + 1) LOOP
        IF x.g IS NOT NULL THEN
          SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = x.g;
          IF l_cnt = 0 THEN
            info(l_run, x.g, 'WARNING: user ' || x.g || ' not found - skipped');
          ELSE
            INSERT INTO gr_run_grantee (run_id, grantee) VALUES (l_run, x.g);
          END IF;
        END IF;
      END LOOP;
    END IF;

    -- Roles each user keeps once the old role is gone
    FOR g IN (SELECT grantee FROM gr_run_grantee WHERE run_id = l_run) LOOP
      INSERT INTO gr_kept_role (run_id, grantee, role)
      SELECT DISTINCT l_run, g.grantee, granted_role
        FROM dba_role_privs
       START WITH grantee = g.grantee AND granted_role <> l_role
     CONNECT BY NOCYCLE PRIOR granted_role = grantee AND granted_role <> l_role;

      SELECT NVL(MAX('Y'), 'N'), NVL(MAX(admin_option), 'NO')
        INTO l_direct, l_admin
        FROM dba_role_privs
       WHERE grantee = g.grantee AND granted_role = l_role;

      SELECT LISTAGG(k.role, ', ') WITHIN GROUP (ORDER BY k.role)
        INTO l_via
        FROM gr_kept_role k
       WHERE k.run_id = l_run AND k.grantee = g.grantee
         AND EXISTS (SELECT 1 FROM dba_role_privs r
                      WHERE r.grantee = k.role AND r.granted_role = l_role);

      l_newrole := NULL;
      IF l_mode = 'ROLE' THEN
        l_newrole := norm(REPLACE(p_role_pattern, '{GRANTEE}', g.grantee));
        IF LENGTH(l_newrole) > 128 THEN
          RAISE_APPLICATION_ERROR(-20005, 'Role name too long: ' || l_newrole);
        END IF;
        l_newrole := DBMS_ASSERT.SIMPLE_SQL_NAME(l_newrole);
      END IF;

      UPDATE gr_run_grantee
         SET direct_grant = l_direct, admin_option = l_admin,
             via_roles = l_via, new_role = l_newrole
       WHERE run_id = l_run AND grantee = g.grantee;
    END LOOP;

    SELECT COUNT(*) INTO l_cnt FROM gr_run_grantee WHERE run_id = l_run;
    info(l_run, NULL, 'Grantees in scope: ' || l_cnt);

    -------------------------------------------------- evidence: capture/audit
    IF norm(p_use_capture) = 'Y' THEN
      FOR c IN (SELECT capture_name, method, scope, status, started_at, stopped_at
                  FROM gr_capture
                 WHERE old_role = l_role AND status <> 'DROPPED') LOOP
        l_captures := l_captures + 1;
        info(l_run, NULL, 'Evidence: ' || c.method || ' ' || c.capture_name || ' [' || c.status || '] '
             || TO_CHAR(c.started_at, 'YYYY-MM-DD') || ' -> '
             || NVL(TO_CHAR(c.stopped_at, 'YYYY-MM-DD'), 'now') || ' ('
             || ROUND(NVL(c.stopped_at, SYSDATE) - c.started_at, 1) || ' days)');
        BEGIN
          IF c.method = 'PA' THEN
            IF c.status = 'RUNNING' THEN
              info(l_run, NULL, 'WARNING: PA capture still running - results are only as fresh as the '
                   || 'last stop_capture (GENERATE_RESULT). Stop it before trusting this plan.');
            END IF;
            OPEN l_cur FOR
              'SELECT DISTINCT u.username, u.object_owner, u.object_name, u.object_type,'
              || '       u.sys_priv, u.obj_priv, u.used_role'
              || '  FROM dba_used_privs u'
              || ' WHERE u.capture = :cap'
              || '   AND u.object_owner IS NOT NULL AND u.object_name IS NOT NULL'
              || '   AND u.username IN (SELECT g.grantee FROM gr_run_grantee g WHERE g.run_id = :run)'
              USING c.capture_name, l_run;
            LOOP
              FETCH l_cur INTO r_user, r_owner, r_name, r_type, r_sys, r_obj, r_urole;
              EXIT WHEN l_cur%NOTFOUND;
              IF (r_sys IS NOT NULL AND in_list(r_sys, l_anymap))
                 OR (r_sys IS NULL AND r_obj IS NOT NULL
                     AND (c.scope = 'ROLE' OR in_list(r_urole, l_tree))) THEN
                add_ev(l_run, r_user, r_owner, r_name, r_type,
                       map_priv(r_sys, r_obj, r_type, l_style), 'CAPTURE', 'N', 'N',
                       'Used ' || NVL(r_sys, r_obj));
              END IF;
            END LOOP;
            CLOSE l_cur;
          ELSE
            OPEN l_cur FOR
              'SELECT DISTINCT a.dbusername, a.object_schema, a.object_name, a.system_privilege_used'
              || '  FROM unified_audit_trail a'
              || ' WHERE INSTR(a.unified_audit_policies, :pol) > 0'
              || '   AND a.object_schema IS NOT NULL AND a.object_name IS NOT NULL'
              || '   AND a.system_privilege_used IS NOT NULL'
              || '   AND a.dbusername IN (SELECT g.grantee FROM gr_run_grantee g WHERE g.run_id = :run)'
              USING c.capture_name, l_run;
            LOOP
              FETCH l_cur INTO r_user, r_owner, r_name, r_sys;
              EXIT WHEN l_cur%NOTFOUND;
              r_type := obj_type(r_owner, r_name);
              FOR i IN 1 .. l_anymap.COUNT LOOP
                IF INSTR(r_sys, l_anymap(i)) > 0 THEN
                  add_ev(l_run, r_user, r_owner, r_name, r_type,
                         map_priv(l_anymap(i), NULL, r_type, l_style), 'AUDIT', 'N', 'N',
                         'Used ' || l_anymap(i));
                END IF;
              END LOOP;
            END LOOP;
            CLOSE l_cur;
          END IF;
        EXCEPTION
          WHEN OTHERS THEN
            IF l_cur%ISOPEN THEN CLOSE l_cur; END IF;
            info(l_run, NULL, 'WARNING: could not read ' || c.method || ' results: ' || SQLERRM);
        END;
      END LOOP;

      IF l_captures = 0 THEN
        info(l_run, NULL, 'WARNING: no capture exists for ' || l_role || '. This plan only covers code '
             || 'dependencies and manual entries - DO NOT run the REVOKES phase from it.');
      END IF;
    END IF;

    ------------------------------------------------- evidence: dependencies
    IF norm(p_use_dependencies) = 'Y' THEN
      FOR dep IN (
        SELECT d.owner AS grantee, d.name AS dep_name, d.type AS dep_type,
               d.referenced_owner AS ref_owner, d.referenced_name AS ref_name,
               d.referenced_type AS ref_type,
               CASE WHEN d.type IN ('VIEW','MATERIALIZED VIEW')
                         AND EXISTS (SELECT 1 FROM dba_tab_privs tp
                                      WHERE tp.owner = d.owner AND tp.table_name = d.name)
                    THEN 'Y' ELSE 'N' END AS gopt
          FROM dba_dependencies d
         WHERE d.owner IN (SELECT g.grantee FROM gr_run_grantee g WHERE g.run_id = l_run)
           AND d.referenced_link_name IS NULL
           AND d.referenced_type IN ('TABLE','VIEW','MATERIALIZED VIEW','SEQUENCE','PACKAGE',
                                     'PROCEDURE','FUNCTION','TYPE','SYNONYM')
           AND (d.referenced_owner <> d.owner OR d.referenced_type = 'SYNONYM')
           AND (d.referenced_owner <> 'PUBLIC' OR d.referenced_type = 'SYNONYM'))
      LOOP
        l_owner := dep.ref_owner;
        l_name  := dep.ref_name;
        IF dep.ref_type = 'SYNONYM' THEN
          resolve(l_owner, l_name, l_type);
        ELSE
          l_type := dep.ref_type;
        END IF;
        IF l_type IS NOT NULL AND l_owner <> dep.grantee THEN
          add_ev(l_run, dep.grantee, l_owner, l_name, l_type, priv_for_type(l_type, l_style),
                 'DEPENDENCY', 'Y', dep.gopt,
                 'Referenced by ' || dep.dep_type || ' ' || dep.grantee || '.' || dep.dep_name
                 || CASE WHEN dep.gopt = 'Y' THEN ' (view is granted onward)' END);
        END IF;
      END LOOP;
    END IF;

    ------------------------------------------------------- evidence: manual
    FOR m IN (SELECT * FROM gr_manual
               WHERE grantee IN (SELECT grantee FROM gr_run_grantee WHERE run_id = l_run)) LOOP
      add_ev(l_run, m.grantee, m.object_owner, m.object_name,
             obj_type(m.object_owner, m.object_name), m.privilege, 'MANUAL',
             m.needs_direct, 'N', NVL(m.note, 'Manual entry'));
    END LOOP;

    ------------------------------------------------------------- aggregate
    INSERT INTO gr_needed (run_id, grantee, object_owner, object_name, object_type, privilege,
                           needs_direct, needs_grant_opt, from_capture, from_audit,
                           from_dependency, from_manual, evidence_rows, disposition, detail)
    SELECT run_id, grantee, object_owner, object_name, MAX(object_type), privilege,
           MAX(needs_direct), MAX(needs_grant_opt),
           MAX(CASE WHEN source = 'CAPTURE'    THEN 'Y' ELSE 'N' END),
           MAX(CASE WHEN source = 'AUDIT'      THEN 'Y' ELSE 'N' END),
           MAX(CASE WHEN source = 'DEPENDENCY' THEN 'Y' ELSE 'N' END),
           MAX(CASE WHEN source = 'MANUAL'     THEN 'Y' ELSE 'N' END),
           COUNT(*), 'GRANT', MAX(detail)
      FROM gr_evidence
     WHERE run_id = l_run
     GROUP BY run_id, grantee, object_owner, object_name, privilege;

    UPDATE gr_needed SET disposition = 'OWN_OBJECT'
     WHERE run_id = l_run AND disposition = 'GRANT' AND object_owner = grantee;

    UPDATE gr_needed n SET disposition = 'MISSING'
     WHERE n.run_id = l_run AND n.disposition = 'GRANT'
       AND NOT EXISTS (SELECT 1 FROM dba_objects o
                        WHERE o.owner = n.object_owner AND o.object_name = n.object_name);

    UPDATE gr_needed n SET disposition = 'ORACLE_OWNED'
     WHERE n.run_id = l_run AND n.disposition = 'GRANT'
       AND EXISTS (SELECT 1 FROM dba_users u
                    WHERE u.username = n.object_owner AND u.oracle_maintained = 'Y');

    UPDATE gr_needed n SET disposition = 'FILTERED'
     WHERE n.run_id = l_run AND n.disposition = 'GRANT'
       AND ((p_owner_include IS NOT NULL AND NOT REGEXP_LIKE(n.object_owner, p_owner_include))
         OR (p_owner_exclude IS NOT NULL AND REGEXP_LIKE(n.object_owner, p_owner_exclude)));

    UPDATE gr_needed n SET disposition = 'ALREADY_HAS'
     WHERE n.run_id = l_run AND n.disposition = 'GRANT'
       AND EXISTS (
             SELECT 1
               FROM dba_tab_privs p
              WHERE p.owner = n.object_owner
                AND p.table_name = n.object_name
                AND (p.privilege = n.privilege OR (n.privilege = 'READ' AND p.privilege = 'SELECT'))
                AND (n.needs_grant_opt = 'N' OR p.grantable = 'YES')
                AND (   p.grantee = n.grantee
                     OR (p.grantee = 'PUBLIC' AND n.needs_grant_opt = 'N')
                     OR (n.needs_direct = 'N' AND n.needs_grant_opt = 'N'
                         AND p.grantee IN (SELECT k.role FROM gr_kept_role k
                                            WHERE k.run_id = n.run_id AND k.grantee = n.grantee))));

    -- READ is redundant where SELECT is also being granted / already held
    UPDATE gr_needed n SET disposition = 'SUPERSEDED'
     WHERE n.run_id = l_run AND n.privilege = 'READ' AND n.disposition IN ('GRANT','ALREADY_HAS')
       AND EXISTS (SELECT 1 FROM gr_needed s
                    WHERE s.run_id = n.run_id AND s.grantee = n.grantee
                      AND s.object_owner = n.object_owner AND s.object_name = n.object_name
                      AND s.privilege = 'SELECT' AND s.disposition IN ('GRANT','ALREADY_HAS'));

    ---------------------------------------------------------- script lines
    FOR g IN (SELECT * FROM gr_run_grantee WHERE run_id = l_run ORDER BY grantee) LOOP
      info(l_run, g.grantee, '================ ' || g.grantee || ' ================');

      SELECT COUNT(*) INTO l_cnt FROM gr_needed
       WHERE run_id = l_run AND grantee = g.grantee AND disposition IN ('GRANT','ALREADY_HAS');
      IF l_cnt = 0 THEN
        info(l_run, g.grantee, 'WARNING: no usage observed. Either the account is idle or the capture '
             || 'window missed its workload - confirm before revoking.');
      END IF;

      IF g.via_roles IS NOT NULL THEN
        info(l_run, g.grantee, 'WARNING: ' || l_role || ' also reaches ' || g.grantee || ' through: '
             || g.via_roles || '. Revoke ' || l_role || ' from those roles too, or access remains.');
      END IF;

      FOR w IN (SELECT sp.privilege, sp.grantee
                  FROM dba_sys_privs sp
                 WHERE sp.privilege IN (SELECT column_value FROM TABLE(l_anyall))
                   AND (   sp.grantee = 'PUBLIC'
                        OR (sp.grantee = g.grantee AND l_revany = 'N')
                        OR sp.grantee IN (SELECT k.role FROM gr_kept_role k
                                           WHERE k.run_id = l_run AND k.grantee = g.grantee))) LOOP
        info(l_run, g.grantee, 'WARNING: ' || g.grantee || ' will still hold ' || w.privilege
             || CASE WHEN w.grantee = g.grantee
                     THEN ' (granted directly - rebuild with p_revoke_direct_any => ''Y'')'
                     ELSE ' via ' || w.grantee END);
      END LOOP;

      -- ROLE mode scaffolding
      IF l_mode = 'ROLE' THEN
        SELECT COUNT(*) INTO l_cnt FROM gr_needed
         WHERE run_id = l_run AND grantee = g.grantee AND disposition = 'GRANT' AND needs_direct = 'N';
        IF l_cnt > 0 THEN
          SELECT COUNT(*) INTO l_cnt2 FROM dba_roles WHERE role = g.new_role;
          IF l_cnt2 = 0 THEN
            add_stmt(l_run, g.grantee, 'GRANTS', 'CREATE ROLE ' || q(g.new_role));
          END IF;
          SELECT COUNT(*) INTO l_cnt2 FROM dba_role_privs
           WHERE grantee = g.grantee AND granted_role = g.new_role;
          IF l_cnt2 = 0 THEN
            add_stmt(l_run, g.grantee, 'GRANTS', 'GRANT ' || q(g.new_role) || ' TO ' || q(g.grantee));
          END IF;
          SELECT COUNT(*) INTO l_cnt2 FROM dba_role_privs
           WHERE grantee = g.grantee AND default_role = 'NO';
          IF l_cnt2 > 0 THEN
            info(l_run, g.grantee, 'NOTE: ' || g.grantee || ' has non-default roles, so it may use an '
                 || 'explicit DEFAULT ROLE list. Check DBA_ROLE_PRIVS.DEFAULT_ROLE for '
                 || g.new_role || ' after granting.');
          END IF;
        END IF;
      END IF;

      -- Object grants
      FOR n IN (SELECT * FROM gr_needed
                 WHERE run_id = l_run AND grantee = g.grantee AND disposition = 'GRANT'
                 ORDER BY object_owner, object_name, privilege) LOOP
        l_to := CASE WHEN l_mode = 'ROLE' AND n.needs_direct = 'N' THEN g.new_role ELSE g.grantee END;
        add_stmt(l_run, g.grantee, 'GRANTS',
                 'GRANT ' || n.privilege || ' ON ' || q(n.object_owner) || '.' || q(n.object_name)
                 || ' TO ' || q(l_to)
                 || CASE WHEN n.needs_grant_opt = 'Y' THEN ' WITH GRANT OPTION' END);
      END LOOP;

      -- Revokes + rollback
      IF g.direct_grant = 'Y' THEN
        add_stmt(l_run, g.grantee, 'REVOKES', 'REVOKE ' || q(l_role) || ' FROM ' || q(g.grantee));
        add_stmt(l_run, g.grantee, 'ROLLBACK', 'GRANT ' || q(l_role) || ' TO ' || q(g.grantee)
                 || CASE WHEN g.admin_option = 'YES' THEN ' WITH ADMIN OPTION' END);
      END IF;

      IF l_revany = 'Y' THEN
        FOR s IN (SELECT privilege, admin_option FROM dba_sys_privs
                   WHERE grantee = g.grantee
                     AND privilege IN (SELECT column_value FROM TABLE(l_anyall))) LOOP
          add_stmt(l_run, g.grantee, 'REVOKES', 'REVOKE ' || s.privilege || ' FROM ' || q(g.grantee));
          add_stmt(l_run, g.grantee, 'ROLLBACK', 'GRANT ' || s.privilege || ' TO ' || q(g.grantee)
                   || CASE WHEN s.admin_option = 'YES' THEN ' WITH ADMIN OPTION' END);
        END LOOP;
      END IF;
    END LOOP;

    info(l_run, NULL, 'ROLLBACK only restores the old role/privileges; the new grants are additive and can stay.');
    info(l_run, NULL, 'Once every holder is migrated, finish with: DROP ROLE ' || q(l_role)
         || '  (or REVOKE its ANY privileges).');
    IF l_mode = 'ROLE' THEN
      info(l_run, NULL, 'CREATE ROLE also grants the new role to ' || USER
           || ' WITH ADMIN OPTION; revoke it from ' || USER || ' afterwards if your policy requires.');
    END IF;

    COMMIT;
    print_report(l_run);
    RETURN l_run;
  END build_plan;

  ------------------------------------------------------------- reporting --
  PROCEDURE print_report(p_run_id IN NUMBER) IS
    l_note VARCHAR2(400);
  BEGIN
    FOR r IN (SELECT * FROM gr_run WHERE run_id = p_run_id) LOOP
      say('Run ' || r.run_id || ' - role ' || r.old_role || ', mode ' || r.grant_mode
          || ', privilege style ' || r.priv_style || ', built ' || TO_CHAR(r.created_at, 'YYYY-MM-DD HH24:MI'));
    END LOOP;
    say(RPAD('GRANTEE', 30) || LPAD('TO GRANT', 10) || LPAD('ALREADY', 10)
        || LPAD('SKIPPED', 10) || LPAD('SCHEMAS', 10) || '  NOTES');
    say(RPAD('-', 100, '-'));
    FOR r IN (SELECT g.grantee, g.direct_grant, g.via_roles,
                     SUM(CASE WHEN n.disposition = 'GRANT' THEN 1 ELSE 0 END) AS to_grant,
                     SUM(CASE WHEN n.disposition = 'ALREADY_HAS' THEN 1 ELSE 0 END) AS has,
                     SUM(CASE WHEN n.disposition NOT IN ('GRANT','ALREADY_HAS') THEN 1 ELSE 0 END) AS skipped,
                     COUNT(DISTINCT CASE WHEN n.disposition = 'GRANT' THEN n.object_owner END) AS schemas
                FROM gr_run_grantee g
                LEFT JOIN gr_needed n ON n.run_id = g.run_id AND n.grantee = g.grantee
               WHERE g.run_id = p_run_id
               GROUP BY g.grantee, g.direct_grant, g.via_roles
               ORDER BY g.grantee) LOOP
      l_note := NULL;
      IF r.to_grant + r.has = 0 THEN
        l_note := 'NO USAGE SEEN; ';
      END IF;
      IF r.via_roles IS NOT NULL THEN
        l_note := l_note || 'also via ' || r.via_roles || '; ';
      END IF;
      IF r.direct_grant = 'N' THEN
        l_note := l_note || 'role not granted directly; ';
      END IF;
      say(RPAD(r.grantee, 30) || LPAD(r.to_grant, 10) || LPAD(r.has, 10)
          || LPAD(r.skipped, 10) || LPAD(r.schemas, 10) || '  ' || RTRIM(l_note, '; '));
    END LOOP;
    say('Details:  SELECT * FROM gr_needed WHERE run_id = ' || p_run_id || ';');
    say('Script:   EXEC grant_recon.print_script(' || p_run_id || ');');
  END print_report;

  PROCEDURE print_script(p_run_id IN NUMBER, p_phase IN VARCHAR2 DEFAULT NULL) IS
    l_phase VARCHAR2(10) := norm(p_phase);
    l_last  VARCHAR2(10) := '#';
  BEGIN
    FOR s IN (SELECT phase, stmt, status
                FROM gr_script
               WHERE run_id = p_run_id
                 AND (l_phase IS NULL OR phase = l_phase)
               ORDER BY DECODE(phase, 'INFO', 1, 'GRANTS', 2, 'REVOKES', 3, 'ROLLBACK', 4), seq) LOOP
      IF s.phase <> l_last THEN
        say(NULL);
        say('-- ' || RPAD('=', 70, '='));
        say('-- ' || CASE s.phase
                       WHEN 'INFO'     THEN 'NOTES AND WARNINGS'
                       WHEN 'GRANTS'   THEN 'PHASE 1: GRANTS (additive - run first, then test)'
                       WHEN 'REVOKES'  THEN 'PHASE 2: REVOKES (cut-over)'
                       WHEN 'ROLLBACK' THEN 'ROLLBACK (only if phase 2 breaks something)'
                     END);
        say('-- ' || RPAD('=', 70, '='));
        l_last := s.phase;
      END IF;
      IF s.phase = 'INFO' THEN
        say(s.stmt);
      ELSE
        say(s.stmt || ';' || CASE WHEN s.status <> 'PENDING' THEN '   -- ' || s.status END);
      END IF;
    END LOOP;
  END print_script;

  ------------------------------------------------------------- execution --
  PROCEDURE execute_phase(p_run_id IN NUMBER, p_phase IN VARCHAR2) IS
    l_phase VARCHAR2(10) := norm(p_phase);
    l_ok    PLS_INTEGER := 0;
    l_err   PLS_INTEGER := 0;
    l_cnt   PLS_INTEGER;
    l_msg   VARCHAR2(4000);
  BEGIN
    IF l_phase NOT IN ('GRANTS','REVOKES','ROLLBACK') THEN
      RAISE_APPLICATION_ERROR(-20006, 'p_phase must be GRANTS, REVOKES or ROLLBACK');
    END IF;

    IF l_phase = 'REVOKES' THEN
      SELECT COUNT(*) INTO l_cnt FROM gr_script
       WHERE run_id = p_run_id AND phase = 'GRANTS' AND status <> 'DONE';
      IF l_cnt > 0 THEN
        RAISE_APPLICATION_ERROR(-20007, l_cnt || ' GRANTS statement(s) not DONE for run ' || p_run_id
          || '. Fix them (see gr_script.error_msg) before revoking.');
      END IF;
    END IF;

    FOR s IN (SELECT seq, stmt FROM gr_script
               WHERE run_id = p_run_id AND phase = l_phase AND status IN ('PENDING','ERROR')
               ORDER BY seq) LOOP
      BEGIN
        EXECUTE IMMEDIATE s.stmt;
        UPDATE gr_script SET status = 'DONE', error_msg = NULL, executed_at = SYSDATE
         WHERE run_id = p_run_id AND seq = s.seq;
        l_ok := l_ok + 1;
      EXCEPTION
        WHEN OTHERS THEN
          l_msg := SQLERRM;
          UPDATE gr_script SET status = 'ERROR', error_msg = l_msg, executed_at = SYSDATE
           WHERE run_id = p_run_id AND seq = s.seq;
          l_err := l_err + 1;
          say('ERROR: ' || s.stmt || ' -> ' || l_msg);
      END;
      COMMIT;
    END LOOP;
    say(l_phase || ' for run ' || p_run_id || ': ' || l_ok || ' succeeded, ' || l_err || ' failed.');
  END execute_phase;

END grant_recon;
/

SHOW ERRORS PACKAGE BODY grant_recon

--------------------------------------------------------------------------------
-- Uninstall (uncomment to remove):
-- DROP PACKAGE grant_recon;
-- DROP TABLE gr_script PURGE;   DROP TABLE gr_manual PURGE;  DROP TABLE gr_needed PURGE;
-- DROP TABLE gr_evidence PURGE; DROP TABLE gr_kept_role PURGE;
-- DROP TABLE gr_run_grantee PURGE; DROP TABLE gr_run PURGE; DROP TABLE gr_capture PURGE;
-- DROP SEQUENCE gr_run_seq;
--------------------------------------------------------------------------------
