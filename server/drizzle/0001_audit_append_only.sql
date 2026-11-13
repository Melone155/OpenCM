-- The audit log is append-only: any UPDATE, DELETE or TRUNCATE is rejected.
-- Retention/archiving (later milestone) must run as a dedicated DB role that
-- disables this trigger explicitly and is itself audited.
CREATE OR REPLACE FUNCTION audit_log_reject_change() RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER audit_log_no_update_delete
	BEFORE UPDATE OR DELETE ON "audit_log"
	FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change();
--> statement-breakpoint
CREATE TRIGGER audit_log_no_truncate
	BEFORE TRUNCATE ON "audit_log"
	FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change();
