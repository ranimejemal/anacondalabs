-- Already applied to the live project via the Supabase MCP connector.
-- Fixes two real findings from Supabase's own security advisor/linter:
--
-- 1. function_search_path_mutable: handle_new_user() had no pinned
--    search_path, which is a real privilege-escalation vector for a
--    SECURITY DEFINER function (a caller could manipulate search_path to
--    make the function resolve objects from an unexpected schema).
--
-- 2. anon_security_definer_function_executable /
--    authenticated_security_definer_function_executable: the function was
--    directly callable by anyone via POST /rest/v1/rpc/handle_new_user,
--    when it should only ever run automatically via the auth.users insert
--    trigger. Triggers invoke the function directly regardless of EXECUTE
--    grants, so revoking public/anon/authenticated EXECUTE doesn't break
--    the signup flow — it only blocks calling it directly as an RPC.

alter function public.handle_new_user() set search_path = public, pg_temp;

revoke execute on function public.handle_new_user() from public, anon, authenticated;
