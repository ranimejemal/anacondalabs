-- Already applied to the live project via the Supabase MCP connector.
-- Fixes a real finding from Supabase's own performance advisor/linter:
-- auth_rls_initplan — the RLS policy called auth.uid() directly, which
-- Postgres re-evaluates per row instead of once per query. Wrapping it in
-- a subselect, (select auth.uid()), lets the planner treat it as a stable
-- InitPlan evaluated once. Immaterial at today's row count, but correct
-- and free to fix now rather than carry the anti-pattern forward.

drop policy if exists "Users can read their own profile" on public.profiles;
create policy "Users can read their own profile"
  on public.profiles for select using ((select auth.uid()) = id);
