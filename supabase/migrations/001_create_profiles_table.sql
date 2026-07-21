-- Already applied to the live project during Sprint 2 (via the Supabase MCP
-- connector's apply_migration). Kept here so the schema is reproducible —
-- e.g. for a fresh Supabase project, or a second developer's environment —
-- without having to reverse-engineer it from supabase_auth.py's docstring.

create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  is_premium boolean not null default false,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, is_premium) values (new.id, false);
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;

drop policy if exists "Users can read their own profile" on public.profiles;
create policy "Users can read their own profile"
  on public.profiles for select using (auth.uid() = id);
