-- Adds Stripe linkage to profiles, needed for Sprint 3 billing:
--   stripe_customer_id     -- lets us open the Stripe customer portal for this user
--   stripe_subscription_id -- lets the webhook know which subscription to watch
--
-- Apply with the Supabase MCP connector (apply_migration) or paste into the
-- Supabase SQL editor if working without the connector.

alter table public.profiles
  add column if not exists stripe_customer_id text,
  add column if not exists stripe_subscription_id text;

create unique index if not exists profiles_stripe_customer_id_idx
  on public.profiles (stripe_customer_id)
  where stripe_customer_id is not null;
