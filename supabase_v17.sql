-- CwhubUZ v17: admin panel — foydalanuvchilar: bloklash va ogohlantirish/xabar yuborish.

alter table public.accounts add column if not exists blocked_until timestamptz;   -- null = bloklanmagan, 'infinity' = abadiy
alter table public.accounts add column if not exists block_reason text;

create or replace function public.is_blocked(p_uid uuid default auth.uid())
returns boolean language sql security definer stable set search_path = public
as $$ select exists (select 1 from public.accounts where user_id = p_uid and blocked_until > now()) $$;
grant execute on function public.is_blocked(uuid) to anon, authenticated;

-- bloklangan foydalanuvchi yoza olmaydi: chat, DM, support, do'stlik, buyurtma
create or replace function public.block_guard() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if public.is_blocked(auth.uid()) and not public.is_site_admin() then
    raise exception 'blocked';
  end if;
  return new;
end; $$;
do $$ declare t text; begin
  foreach t in array array['chat_messages', 'direct_messages', 'tickets', 'ticket_messages', 'friendships', 'premium_orders'] loop
    execute format('drop trigger if exists zz_block_guard on public.%I', t);
    execute format('create trigger zz_block_guard before insert on public.%I for each row execute function public.block_guard()', t);
  end loop;
end $$;

-- admin -> foydalanuvchi xabarlari (ogohlantirish / ma'lumot / blok haqida)
create table if not exists public.user_alerts (
  id         bigserial primary key,
  user_id    uuid not null references auth.users on delete cascade,
  kind       text not null default 'info' check (kind in ('info', 'warn', 'block')),
  body       text not null check (length(trim(body)) between 1 and 500),
  by_admin   uuid default auth.uid(),
  read       boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists user_alerts_user on public.user_alerts (user_id, created_at desc);
alter table public.user_alerts enable row level security;
drop policy if exists "alerts read" on public.user_alerts;
create policy "alerts read" on public.user_alerts for select using (user_id = auth.uid() or public.is_site_admin());
drop policy if exists "alerts mark" on public.user_alerts;
create policy "alerts mark" on public.user_alerts for update using (user_id = auth.uid()) with check (user_id = auth.uid());
revoke insert, update, delete on public.user_alerts from anon, authenticated;
grant select on public.user_alerts to authenticated;
grant update (read) on public.user_alerts to authenticated;

-- admin: foydalanuvchilar ro'yxati (karta uchun to'liq ma'lumot)
create or replace function public.admin_users_list(p_q text)
returns table (user_id uuid, email text, nick text, steam text, avatar_url text, premium_until timestamptz,
               blocked_until timestamptz, block_reason text, is_admin boolean, warns int, created_at timestamptz, last_sign_in_at timestamptz)
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.is_site_admin() then raise exception 'forbidden'; end if;
  return query
    select u.id, u.email::text, coalesce(a.site_nick, a.nick), a.steam, a.avatar_url, a.premium_until,
           a.blocked_until, a.block_reason, (s.user_id is not null),
           (select count(*)::int from user_alerts w where w.user_id = u.id and w.kind = 'warn'),
           u.created_at, u.last_sign_in_at
      from auth.users u
      left join accounts a on a.user_id = u.id
      left join site_admins s on s.user_id = u.id
     where coalesce(p_q, '') = '' or u.email ilike '%' || p_q || '%' or coalesce(a.site_nick, a.nick, '') ilike '%' || p_q || '%' or coalesce(a.steam, '') ilike '%' || p_q || '%'
     order by (a.blocked_until > now()) desc nulls last, u.created_at desc
     limit 120;
end; $$;
grant execute on function public.admin_users_list(text) to authenticated;

-- admin: bloklash. p_days: 0 = blokdan chiqarish, -1 = abadiy
create or replace function public.admin_block_user(p_user uuid, p_days int, p_reason text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_until timestamptz; v_reason text := nullif(left(trim(coalesce(p_reason, '')), 200), '');
begin
  if not public.is_site_admin() then return jsonb_build_object('ok', false, 'err', 'forbidden'); end if;
  if exists (select 1 from site_admins where user_id = p_user) then return jsonb_build_object('ok', false, 'err', 'admin'); end if;
  v_until := case when p_days = 0 then null when p_days < 0 then 'infinity'::timestamptz else now() + make_interval(days => least(p_days, 3650)) end;
  update accounts set blocked_until = v_until, block_reason = case when p_days = 0 then null else v_reason end where user_id = p_user;
  if not found then return jsonb_build_object('ok', false, 'err', 'noacc'); end if;
  insert into user_alerts (user_id, kind, body) values (p_user, case when p_days = 0 then 'info' else 'block' end,
    case when p_days = 0 then 'Akkauntingiz blokdan chiqarildi.'
         else 'Akkauntingiz bloklandi' || case when p_days < 0 then ' (abadiy)' else ' (' || p_days || ' kun)' end || coalesce('. Sabab: ' || v_reason, '') end);
  return jsonb_build_object('ok', true, 'until', v_until);
end; $$;
grant execute on function public.admin_block_user(uuid, int, text) to authenticated;

-- admin: ogohlantirish yoki oddiy xabar yuborish
create or replace function public.admin_send_alert(p_user uuid, p_kind text, p_body text)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if not public.is_site_admin() then return jsonb_build_object('ok', false, 'err', 'forbidden'); end if;
  if p_kind not in ('info', 'warn') or length(trim(coalesce(p_body, ''))) < 1 then return jsonb_build_object('ok', false, 'err', 'bad'); end if;
  insert into user_alerts (user_id, kind, body) values (p_user, p_kind, left(trim(p_body), 500));
  return jsonb_build_object('ok', true);
end; $$;
grant execute on function public.admin_send_alert(uuid, text, text) to authenticated;
