-- CwhubUZ v22: shikoyatlar (report) va haftalik zaxira nusxa (bot uchun)

-- ---------------------------------------------------------------- shikoyatlar
create table if not exists public.reports (
  id           bigserial primary key,
  reporter     uuid not null default auth.uid() references auth.users on delete cascade,
  target_steam text not null check (target_steam ~* '^STEAM_[0-5]:[01]:[0-9]+$'),
  target_name  text check (target_name is null or length(target_name) <= 40),
  match_t      bigint,
  reason       text not null check (reason in ('cheat', 'toxic', 'grief', 'nick', 'other')),
  body         text check (body is null or length(body) <= 500),
  status       text not null default 'open' check (status in ('open', 'done', 'rejected')),
  admin_note   text check (admin_note is null or length(admin_note) <= 300),
  handled_by   uuid,
  handled_at   timestamptz,
  notified     boolean not null default false,
  created_at   timestamptz not null default now()
);
create index if not exists reports_status on public.reports (status, id desc);
alter table public.reports enable row level security;
drop policy if exists "reports create" on public.reports;
create policy "reports create" on public.reports for insert to authenticated with check (reporter = auth.uid() and status = 'open');
drop policy if exists "reports read" on public.reports;
create policy "reports read" on public.reports for select using (reporter = auth.uid() or public.is_site_admin());
drop policy if exists "reports admin" on public.reports;
create policy "reports admin" on public.reports for update using (public.is_site_admin()) with check (public.is_site_admin());
revoke all on public.reports from anon, authenticated;
grant select on public.reports to authenticated;
grant insert (target_steam, target_name, match_t, reason, body) on public.reports to authenticated;
grant update (status, admin_note) on public.reports to authenticated;
grant usage on sequence public.reports_id_seq to authenticated;

-- yozishdan oldin: bloklangan emasmi, o'ziga emas, soatiga 5 tadan ko'p emas, bir odamga soatiga 1 ta
create or replace function public.report_before_insert() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if public.is_blocked(auth.uid()) then raise exception 'blocked'; end if;
  new.reporter := auth.uid(); new.status := 'open'; new.created_at := now(); new.notified := false;
  new.target_steam := upper(new.target_steam);
  if exists (select 1 from accounts where user_id = auth.uid() and upper(steam) = new.target_steam) then
    raise exception 'self';
  end if;
  if (select count(*) from reports where reporter = auth.uid() and created_at > now() - interval '1 hour') >= 5 then
    raise exception 'rate';
  end if;
  if exists (select 1 from reports where reporter = auth.uid() and target_steam = new.target_steam and created_at > now() - interval '1 hour') then
    raise exception 'dup';
  end if;
  new.body := nullif(left(trim(coalesce(new.body, '')), 500), '');
  new.target_name := left(coalesce(new.target_name, ''), 40);
  return new;
end; $$;
drop trigger if exists report_before_insert on public.reports;
create trigger report_before_insert before insert on public.reports for each row execute function public.report_before_insert();

-- admin hal qilganda: kim/qachon yoziladi, shikoyatchiga xabar boradi
create or replace function public.report_after_decide() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.status <> old.status and new.status in ('done', 'rejected') then
    new.handled_by := auth.uid(); new.handled_at := now();
    insert into user_alerts (user_id, kind, body) values (new.reporter, 'info',
      case when new.status = 'done' then 'Shikoyatingiz ko''rib chiqildi va chora ko''rildi: ' || coalesce(nullif(new.target_name, ''), new.target_steam) || '. Rahmat!'
           else 'Shikoyatingiz ko''rib chiqildi: ' || coalesce(nullif(new.target_name, ''), new.target_steam) || ' — qoidabuzarlik topilmadi.' end
      || coalesce(' Izoh: ' || nullif(new.admin_note, ''), ''));
  end if;
  return new;
end; $$;
drop trigger if exists report_after_decide on public.reports;
create trigger report_after_decide before update on public.reports for each row execute function public.report_after_decide();
revoke execute on function public.report_before_insert() from public, anon, authenticated;
revoke execute on function public.report_after_decide() from public, anon, authenticated;

-- admin ro'yxati: shikoyatchi niki bilan
create or replace function public.admin_reports(p_status text)
returns table (id bigint, target_steam text, target_name text, match_t bigint, reason text, body text, status text, admin_note text,
               created_at timestamptz, reporter_nick text, reporter_email text, same_target int)
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.is_site_admin() then raise exception 'forbidden'; end if;
  return query
    select r.id, r.target_steam, r.target_name, r.match_t, r.reason, r.body, r.status, r.admin_note, r.created_at,
           coalesce(a.site_nick, a.nick), a.email,
           (select count(*)::int from reports q where q.target_steam = r.target_steam and q.created_at > now() - interval '30 days')
      from reports r left join accounts a on a.user_id = r.reporter
     where coalesce(p_status, '') = '' or r.status = p_status
     order by (r.status = 'open') desc, r.id desc
     limit 100;
end; $$;
revoke execute on function public.admin_reports(text) from public, anon;
grant execute on function public.admin_reports(text) to authenticated;

-- bot: yangi shikoyatlar Telegram'ga
create or replace function public.bot_take_reports(p_secret text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare res json;
begin
  if not exists (select 1 from server_secrets where name = 'link' and hash = encode(digest(coalesce(p_secret, ''), 'sha256'), 'hex')) then
    return json_build_object('ok', false, 'err', 'auth');
  end if;
  with t as (
    update reports set notified = true where id in (select id from reports where not notified order by id limit 10)
    returning id, reporter, target_steam, target_name, match_t, reason, body, created_at)
  select coalesce(json_agg(json_build_object('id', t.id, 'target_steam', t.target_steam, 'target_name', t.target_name, 'match_t', t.match_t,
           'reason', t.reason, 'body', t.body, 'reporter', coalesce(a.site_nick, a.nick)) order by t.id), '[]'::json)
    into res from t left join accounts a on a.user_id = t.reporter;
  return res;
end; $$;
revoke execute on function public.bot_take_reports(text) from public;
grant execute on function public.bot_take_reports(text) to anon, authenticated;

-- ---------------------------------------------------------------- haftalik zaxira (bot kompyuterga saqlaydi)
create or replace function public.bot_backup(p_secret text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare res json;
begin
  if not exists (select 1 from server_secrets where name = 'link' and hash = encode(digest(coalesce(p_secret, ''), 'sha256'), 'hex')) then
    return json_build_object('ok', false, 'err', 'auth');
  end if;
  select json_build_object(
    'ok', true, 'at', now(),
    'accounts',        (select coalesce(json_agg(t), '[]') from accounts t),
    'site_admins',     (select coalesce(json_agg(t), '[]') from site_admins t),
    'settings',        (select coalesce(json_agg(t), '[]') from settings t),
    'premium_orders',  (select coalesce(json_agg(t), '[]') from premium_orders t),
    'promo_codes',     (select coalesce(json_agg(t), '[]') from promo_codes t),
    'friendships',     (select coalesce(json_agg(t), '[]') from friendships t),
    'tickets',         (select coalesce(json_agg(t), '[]') from tickets t),
    'ticket_messages', (select coalesce(json_agg(t), '[]') from ticket_messages t),
    'chat_messages',   (select coalesce(json_agg(t), '[]') from (select * from chat_messages order by id desc limit 5000) t),
    'direct_messages', (select coalesce(json_agg(t), '[]') from direct_messages t),
    'chat_mutes',      (select coalesce(json_agg(t), '[]') from chat_mutes t),
    'user_alerts',     (select coalesce(json_agg(t), '[]') from user_alerts t),
    'reports',         (select coalesce(json_agg(t), '[]') from reports t),
    'match_demos',     (select coalesce(json_agg(t), '[]') from match_demos t),
    'cw_feed',         (select coalesce(json_agg(t), '[]') from cw_feed t),
    'site_data',       (select coalesce(json_agg(t), '[]') from site_data t)
  ) into res;
  return res;
end; $$;
revoke execute on function public.bot_backup(text) from public;
grant execute on function public.bot_backup(text) to anon, authenticated;

-- bloklangan foydalanuvchi shikoyat ham yubora olmaydi (block_guard ro'yxatiga)
drop trigger if exists zz_block_guard on public.reports;
create trigger zz_block_guard before insert on public.reports for each row execute function public.block_guard();
notify pgrst, 'reload schema';
