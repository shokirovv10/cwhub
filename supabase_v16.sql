-- v16: yopiq cheklar, sayt statistikasi, promo-kodlar, Premium 3/6 oy va nik rangi

-- ---------------------------------------------------------------- 1) cheklar — yopiq bucket
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('receipts', 'receipts', false, 5242880, array['image/png', 'image/jpeg', 'image/webp'])
on conflict (id) do update set public = false, file_size_limit = 5242880, allowed_mime_types = array['image/png', 'image/jpeg', 'image/webp'];

drop policy if exists "receipts own upload" on storage.objects;
create policy "receipts own upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "receipts own or admin read" on storage.objects;
create policy "receipts own or admin read" on storage.objects for select to authenticated
  using (bucket_id = 'receipts' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_site_admin()));

-- ---------------------------------------------------------------- 2) tashriflar (IP yo'q: brauzerdagi tasodifiy id)
create table if not exists public.site_visits (
  day     date not null default (now() at time zone 'Asia/Tashkent')::date,
  visitor text not null check (char_length(visitor) between 8 and 64),
  primary key (day, visitor)
);
alter table public.site_visits enable row level security;   -- to'g'ridan-to'g'ri o'qib bo'lmaydi

create or replace function public.log_visit(p_vid text)
returns void language sql security definer set search_path = public as $$
  insert into site_visits (visitor) select left(p_vid, 64) where char_length(coalesce(p_vid, '')) >= 8
  on conflict do nothing $$;
grant execute on function public.log_visit(text) to anon, authenticated;

-- admin: oxirgi N kun — tashrif, ro'yxatdan o'tish, sotuv
create or replace function public.admin_stats(p_days int default 30)
returns json language plpgsql security definer stable set search_path = public as $$
declare d0 date := (now() at time zone 'Asia/Tashkent')::date - greatest(1, least(p_days, 365)) + 1;
begin
  if not public.is_site_admin() then return json_build_object('ok', false); end if;
  return json_build_object('ok', true,
    'days', (select json_agg(json_build_object(
        'd', g.d,
        'v', (select count(*) from site_visits v where v.day = g.d),
        'r', (select count(*) from auth.users u where (u.created_at at time zone 'Asia/Tashkent')::date = g.d),
        's', (select coalesce(sum(amount), 0) from premium_orders o where o.status = 'approved' and (o.decided_at at time zone 'Asia/Tashkent')::date = g.d),
        'n', (select count(*) from premium_orders o where o.status = 'approved' and (o.decided_at at time zone 'Asia/Tashkent')::date = g.d)) order by g.d)
      from generate_series(d0, (now() at time zone 'Asia/Tashkent')::date, interval '1 day') as g(d)),
    'users', (select count(*) from auth.users),
    'linked', (select count(*) from accounts where steam is not null),
    'premium', (select count(*) from accounts where premium_until > now()),
    'kinds', (select coalesce(json_object_agg(kind, c), '{}'::json) from (select kind, count(*) c from premium_orders where status = 'approved' and decided_at >= d0 group by kind) k));
end; $$;
revoke all on function public.admin_stats(int) from public, anon;
grant execute on function public.admin_stats(int) to authenticated;

-- ---------------------------------------------------------------- 3) yangi mahsulotlar: Premium 3/6 oy, nik rangi
alter table public.accounts add column if not exists color_paid boolean not null default false;
alter table public.accounts add column if not exists nick_color text;
alter table public.premium_orders add column if not exists promo text;
alter table public.premium_orders add column if not exists color text;
alter table public.premium_orders drop constraint if exists premium_orders_kind_check;
alter table public.premium_orders add constraint premium_orders_kind_check check (kind in ('site', 'site3', 'site6', 'prefix', 'color'));

-- ---------------------------------------------------------------- 4) promo-kodlar
create table if not exists public.promo_codes (
  code       text primary key check (code ~ '^[A-Z0-9_-]{3,24}$'),
  percent    int  not null check (percent between 1 and 90),
  uses_left  int,                                   -- null = cheksiz
  expires    date,                                  -- null = muddatsiz
  active     boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.promo_codes enable row level security;   -- faqat RPC orqali

create or replace function public.check_promo(p_code text)
returns json language sql security definer stable set search_path = public as $$
  select coalesce((select json_build_object('ok', true, 'percent', percent) from promo_codes
     where code = upper(trim(coalesce(p_code, ''))) and active and (uses_left is null or uses_left > 0)
       and (expires is null or expires >= (now() at time zone 'Asia/Tashkent')::date)),
    json_build_object('ok', false)) $$;
grant execute on function public.check_promo(text) to anon, authenticated;

create or replace function public.admin_promo_list()
returns setof promo_codes language sql security definer stable set search_path = public as $$
  select * from promo_codes where public.is_site_admin() order by created_at desc $$;
grant execute on function public.admin_promo_list() to authenticated;

create or replace function public.admin_promo_save(p_code text, p_percent int, p_uses int, p_expires date, p_active boolean)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not public.is_site_admin() then return json_build_object('ok', false, 'err', 'admin'); end if;
  insert into promo_codes (code, percent, uses_left, expires, active)
  values (upper(trim(p_code)), p_percent, p_uses, p_expires, coalesce(p_active, true))
  on conflict (code) do update set percent = excluded.percent, uses_left = excluded.uses_left, expires = excluded.expires, active = excluded.active;
  return json_build_object('ok', true);
end; $$;
grant execute on function public.admin_promo_save(text, int, int, date, boolean) to authenticated;

-- buyurtma narxi serverda hisoblanadi (brauzer yuborgan summaga ishonilmaydi), promo-kod qo'llanadi
create or replace function public.order_before_insert()
returns trigger language plpgsql security definer set search_path = public as $$
declare base int; pr record;
begin
  base := case new.kind when 'site' then 49000 when 'site3' then 129000 when 'site6' then 239000 when 'prefix' then 7000 when 'color' then 15000 end;
  if new.kind = 'color' and coalesce(new.color, '') !~ '^#[0-9a-fA-F]{6}$' then raise exception 'rang noto''g''ri'; end if;
  new.amount := base; new.promo := nullif(upper(trim(coalesce(new.promo, ''))), '');
  if new.promo is not null then
    select * into pr from promo_codes where code = new.promo and active and (uses_left is null or uses_left > 0)
      and (expires is null or expires >= (now() at time zone 'Asia/Tashkent')::date) for update;
    if found then
      new.amount := round(base * (100 - pr.percent) / 100.0 / 100) * 100;
      update promo_codes set uses_left = uses_left - 1 where code = pr.code and uses_left is not null;
    else
      new.promo := null;
    end if;
  end if;
  return new;
end; $$;
drop trigger if exists order_before_insert on public.premium_orders;
create trigger order_before_insert before insert on public.premium_orders for each row execute function public.order_before_insert();

-- tasdiqlash: yangi turlar
create or replace function public._decide_order(p_id bigint, p_ok boolean, p_note text)
returns json language plpgsql security definer set search_path = public as $$
declare o record;
begin
  select * into o from premium_orders where id = p_id for update;
  if not found or o.status <> 'pending' then
    return json_build_object('ok', false, 'err', 'buyurtma topilmadi yoki ko''rib chiqilgan');
  end if;
  update premium_orders set status = case when p_ok then 'approved' else 'rejected' end, note = p_note, decided_at = now() where id = p_id;
  if p_ok then
    if o.kind in ('site', 'site3', 'site6') then
      update accounts set premium_until = greatest(coalesce(premium_until, now()), now())
             + case o.kind when 'site3' then interval '90 days' when 'site6' then interval '180 days' else interval '30 days' end
       where user_id = o.user_id;
    elsif o.kind = 'color' then
      update accounts set color_paid = true, nick_color = o.color where user_id = o.user_id;
    else
      update accounts set prefix_paid = true,
                          prefix_text = coalesce(nullif(left(regexp_replace(trim(coalesce(o.prefix_text, '')), '["\[\];|\\]', '', 'g'), 14), ''), prefix_text)
       where user_id = o.user_id;
      perform public.queue_prefix(o.user_id);
    end if;
  end if;
  return json_build_object('ok', true, 'kind', o.kind);
end; $$;
revoke all on function public._decide_order(bigint, boolean, text) from public, anon, authenticated;

-- bot: rang va promo ham ko'rinsin
create or replace function public.bot_take_orders(p_secret text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare res json;
begin
  if not exists (select 1 from server_secrets where name = 'link' and hash = encode(digest(coalesce(p_secret, ''), 'sha256'), 'hex')) then
    return json_build_object('ok', false, 'err', 'auth');
  end if;
  with t as (
    update premium_orders set notified = true
     where id in (select id from premium_orders where status = 'pending' and not notified order by id limit 10)
    returning id, user_id, kind, amount, receipt_url, prefix_text, color, promo, created_at
  )
  select coalesce(json_agg(json_build_object(
           'id', t.id, 'kind', t.kind, 'amount', t.amount, 'receipt_url', t.receipt_url, 'prefix_text', t.prefix_text,
           'color', t.color, 'promo', t.promo,
           'created_at', t.created_at, 'nick', coalesce(a.site_nick, a.nick), 'steam', a.steam,
           'email', left(a.email, 2) || '***@' || split_part(a.email, '@', 2)) order by t.id), '[]'::json)
    into res from t left join accounts a on a.user_id = t.user_id;
  return res;
end; $$;
grant execute on function public.bot_take_orders(text) to anon, authenticated;

-- o'z nik rangini o'zgartirish (rang sotib olinganidan keyin)
create or replace function public.set_my_color(p_color text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from accounts where user_id = auth.uid() and color_paid) then return json_build_object('ok', false, 'err', 'rang sotib olinmagan'); end if;
  if p_color is not null and p_color <> '' and p_color !~ '^#[0-9a-fA-F]{6}$' then return json_build_object('ok', false, 'err', 'rang'); end if;
  update accounts set nick_color = nullif(p_color, '') where user_id = auth.uid();
  return json_build_object('ok', true);
end; $$;
grant execute on function public.set_my_color(text) to authenticated;

-- my_premium: rang ma'lumoti ham
create or replace function public.my_premium()
returns json language sql security definer stable set search_path = public as $$
  select json_build_object('premium_until', premium_until, 'active', coalesce(premium_until > now(), false),
                           'banner_url', banner_url, 'nick_font', nick_font, 'prefix_paid', prefix_paid, 'prefix_text', prefix_text,
                           'color_paid', color_paid, 'nick_color', nick_color)
    from accounts where user_id = auth.uid() $$;
grant execute on function public.my_premium() to authenticated;

-- ochiq profillar: nik rangi
drop function if exists public.public_profiles();
create function public.public_profiles()
returns table (user_id uuid, steam text, nick text, avatar_url text, show_badge boolean, premium boolean, banner_url text, nick_font text, nick_color text)
language sql security definer stable set search_path = public
as $$ select user_id, steam, coalesce(site_nick, nick), avatar_url, show_badge,
              coalesce(premium_until > now(), false),
              case when premium_until > now() then banner_url end,
              case when premium_until > now() then nick_font end,
              case when color_paid then nick_color end
       from public.accounts $$;
grant execute on function public.public_profiles() to anon, authenticated;
notify pgrst, 'reload schema';
