-- CwhubUZ v21: xavfsizlikni kuchaytirish (zaifliklarni yopish)

-- 1) Do'stlik: qabul qiluvchi qatorni boshqa odamga "qayta yo'naltira" olardi (begona bilan do'st bo'lib DM yozish).
drop policy if exists "friends accept" on public.friendships;
create policy "friends accept" on public.friendships for update
  using (addressee = auth.uid()) with check (addressee = auth.uid() and status = 'accepted');
revoke update on public.friendships from anon, authenticated;
grant update (status) on public.friendships to authenticated;

-- 2) Murojaatlar: foydalanuvchi faqat holatni (ochiq/yopiq) o'zgartiradi; "javob berildi" — faqat admin.
drop policy if exists "tickets update" on public.tickets;
create policy "tickets update admin" on public.tickets for update using (public.is_site_admin()) with check (public.is_site_admin());
create policy "tickets update own" on public.tickets for update
  using (user_id = auth.uid()) with check (user_id = auth.uid() and status in ('open', 'closed'));
revoke update on public.tickets from anon, authenticated;
grant update (status, updated_at) on public.tickets to authenticated;

-- 3) Ochiq "avatars" bucket'idagi barcha fayllar ro'yxatini olish yopiladi (rasmlar havola orqali ochilaveradi).
drop policy if exists "avatar read" on storage.objects;

-- 4) Rasm havolalari: faqat xavfsiz belgilar (CSS'ga qo'shtirnoq/qavs bilan chiqib ketishning oldi olinadi)
create or replace function public._safe_img(p text, p_uid uuid) returns boolean language sql immutable as $$
  select p ~ ('^https://jwvsjtntyajutsuqednk\.supabase\.co/storage/v1/object/public/avatars/' || p_uid::text || '/[A-Za-z0-9._-]+$') $$;

create or replace function public.update_profile(p_nick text, p_avatar text)
returns void language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  update public.accounts
     set site_nick = nullif(left(regexp_replace(trim(coalesce(p_nick, '')), '[<>"''`\\]', '', 'g'), 31), ''),
         avatar_url = case when p_avatar is null or p_avatar = '' then null
                           when public._safe_img(p_avatar, auth.uid()) then p_avatar
                           else avatar_url end
   where user_id = auth.uid();
end; $$;
revoke all on function public.update_profile(text, text) from public, anon;
grant execute on function public.update_profile(text, text) to authenticated;

create or replace function public.set_my_style(p_font text, p_banner text)
returns json language plpgsql security definer set search_path = public as $$
declare a record;
begin
  select premium_until into a from accounts where user_id = auth.uid();
  if a.premium_until is null or a.premium_until <= now() then
    return json_build_object('ok', false, 'err', 'Premium faol emas');
  end if;
  if p_font is not null and p_font not in ('', 'f1', 'f2', 'f3') then
    return json_build_object('ok', false, 'err', 'font');
  end if;
  if p_banner is not null and p_banner <> '' and not public._safe_img(p_banner, auth.uid()) and p_banner !~ '^/banners/[a-z0-9_]+\.gif$' then
    return json_build_object('ok', false, 'err', 'banner');
  end if;
  update accounts set nick_font  = case when p_font is null then nick_font else nullif(p_font, '') end,
                      banner_url = case when p_banner is null then banner_url else nullif(p_banner, '') end
   where user_id = auth.uid();
  return json_build_object('ok', true);
end; $$;

create or replace function public.set_my_chat_bg(p_bg text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from accounts where user_id = auth.uid() and premium_until > now()) then
    return json_build_object('ok', false, 'err', 'premium');
  end if;
  if p_bg is not null and p_bg <> '' and p_bg !~ '^bg[0-9]{1,2}$' and not public._safe_img(p_bg, auth.uid()) then
    return json_build_object('ok', false, 'err', 'bg');
  end if;
  update accounts set chat_bg = nullif(p_bg, '') where user_id = auth.uid();
  return json_build_object('ok', true);
end; $$;

-- eski noto'g'ri qiymatlar tozalanadi
update public.accounts set avatar_url = null where avatar_url is not null and not public._safe_img(avatar_url, user_id);
update public.accounts set banner_url = null where banner_url is not null and not public._safe_img(banner_url, user_id) and banner_url !~ '^/banners/[a-z0-9_]+\.gif$';
update public.accounts set chat_bg = null where chat_bg is not null and chat_bg !~ '^bg[0-9]{1,2}$' and not public._safe_img(chat_bg, user_id);

-- 5) Kirmagan (anonim) foydalanuvchi uchun keraksiz funksiyalar yopiladi. Ochiq qoladi: public_profiles, is_site_admin,
--    server/bot funksiyalari (maxfiy kalit bilan), link_by_code, log_visit, demo_ticket_ok.
do $$ declare f text; begin
  foreach f in array array[
    'admin_block_user(uuid, integer, text)', 'admin_decide_order(bigint, boolean, text)', 'admin_promo_list()',
    'admin_promo_save(text, integer, integer, date, boolean)', 'admin_send_alert(uuid, text, text)', 'admin_users_list(text)',
    'chat_mute(uuid, integer)', 'check_promo(text)', 'my_premium()', 'is_blocked(uuid)',
    'set_badge(boolean)', 'set_my_chat_bg(text)', 'set_my_color(text)', 'set_my_prefix(text)', 'set_my_style(text, text)'] loop
    execute format('revoke execute on function public.%s from public, anon', f);
    execute format('grant execute on function public.%s to authenticated', f);
  end loop;
  -- trigger funksiyalarini to'g'ridan-to'g'ri chaqirib bo'lmaydi (triggerlar baribir ishlaydi)
  foreach f in array array['block_guard()', 'chat_before_insert()', 'order_before_insert()', 'email_change_guard()', 'auto_site_admin()'] loop
    execute format('revoke execute on function public.%s from public, anon, authenticated', f);
  end loop;
end $$;
notify pgrst, 'reload schema';
