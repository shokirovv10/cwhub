-- CwhubUZ v19: bitta IP'dan faqat bitta /link (bir kompyuterdan bir nechta akkaunt ulanmasin)

alter table public.accounts add column if not exists link_ip text;

create or replace function public.link_by_code(p_code text, p_steam text, p_nick text, p_secret text, p_ip text)
returns json language plpgsql security definer set search_path = public, extensions
as $$
declare acc record; cur record; v_ip text := nullif(split_part(trim(coalesce(p_ip, '')), ':', 1), '');
begin
  if not exists (select 1 from server_secrets where name = 'link' and hash = encode(digest(coalesce(p_secret, ''), 'sha256'), 'hex')) then
    return json_build_object('ok', false, 'err', 'auth');
  end if;
  if p_code !~ '^[0-9]{4}$' or p_steam !~* '^STEAM_[0-5]:[01]:[0-9]+$' then
    return json_build_object('ok', false, 'err', 'format');
  end if;
  select email into cur from accounts where upper(steam) = upper(p_steam) limit 1;
  if found then
    return json_build_object('ok', false, 'err', 'already', 'email', left(cur.email, 2) || '***@' || split_part(cur.email, '@', 2));
  end if;
  select user_id, email, steam into acc from accounts where code = p_code;
  if not found then
    return json_build_object('ok', false, 'err', 'code');
  end if;
  if acc.steam is not null and acc.steam <> '' then
    return json_build_object('ok', false, 'err', 'taken');
  end if;
  -- shu IP'dan boshqa akkaunt allaqachon ulangan
  if v_ip is not null and exists (select 1 from accounts where link_ip = v_ip and user_id <> acc.user_id) then
    return json_build_object('ok', false, 'err', 'ip');
  end if;
  update accounts set steam = upper(p_steam), nick = left(coalesce(p_nick, ''), 31), linked_at = now(), link_ip = v_ip where user_id = acc.user_id;
  return json_build_object('ok', true, 'email', left(acc.email, 2) || '***@' || split_part(acc.email, '@', 2));
end; $$;
revoke all on function public.link_by_code(text, text, text, text, text) from public;
grant execute on function public.link_by_code(text, text, text, text, text) to anon, authenticated;

-- eski (IP'siz) chaqiruv — yangi qoidaga yo'naltiriladi
create or replace function public.link_by_code(p_code text, p_steam text, p_nick text, p_secret text)
returns json language sql security definer set search_path = public
as $$ select public.link_by_code(p_code, p_steam, p_nick, p_secret, null::text) $$;
notify pgrst, 'reload schema';
