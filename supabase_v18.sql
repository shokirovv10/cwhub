-- CwhubUZ v18: nik rangi tuzatish, shaxsiy chatda javob (reply) va o'qildi belgisi, Premium chat foni.

-- 1) rang buyurtmasi tasdiqlanganda: buyurtmada rang bo'lmasa — oldingi rang saqlanadi (avval null bo'lib qolardi)
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
      update accounts set color_paid = true, nick_color = coalesce(nullif(o.color, ''), nick_color, '#ff9f1c') where user_id = o.user_id;
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

-- rangi bo'lmay qolgan, lekin sotib olinganlar — standart rang
update public.accounts set nick_color = '#ff9f1c' where color_paid and nick_color is null;

-- 2) shaxsiy chat: javob (reply)
alter table public.direct_messages add column if not exists reply_to bigint references public.direct_messages(id) on delete set null;
alter table public.direct_messages add column if not exists reply_body text check (reply_body is null or length(reply_body) <= 140);

-- o'qildi belgisi realtime'da ko'rinishi uchun (UPDATE hodisasida eski qiymat ham)
alter table public.direct_messages replica identity full;

-- 3) Premium: shaxsiy chat foni (tayyor fon kaliti yoki o'z rasmi — faqat bizning storage)
alter table public.accounts add column if not exists chat_bg text;
create or replace function public.set_my_chat_bg(p_bg text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from accounts where user_id = auth.uid() and premium_until > now()) then
    return json_build_object('ok', false, 'err', 'premium');
  end if;
  if p_bg is not null and p_bg <> '' and p_bg !~ '^bg[0-9]{1,2}$'
     and p_bg !~ '^https://jwvsjtntyajutsuqednk\.supabase\.co/storage/v1/object/public/avatars/' then
    return json_build_object('ok', false, 'err', 'bg');
  end if;
  update accounts set chat_bg = nullif(p_bg, '') where user_id = auth.uid();
  return json_build_object('ok', true);
end; $$;
grant execute on function public.set_my_chat_bg(text) to authenticated;

create or replace function public.my_premium()
returns json language sql security definer stable set search_path = public as $$
  select json_build_object('premium_until', premium_until, 'active', coalesce(premium_until > now(), false),
                           'banner_url', banner_url, 'nick_font', nick_font, 'prefix_paid', prefix_paid, 'prefix_text', prefix_text,
                           'color_paid', color_paid, 'nick_color', nick_color, 'chat_bg', case when premium_until > now() then chat_bg end)
    from accounts where user_id = auth.uid() $$;
grant execute on function public.my_premium() to authenticated;
notify pgrst, 'reload schema';
