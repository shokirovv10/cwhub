-- CwhubUZ v2: nik va avatar, do'stlar, sayt ma'lumotlari (bot yozadi), avatar uchun Storage.
-- Supabase -> SQL Editor -> Run (bir marta). Takroriy ishga tushirish xavfsiz.

-- ---------------------------------------------------------------- profil: nik + avatar
alter table public.accounts add column if not exists avatar_url text;
alter table public.accounts add column if not exists site_nick text;

-- get_my_code: yangi akkauntda ro'yxatdan o'tishdagi nikni (user_metadata.nick) saqlaydi
create or replace function public.get_my_code()
returns public.accounts
language plpgsql security definer set search_path = public
as $$
declare
  r public.accounts;
  c text;
  nk text;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  select * into r from public.accounts where user_id = auth.uid();
  if found then return r; end if;
  select left(coalesce(raw_user_meta_data->>'nick', ''), 31) into nk from auth.users where id = auth.uid();
  loop
    c := (1000 + floor(random() * 9000))::int::text;
    begin
      insert into public.accounts (user_id, email, code, site_nick)
      values (auth.uid(), (select email from auth.users where id = auth.uid()), c, nullif(nk, ''))
      returning * into r;
      return r;
    exception when unique_violation then
    end;
  end loop;
end; $$;
revoke all on function public.get_my_code() from public, anon;
grant execute on function public.get_my_code() to authenticated;

-- o'z nik va avatarini o'zgartirish
create or replace function public.update_profile(p_nick text, p_avatar text)
returns void language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  update public.accounts
     set site_nick = nullif(left(trim(coalesce(p_nick, '')), 31), ''),
         avatar_url = case when p_avatar is null or p_avatar = '' then null
                           when p_avatar like 'https://jwvsjtntyajutsuqednk.supabase.co/storage/v1/object/public/avatars/' || auth.uid()::text || '/%' then p_avatar
                           else avatar_url end
   where user_id = auth.uid();
end; $$;
revoke all on function public.update_profile(text, text) from public, anon;
grant execute on function public.update_profile(text, text) to authenticated;

-- ochiq profil ma'lumoti (email chiqmaydi): SteamID -> nik, avatar, akkaunt id
create or replace function public.public_profiles()
returns table (user_id uuid, steam text, nick text, avatar_url text)
language sql security definer stable set search_path = public
as $$ select user_id, steam, coalesce(site_nick, nick), avatar_url from public.accounts $$;
grant execute on function public.public_profiles() to anon, authenticated;

-- ---------------------------------------------------------------- do'stlar
create table if not exists public.friendships (
  requester  uuid not null references auth.users on delete cascade,
  addressee  uuid not null references auth.users on delete cascade,
  status     text not null default 'pending',     -- pending | accepted
  created_at timestamptz default now(),
  primary key (requester, addressee),
  check (requester <> addressee)
);
alter table public.friendships enable row level security;
drop policy if exists "friends read" on public.friendships;
create policy "friends read" on public.friendships for select using (auth.uid() in (requester, addressee));
drop policy if exists "friends ask" on public.friendships;
create policy "friends ask" on public.friendships for insert with check (requester = auth.uid() and status = 'pending');
drop policy if exists "friends accept" on public.friendships;
create policy "friends accept" on public.friendships for update using (addressee = auth.uid()) with check (status = 'accepted');
drop policy if exists "friends remove" on public.friendships;
create policy "friends remove" on public.friendships for delete using (auth.uid() in (requester, addressee));

-- ---------------------------------------------------------------- sayt ma'lumotlari (bot yozadi, hamma o'qiydi)
create table if not exists public.site_data (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz default now()
);
alter table public.site_data enable row level security;
drop policy if exists "site data read" on public.site_data;
create policy "site data read" on public.site_data for select using (true);

-- ---------------------------------------------------------------- avatarlar (Storage)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 2097152, array['image/png', 'image/jpeg', 'image/webp', 'image/gif'])
on conflict (id) do update set public = true, file_size_limit = 2097152,
  allowed_mime_types = array['image/png', 'image/jpeg', 'image/webp', 'image/gif'];

drop policy if exists "avatar read" on storage.objects;
create policy "avatar read" on storage.objects for select using (bucket_id = 'avatars');
drop policy if exists "avatar upload own" on storage.objects;
create policy "avatar upload own" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "avatar update own" on storage.objects;
create policy "avatar update own" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "avatar delete own" on storage.objects;
create policy "avatar delete own" on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
