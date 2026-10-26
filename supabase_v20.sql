-- CwhubUZ v20: emailni faqat bir marta o'zgartirish mumkin (server tomonida majburiy)

alter table public.accounts add column if not exists email_changed_at timestamptz;

create or replace function public.email_change_guard() returns trigger language plpgsql security definer set search_path = public as $$
begin
  -- yangi email so'raldi (tasdiqlash xati yuboriladi): avval o'zgartirgan bo'lsa — rad etiladi
  if coalesce(new.email_change, '') <> '' and new.email_change is distinct from old.email_change
     and exists (select 1 from public.accounts where user_id = new.id and email_changed_at is not null) then
    raise exception 'email_once';
  end if;
  -- email haqiqatan o'zgardi (tasdiqlandi): akkauntga yoziladi va qayta o'zgartirish yopiladi
  if old.email is not null and new.email is distinct from old.email then
    update public.accounts set email = new.email, email_changed_at = now() where user_id = new.id;
  end if;
  return new;
end; $$;
drop trigger if exists cw_email_change on auth.users;
create trigger cw_email_change before update on auth.users for each row execute function public.email_change_guard();
