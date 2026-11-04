-- 在 Supabase 控制台 → SQL Editor 里，整段粘贴并运行（只运行一次）

-- ============ 1. 用户资料（用户名 + 是否管理员） ============
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null check (username ~ '^[A-Za-z0-9_一-龥]{2,20}$'),
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);
create unique index profiles_username_key on public.profiles (lower(username));
alter table public.profiles enable row level security;
create policy "登录用户可查看用户名" on public.profiles for select to authenticated using (true);
-- 注意：不给任何人 insert/update/delete 权限，用户无法自己改成管理员

-- 注册时自动建立资料（用户名来自注册表单）
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
declare n text := btrim(coalesce(new.raw_user_meta_data->>'username', ''));
begin
  if n !~ '^[A-Za-z0-9_一-龥]{2,20}$' then raise exception 'invalid username'; end if;
  insert into public.profiles (id, username) values (new.id, n);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 注册前检查用户名是否可用
create function public.username_available(n text) returns boolean
language sql stable security definer set search_path = '' as $$
  select not exists (select 1 from public.profiles where lower(username) = lower(btrim(n)))
$$;

-- 当前登录者是否为管理员（供下面的权限规则使用）
create function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false)
$$;

-- ============ 2. 数据表 ============
create table public.board_posts (   -- 留言板（所有人共用）
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body text not null check (char_length(btrim(body)) between 1 and 500),
  created_at timestamptz not null default now()
);
create table public.countdowns (    -- 倒数日
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 40),
  date date not null,
  created_at timestamptz not null default now()
);
create table public.events (        -- 日历日程
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  title text not null check (char_length(btrim(title)) between 1 and 100),
  date date not null,
  created_at timestamptz not null default now()
);
create table public.statuses (      -- 今日状态（每人每天一条）
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  date date not null,
  mood text not null check (mood in ('😊','😐','😴','🔥')),
  note text not null default '' check (char_length(note) <= 100),
  created_at timestamptz not null default now(),
  unique (user_id, date)
);
create table public.chat_messages ( -- 公共聊天室
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body text not null check (char_length(btrim(body)) between 1 and 1000),
  created_at timestamptz not null default now()
);
create index on public.chat_messages (created_at);

-- ============ 3. 权限规则（行级安全 RLS） ============
alter table public.board_posts   enable row level security;
alter table public.countdowns    enable row level security;
alter table public.events        enable row level security;
alter table public.statuses      enable row level security;
alter table public.chat_messages enable row level security;

-- 留言板：所有登录用户可看；只能发/改自己的；本人或管理员可删
create policy "board read"   on public.board_posts for select to authenticated using (true);
create policy "board insert" on public.board_posts for insert to authenticated with check (user_id = auth.uid());
create policy "board update" on public.board_posts for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "board delete" on public.board_posts for delete to authenticated using (user_id = auth.uid() or public.is_admin());

-- 倒数日 / 日程 / 状态：本人可看；管理员可看全部；只能发/改自己的；本人或管理员可删
create policy "cd read"   on public.countdowns for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "cd insert" on public.countdowns for insert to authenticated with check (user_id = auth.uid());
create policy "cd update" on public.countdowns for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "cd delete" on public.countdowns for delete to authenticated using (user_id = auth.uid() or public.is_admin());

create policy "ev read"   on public.events for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "ev insert" on public.events for insert to authenticated with check (user_id = auth.uid());
create policy "ev update" on public.events for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "ev delete" on public.events for delete to authenticated using (user_id = auth.uid() or public.is_admin());

create policy "st read"   on public.statuses for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "st insert" on public.statuses for insert to authenticated with check (user_id = auth.uid());
create policy "st update" on public.statuses for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "st delete" on public.statuses for delete to authenticated using (user_id = auth.uid() or public.is_admin());

-- 公共聊天室：所有登录用户可看、可发；不能改；本人或管理员可删
create policy "chat read"   on public.chat_messages for select to authenticated using (true);
create policy "chat insert" on public.chat_messages for insert to authenticated with check (user_id = auth.uid());
create policy "chat delete" on public.chat_messages for delete to authenticated using (user_id = auth.uid() or public.is_admin());

-- ============ 4. 接口访问授权 ============
grant usage on schema public to anon, authenticated;
grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.board_posts, public.countdowns, public.events, public.statuses to authenticated;
grant select, insert, delete on public.chat_messages to authenticated;
grant execute on function public.username_available(text) to anon, authenticated;
grant execute on function public.is_admin() to authenticated;

-- ============ 5. 聊天室实时推送 ============
alter publication supabase_realtime add table public.chat_messages;

-- ============ 第二步：设置管理员（先在网站上用你的邮箱注册好账号，再单独运行下面这句） ============
-- 把邮箱改成你注册时用的那个，并去掉行首的 -- 再运行：
-- update public.profiles set is_admin = true where id = (select id from auth.users where email = 'you@example.com');
