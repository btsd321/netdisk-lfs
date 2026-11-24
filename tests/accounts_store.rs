//! SQLite 账户库与口令原语的集成测试。
//!
//! 每个用例在自己的临时目录里建库，不访问网盘、不依赖真实 HOME；覆盖建库/重开、
//! 角色与状态读写、用户名大小写重复、非法用户名、Argon2id 哈希与校验、口令策略、
//! 分页与状态过滤、登录时间、管理员计数、schema 版本与删除。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use netdisk_lfs::{
    AccountError, Role, UserStatus, UserStore, hash_password, validate_password, verify_password,
};

/// 每个用例一个临时目录；Drop 时连同 SQLite 的 `-wal` / `-shm` 一起删除。
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("netdisk-lfs-accounts-{}-{seq}", std::process::id()));
        std::fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }

    fn db(&self) -> PathBuf {
        self.path.join("accounts.db")
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 创建账户时使用的占位哈希：store 不解析哈希，只有口令用例需要真实 Argon2。
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$cGxhY2Vob2xkZXI";

/// 打开账户库；失败即测试失败，避免后续断言静默跳过。
fn open(workspace: &Workspace) -> UserStore {
    UserStore::open(&workspace.db()).expect("账户库应能打开")
}

/// 用占位哈希创建一个账户。
async fn create(store: &UserStore, username: &str, role: Role, status: UserStatus) {
    store
        .create(username, PASSWORD_HASH, role, status)
        .await
        .unwrap_or_else(|error| panic!("创建 {username} 失败：{error}"));
}

#[tokio::test]
async fn given_new_path_when_open_then_creates_db_and_reopen_keeps_user() {
    let workspace = Workspace::new();
    let db = workspace.path.join("nested").join("accounts.db");

    let store = UserStore::open(&db).expect("应创建父目录与账户库");
    assert!(db.exists(), "账户库文件应已创建");

    let created = store
        .create("Alice", PASSWORD_HASH, Role::Admin, UserStatus::Active)
        .await
        .expect("创建应成功");
    assert_eq!(created.username, "Alice");
    assert_eq!(created.role, Role::Admin);
    assert_eq!(created.status, UserStatus::Active);
    assert!(created.created_at > 0, "created_at 应写入 unix 秒");
    assert_eq!(created.last_login_at, None, "新账户从未登录");
    drop(store);

    let reopened = UserStore::open(&db).expect("重开应成功");
    let loaded =
        reopened.get("alice").await.expect("查询应成功").expect("重开后用户应仍在（大小写不敏感）");
    assert_eq!(loaded, created);
}

#[tokio::test]
async fn given_role_and_status_changes_when_update_then_read_back() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "alice", Role::Readwrite, UserStatus::Active).await;

    store.update_role("alice", Role::Admin).await.expect("改角色应成功");
    store.update_status("alice", UserStatus::Pending).await.expect("改状态应成功");

    let updated = store.get("alice").await.expect("查询应成功").expect("用户应存在");
    assert_eq!(updated.role, Role::Admin);
    assert_eq!(updated.status, UserStatus::Pending);
}

#[tokio::test]
async fn given_case_variant_username_when_create_then_duplicate() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "Alice", Role::Readwrite, UserStatus::Active).await;

    for duplicate in ["Alice", "alice", "ALICE"] {
        let error = store
            .create(duplicate, PASSWORD_HASH, Role::Readonly, UserStatus::Active)
            .await
            .expect_err("大小写变体应被判重复");
        assert!(
            matches!(error, AccountError::DuplicateUsername { ref username } if username == duplicate),
            "实际错误：{error}"
        );
    }
}

#[tokio::test]
async fn given_illegal_username_when_create_or_get_then_invalid_username() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    let too_long = "a".repeat(33);

    for invalid in ["", "ab", too_long.as_str(), "has space", "has:colon", "名字名字"] {
        let error = store
            .create(invalid, PASSWORD_HASH, Role::Readwrite, UserStatus::Active)
            .await
            .expect_err("非法用户名应被拒");
        assert!(
            matches!(error, AccountError::InvalidUsername { .. }),
            "{invalid} 的实际错误：{error}"
        );

        let error = store.get(invalid).await.expect_err("查询入口也应校验用户名");
        assert!(
            matches!(error, AccountError::InvalidUsername { .. }),
            "{invalid} 的查询错误：{error}"
        );
    }
}

#[tokio::test]
async fn given_argon2_password_when_hash_and_verify_then_roundtrip() {
    let password = "correct horse battery";

    let hash = hash_password(password).expect("哈希应成功");
    assert!(hash.starts_with("$argon2id$"), "实际哈希：{hash}");
    assert!(verify_password(&hash, password));
    assert!(!verify_password(&hash, "wrong password"));
    assert!(!verify_password("not-a-phc-string", password), "损坏哈希应返回 false");
}

#[tokio::test]
async fn given_password_policy_violations_when_validate_then_rejected() {
    assert!(validate_password("alice", "correct horse battery", 12).is_ok());

    let short = validate_password("alice", "short", 12).expect_err("过短应拒绝");
    assert!(matches!(short, AccountError::InvalidPassword { .. }));

    let same = validate_password("Alice", "alice123456", 6);
    assert!(same.is_ok(), "只是前缀相同不算与用户名相同");
    let same = validate_password("Alice", "ALICE", 5).expect_err("与用户名相同应拒绝");
    assert!(matches!(same, AccountError::InvalidPassword { .. }));

    let blank = validate_password("alice", "            ", 12).expect_err("全空白应拒绝");
    assert!(matches!(blank, AccountError::InvalidPassword { .. }));
}

#[tokio::test]
async fn given_password_hash_update_when_read_back_then_replaced() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "alice", Role::Readwrite, UserStatus::Active).await;

    let new_hash = hash_password("new correct horse battery").expect("哈希应成功");
    store.update_password_hash("alice", &new_hash).await.expect("改哈希应成功");

    // 直接读库确认列已替换：User 不携带哈希，认证路径才需要它。
    let conn = rusqlite::Connection::open(workspace.db()).expect("只读连接应能打开");
    let stored: String = conn
        .query_row("SELECT password_hash FROM users WHERE username = 'alice'", [], |row| row.get(0))
        .expect("应能读到哈希");
    assert_eq!(stored, new_hash);
}

#[tokio::test]
async fn given_users_when_list_with_pagination_and_status_then_total_and_slices() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "alice", Role::Readwrite, UserStatus::Active).await;
    create(&store, "bob", Role::Readwrite, UserStatus::Active).await;
    create(&store, "carol", Role::Readonly, UserStatus::Active).await;
    create(&store, "dave", Role::Readwrite, UserStatus::Pending).await;
    create(&store, "eve", Role::Readonly, UserStatus::Disabled).await;

    let (all, total) = store.list(None, 10, 0).await.expect("列表应成功");
    assert_eq!(total, 5, "总数应是过滤前的全库数");
    assert_eq!(
        all.iter().map(|user| user.username.as_str()).collect::<Vec<_>>(),
        ["alice", "bob", "carol", "dave", "eve"],
        "应按创建顺序返回"
    );

    let (active, total) = store.list(Some(UserStatus::Active), 2, 0).await.expect("列表应成功");
    assert_eq!(total, 3, "状态过滤后的总数");
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|user| user.status == UserStatus::Active));

    let (rest, total) = store.list(Some(UserStatus::Active), 2, 2).await.expect("列表应成功");
    assert_eq!(total, 3);
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].username, "carol");

    let (pending, total) = store.list(Some(UserStatus::Pending), 0, 0).await.expect("列表应成功");
    assert_eq!(total, 1);
    assert_eq!(pending[0].username, "dave");
}

#[tokio::test]
async fn given_never_logged_in_user_when_touch_last_login_then_timestamp_set() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "alice", Role::Readwrite, UserStatus::Active).await;

    store.touch_last_login("alice").await.expect("记录登录应成功");

    let user = store.get("alice").await.expect("查询应成功").expect("用户应存在");
    let last_login = user.last_login_at.expect("登录时间应写入");
    assert!(last_login >= user.created_at, "登录时间不应早于创建时间");
}

#[tokio::test]
async fn given_mixed_admins_when_count_active_admins_then_only_active_admin() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "active-admin", Role::Admin, UserStatus::Active).await;
    create(&store, "pending-admin", Role::Admin, UserStatus::Pending).await;
    create(&store, "disabled-admin", Role::Admin, UserStatus::Disabled).await;
    create(&store, "writer", Role::Readwrite, UserStatus::Active).await;

    assert_eq!(store.count_active_admins().await.expect("计数应成功"), 1);

    store.update_status("disabled-admin", UserStatus::Active).await.expect("改状态应成功");
    assert_eq!(store.count_active_admins().await.expect("计数应成功"), 2);
}

#[tokio::test]
async fn given_missing_user_when_update_or_delete_then_not_found() {
    let workspace = Workspace::new();
    let store = open(&workspace);

    for result in [
        store.update_role("ghost", Role::Admin).await,
        store.update_status("ghost", UserStatus::Active).await,
        store.update_password_hash("ghost", PASSWORD_HASH).await,
        store.touch_last_login("ghost").await,
        store.delete("ghost").await,
    ] {
        let error = result.expect_err("不存在的用户应返回 NotFound");
        assert!(matches!(error, AccountError::NotFound { .. }), "实际错误：{error}");
    }
}

#[tokio::test]
async fn given_existing_user_when_delete_then_gone() {
    let workspace = Workspace::new();
    let store = open(&workspace);
    create(&store, "alice", Role::Readwrite, UserStatus::Active).await;

    store.delete("alice").await.expect("删除应成功");

    assert_eq!(store.get("alice").await.expect("查询应成功"), None);
    let error = store.delete("alice").await.expect_err("重复删除应 NotFound");
    assert!(matches!(error, AccountError::NotFound { .. }));
}

#[tokio::test]
async fn given_newer_schema_version_when_open_then_rejected() {
    let workspace = Workspace::new();
    let db = workspace.db();
    drop(open(&workspace));

    let conn = rusqlite::Connection::open(&db).expect("应能打开账户库");
    conn.execute("UPDATE schema_meta SET version = 2", []).expect("应能改版本");
    drop(conn);

    let error = UserStore::open(&db).expect_err("更高版本应拒绝启动");

    assert!(
        matches!(error, AccountError::SchemaTooNew { found: 2, supported: 1 }),
        "实际错误：{error}"
    );
}

#[test]
fn given_file_backed_store_when_open_then_path_is_reported() {
    let workspace = Workspace::new();
    let db = workspace.db();

    let store = UserStore::open(&db).expect("账户库应能打开");

    assert_eq!(store.path(), db.as_path());
}
