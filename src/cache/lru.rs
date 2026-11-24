//! 内存 LRU 索引：`oid -> (大小, 访问序号)` 加一条按访问序号排序的淘汰队列。
//!
//! 为什么手写而不引入 `lru` / `dashmap`：本仓库要求新依赖先在 `.agents/decisions/`
//! 记 ADR，而这里要的语义只有四个动作（插入、命中、删除、取最久未访问），用
//! `HashMap`（查找 O(1)）+ `BTreeMap`（按序号取最旧 O(log n)）已经足够，也不涉及
//! 跨线程共享——整个索引由 [`Cache`](crate::cache::Cache) 里同一把
//! `std::sync::Mutex` 保护，临界区里没有 `.await`，不存在「并发结构体的组合」。
//!
//! 访问序用单调递增的序号而不是时间戳：时间戳会撞、受系统时钟跳变影响，序号不会。

use std::collections::{BTreeMap, HashMap};

use crate::store::Oid;

/// 一个缓存对象的索引记录。
#[derive(Debug, Clone, Copy)]
struct Record {
    /// 对象字节数。
    size: u64,
    /// 最近一次访问的序号；越大越新。
    tick: u64,
}

/// 缓存索引：大小记账 + 访问序。
#[derive(Debug, Default)]
pub(crate) struct LruIndex {
    /// oid → 记录；`BTreeMap` 里存的是同一份大小与序号。
    entries: HashMap<Oid, Record>,
    /// 访问序号（升序）→ oid，队首即最久未访问的对象。
    order: BTreeMap<u64, Oid>,
    /// 已记账对象的总字节数。
    used: u64,
    /// 下一个访问序号。
    next_tick: u64,
}

impl LruIndex {
    /// 索引里的对象数。
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// 已记账对象的总字节数。
    pub(crate) fn used_bytes(&self) -> u64 {
        self.used
    }

    /// 记录一次命中：把访问序号推到最新，返回索引里记的大小。
    ///
    /// 只在内存里改动，不碰文件（「只读命中不写盘」）。
    pub(crate) fn touch(&mut self, oid: &Oid) -> Option<u64> {
        let record = *self.entries.get(oid)?;
        self.order.remove(&record.tick);
        let tick = self.stamp();
        self.entries.insert(oid.clone(), Record { size: record.size, tick });
        self.order.insert(tick, oid.clone());
        Some(record.size)
    }

    /// 记账一个新对象；同一个 oid 重复插入时以新大小为准。
    pub(crate) fn insert(&mut self, oid: &Oid, size: u64) {
        if self.entries.contains_key(oid) {
            self.remove(oid);
        }
        let tick = self.stamp();
        self.entries.insert(oid.clone(), Record { size, tick });
        self.order.insert(tick, oid.clone());
        self.used = self.used.saturating_add(size);
    }

    /// 丢掉一个对象，返回它记账时的大小。
    pub(crate) fn remove(&mut self, oid: &Oid) -> Option<u64> {
        let record = self.entries.remove(oid)?;
        self.order.remove(&record.tick);
        self.used = self.used.saturating_sub(record.size);
        Some(record.size)
    }

    /// 最久未访问的对象及其大小；索引为空时返回 `None`。
    pub(crate) fn oldest(&self) -> Option<(Oid, u64)> {
        let (_, oid) = self.order.iter().next()?;
        let size = self.entries.get(oid)?.size;
        Some((oid.clone(), size))
    }

    /// 按「最旧在前」的顺序批量装载（启动扫描按 mtime 升序喂进来）。
    pub(crate) fn load(&mut self, items: impl IntoIterator<Item = (Oid, u64)>) {
        for (oid, size) in items {
            self.insert(&oid, size);
        }
    }

    /// 取下一个访问序号。序号用尽（2^64 次访问）只会让淘汰顺序退化为插入序，
    /// 不影响正确性，因此用 `saturating_add` 而不是绕回。
    fn stamp(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick = self.next_tick.saturating_add(1);
        tick
    }
}

#[cfg(test)]
mod tests {
    use super::LruIndex;
    use crate::store::Oid;

    /// 第 `digit` 个对象：64 位重复字符，哈希与路径都合法。
    fn oid(digit: char) -> Oid {
        Oid::parse(&digit.to_string().repeat(64)).expect("合法 oid")
    }

    #[test]
    fn given_empty_index_when_oldest_then_none() {
        let index = LruIndex::default();

        assert_eq!(index.len(), 0);
        assert_eq!(index.used_bytes(), 0);
        assert!(index.oldest().is_none());
    }

    #[test]
    fn given_inserted_objects_when_oldest_then_least_recently_touched() {
        let (a, b, c) = (oid('a'), oid('b'), oid('c'));
        let mut index = LruIndex::default();
        index.insert(&a, 10);
        index.insert(&b, 20);
        index.insert(&c, 30);

        // b 被访问后变成最新，队首应变成 a。
        assert_eq!(index.touch(&b), Some(20));
        assert_eq!(
            index.oldest().map(|(oid, size)| (oid.to_string(), size)),
            Some((a.to_string(), 10))
        );

        assert_eq!(index.touch(&a), Some(10));
        assert_eq!(index.oldest().map(|(oid, _)| oid.to_string()), Some(c.to_string()));
    }

    #[test]
    fn given_touched_object_when_remove_then_size_subtracted_once() {
        let a = oid('a');
        let mut index = LruIndex::default();
        index.insert(&a, 7);
        index.touch(&a);

        assert_eq!(index.used_bytes(), 7);
        assert_eq!(index.remove(&a), Some(7));
        assert_eq!(index.used_bytes(), 0);
        assert!(index.oldest().is_none(), "移除后不得留在淘汰队列里");
        assert_eq!(index.remove(&a), None, "重复移除应返回 None");
    }

    #[test]
    fn given_same_oid_inserted_twice_when_insert_then_size_replaced_not_added() {
        let a = oid('a');
        let mut index = LruIndex::default();
        index.insert(&a, 5);
        index.insert(&a, 8);

        assert_eq!(index.len(), 1);
        assert_eq!(index.used_bytes(), 8, "重复插入只换大小，不累加");
    }

    #[test]
    fn given_mtime_sorted_batch_when_load_then_oldest_is_first() {
        let (first, second) = (oid('1'), oid('2'));
        let mut index = LruIndex::default();
        index.load([(first.clone(), 3), (second.clone(), 4)]);

        assert_eq!(index.len(), 2);
        assert_eq!(index.used_bytes(), 7);
        assert_eq!(index.oldest().map(|(oid, _)| oid), Some(first));
    }
}
