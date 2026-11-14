//! Complete-copy references follow stable disk IDs during the movement phase.
use super::*;
use std::mem::size_of;

const NONE: usize = usize::MAX;
const SHARED: usize = usize::MAX - 1;

struct Budget {
    used: u64,
    limit: u64,
}
impl Budget {
    fn add(&mut self, bytes: usize) -> Result<(), RepairError> {
        let required = self.used.saturating_add(bytes as u64);
        if required > self.limit {
            return Err(RepairError::StreamingMemoryLimit {
                context: "complete-copy movement",
                required_bytes: required,
                limit_bytes: self.limit,
            });
        }
        self.used = required;
        Ok(())
    }
    fn vector<T>(&mut self, count: usize) -> Result<Vec<T>, RepairError> {
        let bytes = count.saturating_mul(size_of::<T>());
        self.add(bytes)?;
        let mut v = Vec::new();
        v.try_reserve_exact(count)
            .map_err(|e| io_ctx("reserving complete-copy movement")(io::Error::other(e)))?;
        self.add((v.capacity() - count).saturating_mul(size_of::<T>()))?;
        Ok(v)
    }
    fn indexes(&mut self, count: usize) -> Result<Vec<usize>, RepairError> {
        let mut v = self.vector(count)?;
        v.resize(count, NONE);
        Ok(v)
    }
}

pub(super) struct Copies {
    heads: Vec<usize>,
    next: Vec<usize>,
    owners: Vec<usize>,
    targets: Vec<usize>,
    backup_slots: Vec<usize>,
    consumed: Vec<bool>,
}
impl Copies {
    /// All additional storage is fallibly admitted before any filesystem change.
    /// Disk IDs and block locations stay fixed throughout this phase.
    pub(super) fn prepare(
        r: &mut Par2Repairer,
        incomplete: usize,
        limit: u64,
    ) -> Result<(Self, Vec<PathBuf>), RepairError> {
        let mut budget = Budget { used: 0, limit };
        let mut heads = budget.indexes(r.disk_files.len())?;
        let mut next = budget.indexes(r.files.len())?;
        let mut owners = budget.indexes(r.disk_files.len())?;
        let mut targets = budget.vector(r.files.len())?;
        targets.extend(0..r.files.len());
        targets.sort_unstable_by(|&a, &b| r.files[a].target_path.cmp(&r.files[b].target_path));
        let backup_slots = budget.indexes(r.disk_files.len())?;
        let mut consumed = budget.vector(incomplete)?;
        consumed.resize(incomplete, false);
        let backups = budget.vector(incomplete)?;
        let mut capacities = budget.indexes(r.disk_files.len())?;
        // Longest numbered/bak suffix representable by make_backup's usize counter.
        let suffix = 5 + (usize::BITS as usize / 3 + 1);
        for (di, path) in r.disk_files.iter().enumerate() {
            capacities[di] = path.as_os_str().len().saturating_add(suffix);
        }
        for (fi, file) in r.files.iter().enumerate() {
            if let Some(di) = file
                .complete_file
                .as_ref()
                .and_then(|p| r.disk_index.get(p))
                .copied()
            {
                next[fi] = heads[di];
                heads[di] = fi;
                capacities[di] =
                    capacities[di].max(file.target_path.as_os_str().len().saturating_add(suffix));
            }
            for location in r.locations
                [file.first_block..file.first_block + file.block_count as usize]
                .iter()
                .flatten()
            {
                let owner = &mut owners[location.file];
                if *owner == NONE {
                    *owner = fi;
                } else if *owner != fi {
                    *owner = SHARED;
                }
            }
        }
        for (di, &head) in heads.iter().enumerate() {
            let mut fi = head;
            while fi != NONE {
                let path = r.files[fi].complete_file.as_mut().unwrap();
                let old = path.capacity();
                let needed = capacities[di].saturating_sub(old);
                budget.add(needed)?;
                path.try_reserve_exact(capacities[di].saturating_sub(path.as_os_str().len()))
                    .map_err(|e| io_ctx("reserving complete-copy path")(io::Error::other(e)))?;
                budget.add(path.capacity().saturating_sub(old).saturating_sub(needed))?;
                fi = next[fi];
            }
        }
        Ok((
            Self {
                heads,
                next,
                owners,
                targets,
                backup_slots,
                consumed,
            },
            backups,
        ))
    }
    pub(super) fn remap(&self, files: &mut [SourceFileState], di: usize, path: &Path) {
        let mut fi = self.heads[di];
        while fi != NONE {
            let current = files[fi].complete_file.as_mut().unwrap();
            debug_assert!(current.capacity() >= path.as_os_str().len());
            current.clear();
            current.push(path);
            fi = self.next[fi];
        }
    }
    pub(super) fn shared(
        &self,
        r: &Par2Repairer,
        fi: usize,
        di: Option<usize>,
        path: &Path,
    ) -> bool {
        di.is_some_and(|di| self.owners[di] != NONE && self.owners[di] != fi)
            || self
                .targets
                .binary_search_by(|&i| r.files[i].target_path.as_path().cmp(path))
                .is_ok_and(|i| {
                    let other = self.targets[i];
                    other != fi && r.files[other].status == FileStatus::Complete
                })
    }
    pub(super) fn backed_up(&mut self, di: usize, slot: usize) {
        self.backup_slots[di] = slot;
    }
    pub(super) fn moved(&mut self, di: usize, path: &Path, backups: &[PathBuf]) {
        let slot = self.backup_slots[di];
        if slot != NONE && backups[slot] == path {
            self.consumed[slot] = true;
            self.backup_slots[di] = NONE;
        }
    }
    pub(super) fn retain_backups(&self, backups: &mut Vec<PathBuf>) {
        let mut i = 0;
        backups.retain(|_| {
            let keep = !self.consumed[i];
            i += 1;
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn movement_budget_rejects_before_touching_existing_files() {
        let dir =
            std::env::temp_dir().join(format!("par-rs-movement-budget-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let a = b"abcdefghABCDEFGH".as_slice();
        let b = b"12345678!@#$%^&*".as_slice();
        crate::build_set(
            "set",
            &[("a.bin", a), ("b.bin", b)],
            &crate::SetOptions {
                slice_size: 16,
                recovery_blocks: 0,
                ..Default::default()
            },
        )
        .unwrap()
        .write_to(&dir, "set")
        .unwrap();
        std::fs::write(dir.join("a.bin"), b).unwrap();
        std::fs::write(dir.join("b.bin"), a).unwrap();
        let mut r = Par2Repairer::new(&dir, RepairOptions::default());
        r.load_par2_set(&dir.join("set.par2")).unwrap();
        r.finalize().unwrap();
        r.verify(None, &mut NullObserver).unwrap();
        let paths: Vec<_> = r.files.iter().map(|f| f.complete_file.clone()).collect();
        let disks = r.disk_files.clone();
        assert!(matches!(
            Copies::prepare(&mut r, 2, 1),
            Err(RepairError::StreamingMemoryLimit {
                context: "complete-copy movement",
                limit_bytes: 1,
                ..
            })
        ));
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), b);
        assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), a);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);
        assert_eq!(
            paths,
            r.files
                .iter()
                .map(|f| f.complete_file.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(disks, r.disk_files);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn movement_budget_checks_overflow_before_allocation() {
        let mut budget = Budget {
            used: 0,
            limit: 16 << 20,
        };
        assert!(matches!(
            budget.vector::<usize>(usize::MAX),
            Err(RepairError::StreamingMemoryLimit { .. })
        ));
    }
}
