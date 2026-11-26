// SPDX-License-Identifier: CC-BY-4.0

//! Conditional key-value store. `update` is the only conditional primitive and
//! is linearizable; the file-backed store rewrites one JSON snapshot atomically
//! (temp file, fsync, rename) after every successful write.
use scout_wire::{b64, unb64, Error};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Decides the next value from the current one (None = no write).
pub type UpdateFn<'a> = dyn FnMut(Option<&[u8]>) -> Option<Vec<u8>> + 'a;

pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error>;
    /// `f` sees the current value and returns the next one (None = no write).
    /// It runs under the store lock and must not call the store.
    fn update(&self, key: &str, f: &mut UpdateFn) -> Result<(), Error>;
    fn delete(&self, key: &str) -> Result<(), Error>;
    /// Every record, for tests that look for plaintext.
    fn dump(&self) -> BTreeMap<String, Vec<u8>>;
}

#[derive(Default)]
pub struct MemStore {
    m: Mutex<BTreeMap<String, Vec<u8>>>,
    file: Option<PathBuf>,
}

impl MemStore {
    pub fn new() -> MemStore {
        MemStore::default()
    }

    pub fn open_file(path: impl Into<PathBuf>) -> Result<MemStore, Error> {
        let path = path.into();
        let mut m = BTreeMap::new();
        match std::fs::read(&path) {
            Ok(raw) => {
                let enc: BTreeMap<String, String> = serde_json::from_slice(&raw).map_err(|e| Error(format!("store: {e}")))?;
                for (k, v) in enc {
                    m.insert(k, unb64(&v)?);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error(format!("store: {e}"))),
        }
        Ok(MemStore { m: Mutex::new(m), file: Some(path) })
    }

    /// Copy of the contents as a memory-only store.
    pub fn snapshot(&self) -> MemStore {
        MemStore { m: Mutex::new(self.dump()), file: None }
    }

    fn persist(&self, m: &BTreeMap<String, Vec<u8>>) -> Result<(), Error> {
        let Some(path) = &self.file else { return Ok(()) };
        let enc: BTreeMap<&String, String> = m.iter().map(|(k, v)| (k, b64(v))).collect();
        let raw = serde_json::to_vec(&enc).map_err(|e| Error(e.to_string()))?;
        let io = |e: std::io::Error| Error(format!("store: {e}"));
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let tmp = dir.join(format!(".scout-store-{}.tmp", scout_wire::random_id()));
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        std::io::Write::write_all(&mut f, &raw).map_err(io)?;
        f.sync_all().map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)?;
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

impl Store for MemStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.m.lock().map_err(|_| Error("poisoned".into()))?.get(key).cloned())
    }

    fn update(&self, key: &str, f: &mut UpdateFn) -> Result<(), Error> {
        let mut m = self.m.lock().map_err(|_| Error("poisoned".into()))?;
        let old = m.get(key).cloned();
        let Some(next) = f(old.as_deref()) else { return Ok(()) };
        m.insert(key.to_string(), next);
        if let Err(e) = self.persist(&m) {
            match old {
                Some(o) => m.insert(key.to_string(), o),
                None => m.remove(key),
            };
            return Err(e);
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let mut m = self.m.lock().map_err(|_| Error("poisoned".into()))?;
        let Some(old) = m.remove(key) else { return Ok(()) };
        if let Err(e) = self.persist(&m) {
            m.insert(key.to_string(), old);
            return Err(e);
        }
        Ok(())
    }

    fn dump(&self) -> BTreeMap<String, Vec<u8>> {
        self.m.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn incr(cur: Option<&[u8]>) -> Option<Vec<u8>> {
        let n: u32 = cur.and_then(|c| std::str::from_utf8(c).ok()).and_then(|s| s.parse().ok()).unwrap_or(0);
        Some((n + 1).to_string().into_bytes())
    }

    #[test]
    fn concurrent_update_is_linearizable() {
        let dir = std::env::temp_dir().join(format!("scout-store-{}", scout_wire::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stores: Vec<Arc<dyn Store>> = vec![Arc::new(MemStore::new()), Arc::new(MemStore::open_file(dir.join("s.json")).unwrap())];
        for s in stores {
            let hs: Vec<_> = (0..40)
                .map(|_| {
                    let s = s.clone();
                    std::thread::spawn(move || s.update("n", &mut incr).unwrap())
                })
                .collect();
            hs.into_iter().for_each(|h| h.join().unwrap());
            assert_eq!(s.get("n").unwrap().unwrap(), b"40");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn file_store_survives_reload() {
        let dir = std::env::temp_dir().join(format!("scout-store-{}", scout_wire::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.json");
        let s = MemStore::open_file(&p).unwrap();
        s.update("a", &mut |_| Some(b"1".to_vec())).unwrap();
        s.update("b", &mut |_| Some(b"2".to_vec())).unwrap();
        s.update("c", &mut |_| None).unwrap();
        s.delete("b").unwrap();
        let s2 = MemStore::open_file(&p).unwrap();
        assert_eq!(s2.get("a").unwrap().unwrap(), b"1");
        assert!(s2.get("b").unwrap().is_none());
        assert!(s2.get("c").unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }
}
