//! 虚拟存储（对齐 Go 版 drivers/virtual，测试用途）
//!
//! 列表生成 num_file 个假文件 + num_folder 个假文件夹；
//! Go 版下载返回随机数据流，Rust 版后端按 local_path/URL 流式读取，
//! 无对应能力，故 download 返回明确错误（测试存储不用于真实下载）。

use super::DownloadInfo;
use crate::config::Entry;

pub struct Virtual {
    num_file: u32,
    num_folder: u32,
}

impl Virtual {
    pub fn new(num_file: u32, num_folder: u32) -> Self {
        Virtual { num_file, num_folder }
    }

    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    fn fake_name(&self, is_dir: bool, i: u32) -> String {
        if is_dir {
            format!("virtual_folder_{i}")
        } else {
            format!("virtual_file_{i}.bin")
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        if !parent_fid.is_empty() && parent_fid != "/" && parent_fid != "0" {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for i in 0..self.num_folder {
            out.push(Entry {
                fid: format!("/{}", self.fake_name(true, i)),
                name: self.fake_name(true, i),
                size: 0,
                is_dir: true,
                updated_at: None,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
        for i in 0..self.num_file {
            out.push(Entry {
                fid: format!("/{}", self.fake_name(false, i)),
                name: self.fake_name(false, i),
                size: 1024 * 1024,
                is_dir: false,
                updated_at: None,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        Err("虚拟存储无真实文件（Go 版为随机数据流，Rust 版不支持）".into())
    }

    pub async fn mkdir(&self, _parent_fid: &str, _name: &str) -> Result<(), String> {
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, _e: &Entry, _new_name: &str) -> Result<(), String> {
        Ok(())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, _e: &Entry) -> Result<(), String> {
        Ok(())
    }

    pub async fn put(&self, _dst_dir_fid: &str, _input: super::PutInput) -> Result<(), String> {
        Ok(())
    }
}
