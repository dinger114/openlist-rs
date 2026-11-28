// rust-embed 把 web/dist 的内容编进二进制，但 cargo 并不知道这些文件是编译输入：
// 只跑 `npm run build` 再 `cargo build` 的话，宿主机上会继续用上一次的嵌入产物
// （dist 的资源名带哈希，目录 mtime 会变，所以盯目录就够）。CI 是全新构建，
// 不受影响；这条只保证本地「改完前端直接 cargo build」拿到的是新页面。
fn main() {
    println!("cargo:rerun-if-changed=web/dist");
}
