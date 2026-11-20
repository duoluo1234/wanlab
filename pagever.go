package main

import "net/http"

// pageVer 界面版本号: 与 index.html 内的 WLVER 必须一致(由补丁脚本同时盖戳)。
// 页面定时比对 /api/pagever, 不一致就自动刷新一次, 避免浏览器缓存旧界面。
const pageVer = "20261119-1952"

func handlePageVer(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ver": pageVer})
}
