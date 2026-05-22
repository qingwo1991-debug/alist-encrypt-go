# -*- coding: utf-8 -*-
import os
import re

PROXY_PATH = "/root/AI/OpenList-Encrypt/openlist-lib/openlistlib/encrypt/proxy.go"
OUT_DIR = "/root/AI/OpenList-Encrypt/openlist-lib/openlistlib/encrypt"

def main():
    print("Reading proxy.go...")
    with open(PROXY_PATH, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    print(f"Total lines: {len(lines)}")

    # Extract header (package and imports)
    header_lines = []
    in_import = False
    start_of_code = 0
    
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("package "):
            header_lines.append(line)
            continue
        if stripped.startswith("import "):
            header_lines.append(line)
            if "(" in stripped:
                in_import = True
            continue
        if in_import:
            header_lines.append(line)
            if ")" in stripped:
                in_import = False
            continue
        if stripped == "" or stripped.startswith("//") or stripped.startswith("/*"):
            header_lines.append(line)
            continue
        # Code starts here
        start_of_code = idx
        break

    header = "".join(header_lines)
    print(f"Header lines: {len(header_lines)}, Code starts at index {start_of_code}")

    # Now parse declarations starting from start_of_code
    declarations = []
    i = start_of_code
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()
        
        # Look for comments preceding the declaration
        comment_lines = []
        j = i - 1
        while j >= start_of_code:
            prev_line = lines[j].strip()
            if prev_line.startswith("//"):
                comment_lines.insert(0, lines[j])
                j -= 1
            else:
                break
        
        is_decl = False
        decl_type = ""
        decl_name = ""
        block_char_open = ""
        block_char_close = ""
        
        if stripped.startswith("func "):
            is_decl = True
            decl_type = "func"
            m = re.search(r'func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)', stripped)
            if m:
                decl_name = m.group(1)
            block_char_open = "{"
            block_char_close = "}"
        elif stripped.startswith("type ") and ("struct" in stripped or "interface" in stripped or "func" in stripped or "string" in stripped or "int" in stripped):
            is_decl = True
            decl_type = "type"
            m = re.search(r'type\s+([a-zA-Z0-9_]+)', stripped)
            if m:
                decl_name = m.group(1)
            block_char_open = "{"
            block_char_close = "}"
        elif stripped.startswith("const ") or stripped.startswith("var "):
            is_decl = True
            decl_type = "const_var"
            m = re.search(r'(?:const|var)\s+([a-zA-Z0-9_]+|\()', stripped)
            if m:
                decl_name = m.group(1)
            if "(" in stripped and "=" not in stripped:
                block_char_open = "("
                block_char_close = ")"
            elif "{" in stripped or "func" in stripped:
                block_char_open = "{"
                block_char_close = "}"
            else:
                block_char_open = ""
                block_char_close = ""
                
        if is_decl:
            nest_count = 0
            block_lines = []
            block_lines.extend(comment_lines)
            
            start_i = i
            has_started_block = False
            
            while i < n:
                curr_line = lines[i]
                block_lines.append(curr_line)
                
                # Count block delimiters
                if block_char_open:
                    clean_line = re.sub(r'".*?"', '', curr_line)
                    clean_line = re.sub(r'`.*?`', '', clean_line)
                    clean_line = re.sub(r'//.*', '', clean_line)
                    
                    if block_char_open in clean_line:
                        nest_count += clean_line.count(block_char_open)
                        has_started_block = True
                    if block_char_close in clean_line:
                        nest_count -= clean_line.count(block_char_close)
                        
                    if has_started_block and nest_count <= 0:
                        i += 1
                        break
                else:
                    # Single line decl, ends on empty line or next declaration
                    if curr_line.strip() == "":
                        i += 1
                        break
                    if i + 1 < n:
                        next_stripped = lines[i+1].strip()
                        if next_stripped.startswith("func ") or next_stripped.startswith("type ") or next_stripped.startswith("const ") or next_stripped.startswith("var "):
                            i += 1
                            break
                i += 1
                
            declarations.append({
                "type": decl_type,
                "name": decl_name,
                "lines": block_lines,
                "start": start_i,
                "end": i
            })
        else:
            i += 1

    print(f"Found {len(declarations)} declarations.")

    files = {
        "proxy_server.go": [],
        "proxy_alist_api.go": [],
        "proxy_webdav.go": [],
        "proxy_download.go": [],
        "proxy_upload.go": [],
        "proxy_cache.go": [],
        "proxy_path.go": [],
        "proxy_utils.go": [],
        "proxy_prefetch.go": [],
        "proxy_remainder.go": []
    }
    
    for d in declarations:
        name = d["name"]
        lines_str = "".join(d["lines"])
        
        # 1. proxy_server.go
        if name in ["ProxyServer", "NewProxyServer", "UpdateConfig", "Start", "Stop", "ServeHTTP", "ensureRuntimeCaches"]:
            files["proxy_server.go"].append(d)
        elif "func (p *ProxyServer) Start(" in lines_str:
            files["proxy_server.go"].append(d)
        elif "func (p *ProxyServer) Stop(" in lines_str:
            files["proxy_server.go"].append(d)
        elif "func (p *ProxyServer) ServeHTTP(" in lines_str:
            files["proxy_server.go"].append(d)
        elif "func (p *ProxyServer) UpdateConfig(" in lines_str:
            files["proxy_server.go"].append(d)
            
        # 2. proxy_alist_api.go
        elif name.startswith("handleFs") or name.startswith("handleAlist") or name in ["handlePlayStream", "handlePlayStats", "handleStats", "handleLocalState", "handleLocalExport", "handleLocalImport", "handleRestart", "handleSyncOverview", "handleSyncStatsPage", "handleProviderRoutingCandidates", "handleProviderRoutingCandidatesRefresh", "handleConfigV2Schema"]:
            files["proxy_alist_api.go"].append(d)
            
        # 3. proxy_webdav.go
        elif name in ["handleWebDAV", "handlePropfind", "handleGet", "handlePut", "handleCopy", "handleMove", "handleDelete", "webdavNegativeBlocked", "webdavNegativeKey", "webdavNegativeTTL", "shouldRetryPropfind404", "propfindRetryTimeout"]:
            files["proxy_webdav.go"].append(d)
            
        # 4. proxy_download.go
        elif name in ["handleDownload", "streamDecryptResponse", "followRedirectDecrypt", "handleRedirect", "parseRangeStart", "copyWithAdaptiveBuffer"] or "Download" in name or "DecryptResponse" in name:
            files["proxy_download.go"].append(d)
            
        # 5. proxy_upload.go
        elif name in ["handleUpload", "encryptUploadStream"] or "Upload" in name:
            files["proxy_upload.go"].append(d)
            
        # 6. proxy_cache.go
        elif name in ["fileCache", "redirectCache", "loadRedirectCache", "saveRedirectCache", "localKeyFromURLs", "lookupLocalStrategy"] or "Cache" in name:
            files["proxy_cache.go"].append(d)
            
        # 7. proxy_path.go
        elif name in ["findEncryptPath", "matchRoutingRules", "matchBuiltinRouting", "newProxyResolver", "sortRoutingRules"] or "Path" in name or "Routing" in name:
            files["proxy_path.go"].append(d)
            
        # 8. proxy_prefetch.go
        elif "Prefetch" in name or "Warmup" in name or "prefetch" in name.lower() or "warmup" in name.lower():
            files["proxy_prefetch.go"].append(d)
            
        # 9. proxy_utils.go
        elif name in ["clampStreamBufferKB", "clampSeconds", "maskSensitiveValue", "sanitizeURLForDebug", "debugf", "debugEnabled", "upstreamTimeout", "probeTimeout", "probeBudget", "upstreamBackoff", "isLocalOrPrivateHost", "syncMapLen", "copyWithBuffer", "copyWithSmallBuffer"] or name in ["shardedAnyMap", "mapShard", "upstreamHTTPStats", "instrumentedRoundTripper", "ProbeMethodStats"]:
            files["proxy_utils.go"].append(d)
        else:
            files["proxy_remainder.go"].append(d)

    for fname, decls in files.items():
        print(f"  {fname}: {len(decls)} declarations")
    
    # Write files
    for fname, decls in files.items():
        if fname == "proxy_remainder.go":
            out_path = PROXY_PATH
        else:
            out_path = os.path.join(OUT_DIR, fname)
            
        if not decls:
            continue
            
        print(f"Writing {out_path}...")
        decls_sorted = sorted(decls, key=lambda x: x["start"])
        
        content = header + "\n"
        for d in decls_sorted:
            content += "".join(d["lines"]) + "\n"
            
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content)

    print("Splitting complete!")

if __name__ == "__main__":
    main()
