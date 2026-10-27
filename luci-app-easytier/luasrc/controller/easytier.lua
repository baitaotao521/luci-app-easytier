
module("luci.controller.easytier", package.seeall)
local i18n = require "luci.i18n"

-- 安全执行命令并返回结果
local function safe_exec(cmd)
    local handle = io.popen(cmd)
    if not handle then return "" end
    local result = handle:read("*all") or ""
    handle:close()
    return result:gsub("[\r\n]+$", "")
end

-- 安全读取文件内容
local function safe_read_file(path)
    local file = io.open(path, "r")
    if not file then return nil end
    local content = file:read("*all")
    file:close()
    return content
end

-- 计算运行时长
local function calc_uptime(start_time_file)
    local content = safe_read_file(start_time_file)
    if not content or content == "" then return "" end
    
    local start_time = tonumber(content:match("%d+"))
    if not start_time then return "" end
    
    local now = os.time()
    local elapsed = now - start_time
    
    local days = math.floor(elapsed / 86400)
    local hours = math.floor((elapsed % 86400) / 3600)
    local mins = math.floor((elapsed % 3600) / 60)
    local secs = elapsed % 60
    
    local result = ""
    if days > 0 then result = days .. "天 " end
    result = result .. string.format("%02d小时%02d分%02d秒", hours, mins, secs)
    return result
end

function index()
	if not nixio.fs.access("/etc/config/easytier") then
		return
	end
	
	entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false
	entry({"admin", "vpn", "easytier"}, firstchild(),_("EasyTier"), 46).dependent = true
	entry({"admin", "vpn", "easytier", "status"}, cbi("easytier_status"),_("Status"), 1).leaf = true
	entry({"admin", "vpn", "easytier", "config"}, cbi("easytier"),_("EasyTier Core"), 2).leaf = true
	entry({"admin", "vpn", "easytier", "webconsole"}, template("easytier/easytier_web"),_("EasyTier Web"), 3).leaf = true
	entry({"admin", "vpn", "easytier", "log"}, template("easytier/easytier_log"),_("Logs"), 4).leaf = true
	entry({"admin", "vpn", "easytier", "upload"}, template("easytier/easytier_upload"),_("Upload Program"), 5).leaf = true
	entry({"admin", "vpn", "easytier", "upload_binary"}, call("upload_binary")).leaf = true
	entry({"admin", "vpn", "easytier", "get_upload_config"}, call("get_upload_config")).leaf = true
	entry({"admin", "vpn", "easytier", "save_upload_config"}, call("save_upload_config")).leaf = true
	entry({"admin", "vpn", "easytier", "get_disk_space"}, call("get_disk_space")).leaf = true
	entry({"admin", "vpn", "easytier", "get_tun_info"}, call("get_tun_info")).leaf = true
	entry({"admin", "vpn", "easytier", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "vpn", "easytier", "get_log_size"}, call("get_log_size")).leaf = true
	entry({"admin", "vpn", "easytier", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "vpn", "easytier", "get_wlog"}, call("get_wlog")).leaf = true
	entry({"admin", "vpn", "easytier", "get_wlog_size"}, call("get_wlog_size")).leaf = true
	entry({"admin", "vpn", "easytier", "clear_wlog"}, call("clear_wlog")).leaf = true
	entry({"admin", "vpn", "easytier", "clear_version_cache"}, call("clear_version_cache")).leaf = true
	entry({"admin", "vpn", "easytier", "get_web_config"}, call("get_web_config")).leaf = true
	entry({"admin", "vpn", "easytier", "save_web_config"}, call("save_web_config")).leaf = true
	entry({"admin", "vpn", "easytier", "reset_database"}, call("reset_database")).leaf = true
	entry({"admin", "vpn", "easytier", "check_web_status"}, call("check_web_status")).leaf = true
	entry({"admin", "vpn", "easytier", "api_status"}, call("act_status")).leaf = true
	entry({"admin", "vpn", "easytier", "api_conninfo"}, call("act_conninfo")).leaf = true
	entry({"admin", "vpn", "easytier", "restart_service"}, call("restart_service")).leaf = true
	entry({"admin", "vpn", "easytier", "toggle_core"}, call("toggle_core")).leaf = true
	entry({"admin", "vpn", "easytier", "toggle_web"}, call("toggle_web")).leaf = true
	entry({"admin", "vpn", "easytier", "download_easytier"}, call("download_easytier")).leaf = true
	entry({"admin", "vpn", "easytier", "download_progress"}, call("download_progress")).leaf = true
	entry({"admin", "vpn", "easytier", "cancel_download"}, call("cancel_download")).leaf = true
end

-- Keep CPU samples on disk: LuCI CGI requests may not share a Lua state.
local STATUS_CPU_SAMPLE = "/tmp/easytier-status.cpu"

local function status_processes(corebin, webbin)
	local fs = require "nixio.fs"
	local services = {
		core = { identities = {}, ticks = 0, rss = 0, count = 0 },
		web = { identities = {}, ticks = 0, rss = 0, count = 0 }
	}
	local corename = corebin:match("([^/]+)$") or "easytier-core"
	local webname = webbin:match("([^/]+)$") or "easytier-web"
	local entries = fs.dir("/proc")
	if entries then
		for pid in entries do
			if pid:match("^%d+$") then
				local stat = safe_read_file("/proc/" .. pid .. "/stat")
				local name, fields
				if stat then name, fields = stat:match("^%d+ %((.*)%)%s+(.+)") end
				local service
				if name == "easytier-core" or name == corename:sub(1, 15) then
					service = services.core
				elseif name and (name:match("^easytier%-web") or name == webname:sub(1, 15)) then
					-- Linux comm is truncated to 15 bytes, including easytier-web-embed.
					service = services.web
				end
				if service and fields then
					local index, utime, stime, started = 0
					for value in fields:gmatch("%S+") do
						index = index + 1
						if index == 12 then utime = tonumber(value)
						elseif index == 13 then stime = tonumber(value)
						elseif index == 20 then started = value; break end
					end
					if utime and stime and started and started:match("^%d+$") then
						service.count = service.count + 1
						service.identities[#service.identities + 1] = pid .. ":" .. started
						service.ticks = service.ticks + utime + stime
						local status = safe_read_file("/proc/" .. pid .. "/status") or ""
						service.rss = service.rss + (tonumber(status:match("VmRSS:%s*(%d+)")) or 0)
					end
				end
			end
		end
	end
	for _, service in pairs(services) do
		table.sort(service.identities)
		service.identity = table.concat(service.identities, ",")
		if service.identity == "" then service.identity = "-" end
	end
	return services
end

local function status_cpu(services)
	local stat = safe_read_file("/proc/stat") or ""
	local cpu = stat:match("^cpu%s+([^\n]+)")
	local total, count = 0, 0
	if cpu then
		for value in cpu:gmatch("%d+") do
			count = count + 1
			-- guest/guest_nice are already included in user/nice.
			if count > 8 then break end
			total = total + tonumber(value)
		end
	end
	local uptime = tonumber((safe_read_file("/proc/uptime") or ""):match("^([%d%.]+)"))
	local previous = safe_read_file(STATUS_CPU_SAMPLE) or ""
	local oldtime, oldtotal = previous:match("^v1 ([%d%.]+) (%d+)\n")
	oldtime, oldtotal = tonumber(oldtime), tonumber(oldtotal)
	local valid = count >= 4 and uptime and total > 0
	local elapsed = valid and oldtime and oldtotal and uptime > oldtime and total > oldtotal
	for name, service in pairs(services) do
		service.cpu = ""
		local identity, ticks = previous:match("\n" .. name .. " ([%d:,%-]+) (%d+)\n")
		ticks = tonumber(ticks)
		if elapsed and service.count > 0 and identity == service.identity and ticks and service.ticks >= ticks then
			local percent = (service.ticks - ticks) * 100 / (total - oldtotal)
			service.cpu = string.format("%.1f%%", math.min(percent, 100))
		end
	end
	if valid then
		local content = string.format("v1 %.2f %.0f\ncore %s %.0f\nweb %s %.0f\n",
			uptime, total, services.core.identity, services.core.ticks, services.web.identity, services.web.ticks)
		local temporary = os.tmpname()
		if temporary then
			local file = io.open(temporary, "w")
			if file then
				local written = file:write(content)
				file:close()
				if written then os.rename(temporary, STATUS_CPU_SAMPLE) end
			end
			os.remove(temporary)
		end
	else
		os.remove(STATUS_CPU_SAMPLE)
	end
end

local function status_cached_version(path)
	return (safe_read_file(path) or ""):gsub("[\r\n]+", "")
end

local function status_save_version(path, version)
	if version ~= "" and version ~= "unknown" then
		local file = io.open(path, "w")
		if file then file:write(version); file:close() end
	end
end

local function status_binary_version(path, cached, refresh)
	if refresh and (cached == "" or cached == "unknown") then
		local quoted = "'" .. path:gsub("'", "'\\''") .. "'"
		local output = safe_exec(quoted .. " -V 2>/dev/null")
		cached = output:match("%d[^\r\n]*") or ""
	end
	return cached ~= "" and cached or "unknown"
end

function act_status()
	local e = {}
	local uci = require "luci.model.uci".cursor()
	local corebin = uci:get_first("easytier", "easytier", "easytierbin") or "/usr/bin/easytier-core"
	local webbin = uci:get_first("easytier", "easytier", "webbin") or "/usr/bin/easytier-web"
	local services = status_processes(corebin, webbin)
	status_cpu(services)
	e.crunning = services.core.count > 0
	e.wrunning = services.web.count > 0
	e.port = tonumber(uci:get_first("easytier", "easytier", "web_html_port")) or 0
	e.cenabled = uci:get_first("easytier", "easytier", "enabled") == "1"
	e.wenabled = uci:get_first("easytier", "easytier", "web_enabled") == "1"
	e.etsta = calc_uptime("/tmp/easytier_time")
	e.etwebsta = calc_uptime("/tmp/easytierweb_time")
	e.etcpu = services.core.cpu
	e.etwebcpu = services.web.cpu
	e.etram = e.crunning and string.format("%.2f MB", services.core.rss / 1024) or ""
	e.etwebram = e.wrunning and string.format("%.2f MB", services.web.rss / 1024) or ""

	-- Routine polling never executes binaries or reaches the network.
	local refresh = luci.http.formvalue("versions") == "1"
	e.etnewtag = status_cached_version("/tmp/easytiernew.tag")
	if refresh and e.etnewtag == "" then
		local release = safe_exec("curl -f -L -k -s --connect-timeout 3 --max-time 4 --user-agent 'luci-app-easytier' 'https://api.github.com/repos/EasyTier/EasyTier/releases/latest' 2>/dev/null")
		local tag = release:match('"tag_name"%s*:%s*"([^"]+)"') or ""
		e.etnewtag = tag:match("^[vV]?(%d[^%s]*)$") or ""
		status_save_version("/tmp/easytiernew.tag", e.etnewtag)
	end
	local coretag = status_cached_version("/tmp/easytier.tag")
	local webtag = status_cached_version("/tmp/easytierweb.tag")
	e.ettag = status_binary_version(corebin, coretag, refresh)
	e.etwebtag = status_binary_version(webbin, webtag, refresh)
	if refresh then
		if coretag == "" or coretag == "unknown" then status_save_version("/tmp/easytier.tag", e.ettag) end
		if webtag == "" or webtag == "unknown" then status_save_version("/tmp/easytierweb.tag", e.etwebtag) end
	end
	e.no_tun = uci:get_first("easytier", "easytier", "no_tun") == "1"
	e.dev_name = uci:get_first("easytier", "easytier", "tunname") or "tun0"
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_upload_config()
	local uci = require "luci.model.uci".cursor()
	local http = require "luci.http"
	
	http.prepare_content("application/json")
	
	local config = {
		easytierbin = uci:get_first("easytier", "easytier", "easytierbin") or "/usr/bin/easytier-core",
		webbin = uci:get_first("easytier", "easytier", "webbin") or "/usr/bin/easytier-web",
		github_proxys = {},
		fallback_version = uci:get_first("easytier", "easytier", "fallback_version") or "v2.7.0"
	}
	
	-- 读取代理列表（list 类型）
	uci:foreach("easytier", "easytier", function(s)
		local proxys = s.github_proxys
		if proxys then
			if type(proxys) == "table" then
				config.github_proxys = proxys
			else
				table.insert(config.github_proxys, proxys)
			end
		end
	end)
	
	http.write_json(config)
end

function save_upload_config()
	local uci = require "luci.model.uci".cursor()
	local http = require "luci.http"
	local json = require "luci.jsonc"
	
	http.prepare_content("application/json")
	
	-- 读取 POST 数据
	local content = http.content()
	local data = json.parse(content)
	
	if not data then
		http.write_json({success = false, message = "Invalid JSON data"})
		return
	end
	
	-- 保存配置
	uci:set("easytier", "@easytier[0]", "easytierbin", data.easytierbin or "/usr/bin/easytier-core")
	uci:set("easytier", "@easytier[0]", "webbin", data.webbin or "/usr/bin/easytier-web")
	uci:set("easytier", "@easytier[0]", "fallback_version", data.fallback_version or "v2.7.0")
	
	-- 删除旧的代理列表
	uci:delete("easytier", "@easytier[0]", "github_proxys")
	
	-- 保存代理列表（list 类型）
	if data.github_proxys and type(data.github_proxys) == "table" then
		for _, proxy in ipairs(data.github_proxys) do
			if proxy and proxy ~= "" then
				local current = uci:get("easytier", "@easytier[0]", "github_proxys") or {}
				if type(current) ~= "table" then
					current = {current}
				end
				table.insert(current, proxy)
				uci:set("easytier", "@easytier[0]", "github_proxys", current)
			end
		end
	end
	
	uci:commit("easytier")
	
	http.write_json({success = true, message = "Configuration saved successfully"})
end

function get_disk_space()
	local http = require "luci.http"
	local json = require "luci.jsonc"
	local nixio = require "nixio"
	
	http.prepare_content("application/json")
	
	local content = http.content()
	local data = json.parse(content)
	
	if not data or not data.path then
		http.write_json({success = false, message = "Invalid path"})
		return
	end
	
	local path = data.path
	local full_path = data.full_path
	local input_type = data.type
	
	local df_output = luci.sys.exec("df -h '" .. path .. "' 2>/dev/null | tail -n 1")
	local df_kb = luci.sys.exec("df -k '" .. path .. "' 2>/dev/null | tail -n 1")
	
	if df_output and df_output ~= "" and df_kb and df_kb ~= "" then
		local available = df_output:match("%S+%s+%S+%s+%S+%s+(%S+)")
		local available_kb = df_kb:match("%S+%s+%S+%s+%S+%s+(%d+)")
		local available_mb = available_kb and math.floor(tonumber(available_kb) / 1024) or 0
		
		if available and available_mb then
			local result = {
				success = true,
				available = available,
				available_mb = available_mb
			}
			
			if input_type == "easytierbin" and full_path then
				if nixio.fs.access(full_path) then
					local size = luci.sys.exec("ls -lh '" .. full_path .. "' 2>/dev/null | awk '{print $5}'")
					if size and size ~= "" then
						result.core_size = size:gsub("[\r\n]+$", "")
					end
				end
				
				local dir = full_path:match("(.*/)")
				local cli_path = (dir or "/usr/bin/") .. "easytier-cli"
				if nixio.fs.access(cli_path) then
					local size = luci.sys.exec("ls -lh '" .. cli_path .. "' 2>/dev/null | awk '{print $5}'")
					if size and size ~= "" then
						result.cli_size = size:gsub("[\r\n]+$", "")
					end
				end
			elseif input_type == "webbin" and full_path then
				if nixio.fs.access(full_path) then
					local size = luci.sys.exec("ls -lh '" .. full_path .. "' 2>/dev/null | awk '{print $5}'")
					if size and size ~= "" then
						result.web_size = size:gsub("[\r\n]+$", "")
					end
				end
			end
			
			http.write_json(result)
			return
		end
	end
	
	http.write_json({success = false, message = "Unable to query disk space"})
end

function get_tun_info()
	luci.http.prepare_content("application/json")
	local nixio = require "nixio"
	local fs = require "nixio.fs"
	local ifname = luci.http.formvalue("ifname") or "tun0"
	if ifname == "" or ifname:find("/", 1, true) or not fs.access("/sys/class/net/" .. ifname) then
		luci.http.write_json({success = true, exists = false})
		return
	end
	local base = "/sys/class/net/" .. ifname .. "/"
	local response = {
		success = true,
		exists = true,
		ip = "",
		netmask = "",
		mtu = (safe_read_file(base .. "mtu") or ""):match("%d+") or "",
		state = "UNKNOWN",
		rx_bytes = tonumber(safe_read_file(base .. "statistics/rx_bytes")) or 0,
		tx_bytes = tonumber(safe_read_file(base .. "statistics/tx_bytes")) or 0
	}
	local flags = tonumber((safe_read_file(base .. "flags") or ""):match("[%da-fA-Fx]+"))
	if flags then response.state = flags % 2 == 1 and "UP" or "DOWN" end
	for _, address in ipairs(nixio.getifaddrs() or {}) do
		if address.name == ifname then
			if address.family == "inet" and response.ip == "" then
				response.ip = address.addr or ""
				response.netmask = address.netmask or ""
			elseif address.family == "inet6" and not response.ipv6 and address.addr then
				response.ipv6 = address.addr .. (address.prefix and "/" .. address.prefix or "")
			end
		end
	end
	luci.http.write_json(response)
end

function get_log()
    local log = ""
    local files = {"/tmp/easytier.log"}
    for i, file in ipairs(files) do
        if luci.sys.call("[ -f '" .. file .. "' ]") == 0 then
            log = log .. luci.sys.exec("sed 's/\\x1b\\[[0-9;]*m//g' " .. file)
        end
    end
    luci.http.write(log)
end

function get_log_size()
    local size = luci.sys.exec("[ -f '/tmp/easytier.log' ] && stat -c%s /tmp/easytier.log 2>/dev/null || echo 0")
    luci.http.prepare_content("application/json")
    luci.http.write_json({size = tonumber(size) or 0})
end

function get_wlog_size()
    local size = luci.sys.exec("[ -f '/tmp/easytierweb.log' ] && stat -c%s /tmp/easytierweb.log 2>/dev/null || echo 0")
    luci.http.prepare_content("application/json")
    luci.http.write_json({size = tonumber(size) or 0})
end

function clear_log()
	luci.sys.call("echo '' >/tmp/easytier.log")
end

local function test_binary(path)
	local handle = io.popen(path .. " -h 2>&1")
	local output = handle:read("*a")
	handle:close()
	
	local line_count = 0
	for _ in output:gmatch("[^\r\n]+") do
		line_count = line_count + 1
	end
	
	return line_count >= 3 and output:lower():match("easytier")
end

local function cleanup_files(...)
	for _, file in ipairs({...}) do
		nixio.fs.remove(file)
	end
end

function upload_binary()
	local http = require "luci.http"
	local uci = require "luci.model.uci".cursor()
	local nixio = require "nixio"
	local translate = i18n.translate
	
	local fp
	local filename = ""
	local tmp_file = ""
	
	http.setfilehandler(
		function(meta, chunk, eof)
			if meta and meta.file then
				filename = meta.file
				tmp_file = "/tmp/upload_" .. filename
			end
			if not fp and tmp_file ~= "" then
				fp = io.open(tmp_file, "w")
			end
			if chunk and fp then
				fp:write(chunk)
			end
			if eof and fp then
				fp:close()
			end
		end
	)
	
	http.prepare_content("application/json")
	
	if not http.formvalue("file") or tmp_file == "" then
		http.write_json({success = false, message = translate("No file uploaded")})
		return
	end
	
	local is_archive = filename:match("%.zip$") or filename:match("%.tar%.gz$") or filename:match("%.tgz$") or filename:match("%.tar$")
	
	if is_archive then
		local extract_dir = "/tmp/easytier_extract"
		os.execute("rm -rf " .. extract_dir .. " && mkdir -p " .. extract_dir)
		
		if filename:match("%.zip$") then
			if os.execute("which unzip >/dev/null 2>&1") ~= 0 then
				cleanup_files(tmp_file)
				http.write_json({success = false, message = translate("System lacks unzip package, cannot extract zip archive")})
				return
			end
			os.execute("unzip -o -q " .. tmp_file .. " -d " .. extract_dir)
		else
			os.execute("tar -xzf " .. tmp_file .. " -C " .. extract_dir .. " 2>/dev/null || tar -xf " .. tmp_file .. " -C " .. extract_dir)
		end
		
		os.execute("find " .. extract_dir .. "/easytier-linux-* -maxdepth 1 -type f -exec mv {} " .. extract_dir .. "/ \\; 2>/dev/null")
		cleanup_files(tmp_file)
		
		if nixio.fs.access(extract_dir .. "/easytier-web") then
			nixio.fs.remove(extract_dir .. "/easytier-web")
		end
		
		local binaries = {"easytier-core", "easytier-cli", "easytier-web-embed"}
		local valid_bins = {}
		
		for _, bin in ipairs(binaries) do
			local src = extract_dir .. "/" .. bin
			if nixio.fs.access(src) then
				nixio.fs.chmod(src, "755")
				if test_binary(src) then
					table.insert(valid_bins, {name = bin, path = src})
				else
					cleanup_files(src)
				end
			end
		end
		
		if #valid_bins == 0 then
			os.execute("rm -rf " .. extract_dir)
			http.write_json({success = false, message = translate("Not a valid EasyTier program or architecture mismatch")})
			return
		end
		
		local core_path = uci:get_first("easytier", "easytier", "easytierbin") or "/usr/bin/easytier-core"
		local web_path = uci:get_first("easytier", "easytier", "webbin") or "/usr/bin/easytier-web"
		
		for _, bin in ipairs(valid_bins) do
			local final_path
			if bin.name == "easytier-web-embed" then
				final_path = web_path
			elseif bin.name == "easytier-core" then
				final_path = core_path
			elseif bin.name == "easytier-cli" then
				local core_dir = core_path:match("(.*/)")
				final_path = (core_dir or "/usr/bin/") .. "easytier-cli"
			end
			
			os.execute("rm -f " .. final_path)
			
			if os.execute("mv " .. bin.path .. " " .. final_path) ~= 0 then
				os.execute("rm -rf " .. extract_dir)
				http.write_json({success = false, message = translate("Failed to move file. Insufficient space or permission denied")})
				return
			end
			
			os.execute("chmod 755 " .. final_path)
			if not test_binary(final_path) then
				os.execute("rm -f " .. final_path)
				os.execute("rm -rf " .. extract_dir)
				http.write_json({success = false, message = translate("Not a valid EasyTier program or architecture mismatch")})
				return
			end
		end
		
		os.execute("rm -rf " .. extract_dir)
		nixio.fs.remove("/tmp/easytier.tag")
		nixio.fs.remove("/tmp/easytierweb.tag")
		http.write_json({success = true, message = translate("Successfully installed") .. " " .. #valid_bins .. " " .. translate("binary file(s)")})
	else
		local valid_names = {["easytier-core"] = true, ["easytier-cli"] = true, ["easytier-web-embed"] = true, ["easytier-web"] = true}
		
		if not valid_names[filename] then
			cleanup_files(tmp_file)
			http.write_json({success = false, message = translate("Not a valid EasyTier program")})
			return
		end
		
		if filename == "easytier-web" then
			cleanup_files(tmp_file)
			http.write_json({success = false, message = translate("easytier-web is not used by this plugin, please upload easytier-web-embed")})
			return
		end
		
		nixio.fs.chmod(tmp_file, "755")
		if not test_binary(tmp_file) then
			cleanup_files(tmp_file)
			http.write_json({success = false, message = translate("Not a valid EasyTier program or architecture mismatch")})
			return
		end
		
		local core_path = uci:get_first("easytier", "easytier", "easytierbin") or "/usr/bin/easytier-core"
		local web_path = uci:get_first("easytier", "easytier", "webbin") or "/usr/bin/easytier-web"
		
		local final_path
		if filename == "easytier-web-embed" then
			final_path = web_path
		elseif filename == "easytier-core" then
			final_path = core_path
		elseif filename == "easytier-cli" then
			local core_dir = core_path:match("(.*/)")
			final_path = (core_dir or "/usr/bin/") .. "easytier-cli"
		end
		
		os.execute("rm -f " .. final_path)
		
		if os.execute("mv " .. tmp_file .. " " .. final_path) ~= 0 then
			cleanup_files(tmp_file)
			http.write_json({success = false, message = translate("Failed to move file. Insufficient space or permission denied")})
			return
		end
		
		os.execute("chmod 755 " .. final_path)
		if not test_binary(final_path) then
			os.execute("rm -f " .. final_path)
			http.write_json({success = false, message = translate("Not a valid EasyTier program or architecture mismatch")})
			return
		end
		
		nixio.fs.remove("/tmp/easytier.tag")
		nixio.fs.remove("/tmp/easytierweb.tag")
		http.write_json({success = true, message = translate("Binary uploaded successfully to") .. " " .. final_path})
	end
end

function get_wlog()
    local log = ""
    local files = {"/tmp/easytierweb.log"}
    for i, file in ipairs(files) do
        if luci.sys.call("[ -f '" .. file .. "' ]") == 0 then
            log = log .. luci.sys.exec("sed 's/\\x1b\\[[0-9;]*m//g' " .. file)
        end
    end
    luci.http.write(log)
end

function clear_wlog()
	luci.sys.call("echo '' >/tmp/easytierweb.log")
end

function clear_version_cache()
	local type = luci.http.formvalue("type")
	if type == "core" then
		luci.sys.call("rm -f /tmp/easytiernew.tag /tmp/easytier.tag")
	elseif type == "web" then
		luci.sys.call("rm -f /tmp/easytiernew.tag /tmp/easytierweb.tag")
	end
	luci.http.write("OK")
end

-- Load only the visible diagnostic; each CLI invocation starts a new process.
local CONNINFO_CLI_PARTS = {
	node = "node",
	peer = "peer",
	route = "route",
	connector = "connector",
	stun = "stun",
	peer_center = "peer-center",
	vpn_portal = "vpn-portal",
	proxy = "proxy",
	acl = "acl stats",
	mapped_listener = "mapped-listener",
	stats = "stats",
}
-- cmdline 只读本地 /proc，不需要 easytier-cli
local CONNINFO_LOCAL_PARTS = { cmdline = true }

-- 分区结果的短时缓存，避免轮询与手动刷新、来回切换分区时重复起进程
local CONNINFO_CACHE_DIR = "/tmp/easytier_conninfo"
local CONNINFO_CACHE_TTL = 3

local function conninfo_process(binary)
	local fs = require "nixio.fs"
	local entries = fs.dir("/proc")
	local name = (binary:match("([^/]+)$") or "easytier-core"):sub(1, 15)
	if entries then
		for pid in entries do
			if pid:match("^%d+$") then
				local stat = safe_read_file("/proc/" .. pid .. "/stat") or ""
				local comm, fields = stat:match("^%d+ %((.*)%)%s+(.+)")
				if comm == name or comm == "easytier-core" then
					local index = 0
					for value in fields:gmatch("%S+") do
						index = index + 1
						if index == 20 then return pid, pid .. ":" .. value end
					end
				end
			end
		end
	end
end

local function read_conninfo_cache(name, instance)
	local content = safe_read_file(CONNINFO_CACHE_DIR .. "/" .. name) or ""
	local ts, cached_instance, data = content:match("^(%d+)\n([^\n]+)\n([%s%S]*)$")
	local age = ts and os.time() - tonumber(ts)
	local ttl = name == "stun" and 60 or CONNINFO_CACHE_TTL
	if not age or age < 0 or age > ttl or cached_instance ~= instance then return nil end
	return data
end

local function write_conninfo_cache(name, instance, data)
	local fs = require "nixio.fs"
	fs.mkdir(CONNINFO_CACHE_DIR)
	local temporary = os.tmpname()
	if not temporary then return end
	local handle = io.open(temporary, "w")
	if handle then
		local written = handle:write(tostring(os.time()) .. "\n" .. instance .. "\n" .. data)
		handle:close()
		if written then os.rename(temporary, CONNINFO_CACHE_DIR .. "/" .. name) end
	end
	os.remove(temporary)
end

function act_conninfo()
	local e = {}
	local uci = require "luci.model.uci".cursor()
	local easytierbin = uci:get_first("easytier", "easytier", "easytierbin") or "/usr/bin/easytier-core"
	local clibin = (easytierbin:match("(.*/)") or "/usr/bin/") .. "easytier-cli"
	local quoted_cli = "'" .. clibin:gsub("'", "'\\''") .. "'"
	local parts = luci.http.formvalue("parts") or "peer"
	local refresh = luci.http.formvalue("refresh") == "1"
	local want_cli, want_local = {}, {}
	for name in parts:gmatch("[%w_]+") do
		if CONNINFO_CLI_PARTS[name] then want_cli[name] = true
		elseif CONNINFO_LOCAL_PARTS[name] then want_local[name] = true end
	end

	local pid, instance = conninfo_process(easytierbin)
	if pid then
		for name in pairs(want_cli) do
			local cached = not refresh and read_conninfo_cache(name, instance)
			if cached then
				e[name] = cached
			else
				local handle = io.popen(quoted_cli .. " " .. CONNINFO_CLI_PARTS[name] .. " 2>&1")
				local result = ""
				if handle then
					result = handle:read("*all") or ""
					handle:close()
				end
				e[name] = result
				write_conninfo_cache(name, instance, result)
			end
		end

		if want_local.cmdline then
			e.cmdline = (safe_read_file("/proc/" .. pid .. "/cmdline") or ""):gsub("%z", " ")

			-- 检查是否使用配置文件启动，配置内容随本次响应一起返回，前端无需再请求一次
			if e.cmdline:match("%-%-config%-file") or e.cmdline:match("%-c%s+/") then
				e.config_file = safe_read_file("/etc/easytier/config.toml") or ""
			else
				e.config_file = ""
			end
		end
	else
		local errMsg = i18n.translate("Error: Program not running! Please start the program and refresh")
		for name in pairs(want_cli) do
			e[name] = errMsg
		end
		if want_local.cmdline then
			e.cmdline = errMsg
		end
		-- Caches belong to a PID/start-time identity; a restarted core cannot reuse them.
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end


function get_web_config()
	luci.http.prepare_content("application/json")
	local uci = require "luci.model.uci".cursor()
	
	local config = {
		web_enabled = uci:get_first("easytier", "easytier", "web_enabled") or "0",
		web_db_path = uci:get_first("easytier", "easytier", "web_db_path") or "/etc/easytier/et.db",
		web_protocol = uci:get_first("easytier", "easytier", "web_protocol") or "udp",
		web_port = uci:get_first("easytier", "easytier", "web_port") or "22020",
		web_fw_web = uci:get_first("easytier", "easytier", "web_fw_web") or "0",
		web_api_port = uci:get_first("easytier", "easytier", "web_api_port") or "11211",
		web_html_port = uci:get_first("easytier", "easytier", "web_html_port") or "11211",
		web_api_addr = uci:get_first("easytier", "easytier", "web_api_addr") or "0.0.0.0",
		web_html_addr = uci:get_first("easytier", "easytier", "web_html_addr") or "0.0.0.0",
		web_fw_api = uci:get_first("easytier", "easytier", "web_fw_api") or "0",
		web_api_host = uci:get_first("easytier", "easytier", "web_api_host") or "",
		web_geoip_db = uci:get_first("easytier", "easytier", "web_geoip_db") or "",
		web_disable_registration = uci:get_first("easytier", "easytier", "web_disable_registration") or "0",
		web_allow_auto_create_user = uci:get_first("easytier", "easytier", "web_allow_auto_create_user") or "0",
		-- EasyTier 2.7.0 新增的 web 参数
		web_heartbeat_min_response_ms = uci:get_first("easytier", "easytier", "web_heartbeat_min_response_ms") or "",
		web_heartbeat_timeout_ms = uci:get_first("easytier", "easytier", "web_heartbeat_timeout_ms") or "",
		web_gateway_peer_url = uci:get_first("easytier", "easytier", "web_gateway_peer_url") or "",
		web_gateway_relay_data = uci:get_first("easytier", "easytier", "web_gateway_relay_data") or "0",
		web_weblog = uci:get_first("easytier", "easytier", "web_weblog") or "off",
		-- OIDC配置
		web_oidc_enabled = uci:get_first("easytier", "easytier", "web_oidc_enabled") or "0",
		web_oidc_issuer_url = uci:get_first("easytier", "easytier", "web_oidc_issuer_url") or "",
		web_oidc_client_id = uci:get_first("easytier", "easytier", "web_oidc_client_id") or "",
		web_oidc_client_secret = uci:get_first("easytier", "easytier", "web_oidc_client_secret") or "",
		web_oidc_redirect_url = uci:get_first("easytier", "easytier", "web_oidc_redirect_url") or "",
		web_oidc_username_claim = uci:get_first("easytier", "easytier", "web_oidc_username_claim") or "preferred_username",
		web_oidc_scopes = uci:get_first("easytier", "easytier", "web_oidc_scopes") or "openid profile",
		web_oidc_frontend_base_url = uci:get_first("easytier", "easytier", "web_oidc_frontend_base_url") or "",
		web_oidc_disable_pkce = uci:get_first("easytier", "easytier", "web_oidc_disable_pkce") or "0",
		-- Webhook配置
		web_webhook_enabled = uci:get_first("easytier", "easytier", "web_webhook_enabled") or "0",
		web_webhook_url = uci:get_first("easytier", "easytier", "web_webhook_url") or "",
		web_webhook_secret = uci:get_first("easytier", "easytier", "web_webhook_secret") or "",
		web_internal_auth_token = uci:get_first("easytier", "easytier", "web_internal_auth_token") or "",
		web_web_instance_id = uci:get_first("easytier", "easytier", "web_web_instance_id") or "",
		web_web_instance_api_base_url = uci:get_first("easytier", "easytier", "web_web_instance_api_base_url") or ""
	}
	
	luci.http.write_json(config)
end

function save_web_config()
	local uci = require "luci.model.uci".cursor()
	local http = require "luci.http"
	
	local web_enabled = http.formvalue("web_enabled") or "0"
	local web_db_path = http.formvalue("web_db_path") or "/etc/easytier/et.db"
	local web_protocol = http.formvalue("web_protocol") or "udp"
	local web_port = http.formvalue("web_port") or "22020"
	local web_fw_web = http.formvalue("web_fw_web") or "0"
	local web_api_port = http.formvalue("web_api_port") or "11211"
	local web_html_port = http.formvalue("web_html_port") or "11211"
	local web_api_addr = http.formvalue("web_api_addr") or "0.0.0.0"
	local web_html_addr = http.formvalue("web_html_addr") or "0.0.0.0"
	local web_fw_api = http.formvalue("web_fw_api") or "0"
	local web_api_host = http.formvalue("web_api_host") or ""
	local web_geoip_db = http.formvalue("web_geoip_db") or ""
	local web_disable_registration = http.formvalue("web_disable_registration") or "0"
	local web_allow_auto_create_user = http.formvalue("web_allow_auto_create_user") or "0"
	-- EasyTier 2.7.0 新增的 web 参数
	local web_heartbeat_min_response_ms = http.formvalue("web_heartbeat_min_response_ms") or ""
	local web_heartbeat_timeout_ms = http.formvalue("web_heartbeat_timeout_ms") or ""
	local web_gateway_peer_url = http.formvalue("web_gateway_peer_url") or ""
	local web_gateway_relay_data = http.formvalue("web_gateway_relay_data") or "0"
	local web_weblog = http.formvalue("web_weblog") or "off"
	-- OIDC
	local web_oidc_enabled = http.formvalue("web_oidc_enabled") or "0"
	local web_oidc_issuer_url = http.formvalue("web_oidc_issuer_url") or ""
	local web_oidc_client_id = http.formvalue("web_oidc_client_id") or ""
	local web_oidc_client_secret = http.formvalue("web_oidc_client_secret") or ""
	local web_oidc_redirect_url = http.formvalue("web_oidc_redirect_url") or ""
	local web_oidc_username_claim = http.formvalue("web_oidc_username_claim") or "preferred_username"
	local web_oidc_scopes = http.formvalue("web_oidc_scopes") or "openid profile"
	local web_oidc_frontend_base_url = http.formvalue("web_oidc_frontend_base_url") or ""
	local web_oidc_disable_pkce = http.formvalue("web_oidc_disable_pkce") or "0"
	-- Webhook
	local web_webhook_enabled = http.formvalue("web_webhook_enabled") or "0"
	local web_webhook_url = http.formvalue("web_webhook_url") or ""
	local web_webhook_secret = http.formvalue("web_webhook_secret") or ""
	local web_internal_auth_token = http.formvalue("web_internal_auth_token") or ""
	local web_web_instance_id = http.formvalue("web_web_instance_id") or ""
	local web_web_instance_api_base_url = http.formvalue("web_web_instance_api_base_url") or ""
	
	uci:set("easytier", "@easytier[0]", "web_enabled", web_enabled)
	uci:set("easytier", "@easytier[0]", "web_db_path", web_db_path)
	uci:set("easytier", "@easytier[0]", "web_protocol", web_protocol)
	uci:set("easytier", "@easytier[0]", "web_port", web_port)
	uci:set("easytier", "@easytier[0]", "web_fw_web", web_fw_web)
	uci:set("easytier", "@easytier[0]", "web_api_port", web_api_port)
	uci:set("easytier", "@easytier[0]", "web_html_port", web_html_port)
	uci:set("easytier", "@easytier[0]", "web_api_addr", web_api_addr)
	uci:set("easytier", "@easytier[0]", "web_html_addr", web_html_addr)
	uci:set("easytier", "@easytier[0]", "web_fw_api", web_fw_api)
	uci:set("easytier", "@easytier[0]", "web_api_host", web_api_host)
	uci:set("easytier", "@easytier[0]", "web_geoip_db", web_geoip_db)
	uci:set("easytier", "@easytier[0]", "web_disable_registration", web_disable_registration)
	uci:set("easytier", "@easytier[0]", "web_allow_auto_create_user", web_allow_auto_create_user)
	-- EasyTier 2.7.0 新增的 web 参数
	uci:set("easytier", "@easytier[0]", "web_heartbeat_min_response_ms", web_heartbeat_min_response_ms)
	uci:set("easytier", "@easytier[0]", "web_heartbeat_timeout_ms", web_heartbeat_timeout_ms)
	uci:set("easytier", "@easytier[0]", "web_gateway_peer_url", web_gateway_peer_url)
	uci:set("easytier", "@easytier[0]", "web_gateway_relay_data", web_gateway_relay_data)
	uci:set("easytier", "@easytier[0]", "web_weblog", web_weblog)
	-- OIDC
	uci:set("easytier", "@easytier[0]", "web_oidc_enabled", web_oidc_enabled)
	uci:set("easytier", "@easytier[0]", "web_oidc_issuer_url", web_oidc_issuer_url)
	uci:set("easytier", "@easytier[0]", "web_oidc_client_id", web_oidc_client_id)
	uci:set("easytier", "@easytier[0]", "web_oidc_client_secret", web_oidc_client_secret)
	uci:set("easytier", "@easytier[0]", "web_oidc_redirect_url", web_oidc_redirect_url)
	uci:set("easytier", "@easytier[0]", "web_oidc_username_claim", web_oidc_username_claim)
	uci:set("easytier", "@easytier[0]", "web_oidc_scopes", web_oidc_scopes)
	uci:set("easytier", "@easytier[0]", "web_oidc_frontend_base_url", web_oidc_frontend_base_url)
	uci:set("easytier", "@easytier[0]", "web_oidc_disable_pkce", web_oidc_disable_pkce)
	-- Webhook
	uci:set("easytier", "@easytier[0]", "web_webhook_enabled", web_webhook_enabled)
	uci:set("easytier", "@easytier[0]", "web_webhook_url", web_webhook_url)
	uci:set("easytier", "@easytier[0]", "web_webhook_secret", web_webhook_secret)
	uci:set("easytier", "@easytier[0]", "web_internal_auth_token", web_internal_auth_token)
	uci:set("easytier", "@easytier[0]", "web_web_instance_id", web_web_instance_id)
	uci:set("easytier", "@easytier[0]", "web_web_instance_api_base_url", web_web_instance_api_base_url)
	
	uci:commit("easytier")
	
	http.prepare_content("application/json")
	http.write_json({success = true})
end

function reset_database()
	luci.http.prepare_content("application/json")
	
	local json = require "luci.jsonc"
	local nixio = require "nixio"
	
	-- 从请求中获取数据库路径
	local req_data = json.parse(luci.http.content())
	if not req_data or not req_data.db_path then
		luci.http.write_json({success = false, message = "Missing db_path parameter"})
		return
	end
	
	local db_path = req_data.db_path
	
	-- 安全检查：路径必须是绝对路径且不能是根目录或系统关键目录
	if not db_path:match("^/") or db_path == "/" or 
	   db_path:match("^/bin") or db_path:match("^/sbin") or 
	   db_path:match("^/usr/bin") or db_path:match("^/usr/sbin") or
	   db_path:match("^/lib") or db_path:match("^/boot") then
		luci.http.write_json({success = false, message = "Invalid database path"})
		return
	end
	
	-- 构建要删除的文件列表
	local files_to_delete = {
		db_path,
		db_path .. "-wal",
		db_path .. "-shm"
	}
	
	local deleted_files = {}
	
	-- 删除文件
	for _, file in ipairs(files_to_delete) do
		if nixio.fs.access(file) then
			local result = os.remove(file)
			if result then
				table.insert(deleted_files, file)
			end
		end
	end
	
	if #deleted_files > 0 then
		luci.http.write_json({
			success = true,
			deleted_files = deleted_files,
			message = "Database reset successfully"
		})
	else
		luci.http.write_json({
			success = false,
			message = "No database files found or deletion failed"
		})
	end
end

function check_web_status()
	local running = luci.sys.call("pgrep easytier-web >/dev/null") == 0
	local uci = require "luci.model.uci".cursor()
	local port = uci:get_first("easytier", "easytier", "web_html_port") or "11211"
	
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		running = running,
		port = port
	})
end

function restart_service()
	luci.http.prepare_content("application/json")
	luci.sys.exec("/etc/init.d/easytier restart >/dev/null 2>&1 &")
	luci.http.write_json({success = true})
end

function toggle_core()
	local enabled = luci.http.formvalue("enabled")
	local uci = require "luci.model.uci".cursor()
	uci:set("easytier", uci:get_first("easytier", "easytier"), "enabled", enabled)
	uci:commit("easytier")
	
	if enabled == "1" then
		luci.sys.exec("/etc/init.d/easytier start >/dev/null 2>&1 &")
	else
		luci.sys.exec("/etc/init.d/easytier restart >/dev/null 2>&1 &")
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json({success = true})
end

function toggle_web()
	local enabled = luci.http.formvalue("enabled")
	local uci = require "luci.model.uci".cursor()
	uci:set("easytier", uci:get_first("easytier", "easytier"), "web_enabled", enabled)
	uci:commit("easytier")
	
	if enabled == "1" then
		luci.sys.exec("/etc/init.d/easytier start >/dev/null 2>&1 &")
	else
		luci.sys.exec("/etc/init.d/easytier restart >/dev/null 2>&1 &")
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json({success = true})
end
-- 检测CPU架构
local function detect_arch()
	local cputype = safe_exec("uname -ms | tr ' ' '_' | tr '[A-Z]' '[a-z]'")
	local cpucore = ""
	
	if cputype:match("linux.*armv.*") then
		cpucore = "arm"
	end
	if cputype:match("linux.*armv7.*") and safe_exec("cat /proc/cpuinfo | grep vfp") ~= "" then
		cpucore = "armv7"
	end
	if cputype:match("linux.*aarch64.*") or cputype:match("linux.*armv8.*") then
		cpucore = "aarch64"
	end
	if cputype:match("linux.*86.*") then
		cpucore = "i386"
	end
	if cputype:match("linux.*86_64.*") then
		cpucore = "x86_64"
	end
	if cputype:match("linux.*mips.*") then
		local mipstype = safe_exec("echo -n I | hexdump -o 2>/dev/null | awk '{ print substr($2,6,1); exit}'")
		if mipstype == "0" then
			cpucore = "mips"
		else
			cpucore = "mipsel"
		end
	end
	
	return cpucore
end

-- 检查依赖
local function check_dependencies()
	local arch = detect_arch()
	if arch == "" then
		return false, i18n.translate("Unable to detect CPU architecture")
	end
	if arch == "i386" then
		return false, i18n.translate("No x86-32bit program available")
	end
	if safe_exec("which unzip") == "" then
		return false, i18n.translate("System lacks unzip, cannot download and extract")
	end
	return true, arch
end

-- 获取GitHub镜像列表
local function get_github_proxies()
	local uci = require "luci.model.uci".cursor()
	local proxies = {}
	
	-- 从UCI配置读取代理列表
	local proxy_list = uci:get("easytier", "@easytier[0]", "github_proxys")
	
	if proxy_list then
		if type(proxy_list) == "table" then
			-- 多个代理
			for _, proxy in ipairs(proxy_list) do
				if proxy and proxy ~= "" then
					table.insert(proxies, proxy)
				end
			end
		else
			-- 单个代理
			if proxy_list ~= "" then
				table.insert(proxies, proxy_list)
			end
		end
	end
	
	-- 如果没有配置代理，使用默认值
	if #proxies == 0 then
		proxies = {
			"https://ghproxy.net/",
			"https://gh-proxy.com/",
			"https://cdn.gh-proxy.com/",
			"https://ghfast.top/"
		}
	end
	
	-- 添加不使用代理的选项（空字符串表示直连）
	table.insert(proxies, "")
	
	return proxies
end

-- 下载文件
local function download_file(url, output_path, progress_callback)
	local download_tools = {"curl", "wget"}
	
	for _, tool in ipairs(download_tools) do
		if safe_exec("which " .. tool) ~= "" then
			local cmd = ""
			if tool == "curl" then
				cmd = string.format("curl -L -k --connect-timeout 30 --max-time 300 -o '%s' '%s'", output_path, url)
			elseif tool == "wget" then
				cmd = string.format("wget --no-check-certificate --timeout=30 --tries=3 -O '%s' '%s'", output_path, url)
			end
			
			if progress_callback then
				progress_callback(50, i18n.translate("Downloading with") .. " " .. tool .. "...")
			end
			
			local result = os.execute(cmd)
			if result == 0 and nixio.fs.access(output_path) then
				-- 检查文件大小，确保下载完整
				local stat = nixio.fs.stat(output_path)
				if stat and stat.size > 3 * 1024 * 1024 then -- 至少3MB
					return true
				end
			end
		end
	end
	
	return false
end

function download_easytier()
	luci.http.prepare_content("application/json")
	
	local json = require "luci.jsonc"
	local progress_file = "/tmp/easytier_download_progress"
	
	-- 检查是否已有下载任务
	local existing_progress = safe_read_file(progress_file)
	if existing_progress then
		local progress_data = json.parse(existing_progress)
		if progress_data and progress_data.progress > 0 and progress_data.progress < 100 and not progress_data.error then
			luci.http.write_json({
				success = true,
				progress = progress_data.progress,
				message = i18n.translate("Download task already exists"),
				url = progress_data.url or ""
			})
			return
		end
	end
	
	local req_data = json.parse(luci.http.content())
	if not req_data or not req_data.version then
		luci.http.write_json({success = false, message = i18n.translate("Missing version parameter")})
		return
	end
	
	local version = req_data.version
	
	-- 1. 检查依赖和架构
	local ok, arch_or_error = check_dependencies()
	if not ok then
		luci.http.write_json({success = false, message = arch_or_error})
		return
	end
	
	local arch = arch_or_error
	local proxies = get_github_proxies()
	local download_dir = "/tmp/easytier_download"
	local zip_file = download_dir .. "/easytier-linux-" .. arch .. "-" .. version .. ".zip"
	
	-- 创建下载目录
	os.execute("mkdir -p " .. download_dir)
	
	-- 创建取消标志文件
	local cancel_file = "/tmp/easytier_download_cancel"
	os.execute("rm -f " .. cancel_file)
	
	-- 创建进度文件标记任务开始
	local f = io.open(progress_file, "w")
	if f then
		f:write(json.stringify({
			progress = 1,
			message = "Downloading...",
			url = "",
			error = false
		}))
		f:close()
	end
	
	-- 检查是否被取消
	local function check_cancelled()
		return nixio.fs.access(cancel_file)
	end
	
	-- 2. 循环尝试不同的镜像地址下载、解压、验证
	local download_success = false
	local download_url = ""
	local core_file, cli_file, web_file
	
	for _, proxy in ipairs(proxies) do
		-- 检查是否被取消
		if check_cancelled() then
			os.execute("rm -rf " .. download_dir)
			os.execute("rm -f " .. progress_file)
			luci.http.write_json({success = false, message = i18n.translate("Download cancelled")})
			return
		end
		
		download_url = proxy .. "https://github.com/EasyTier/EasyTier/releases/download/" .. version .. "/easytier-linux-" .. arch .. "-" .. version .. ".zip"
		
		-- 删除之前的失败文件
		os.execute("rm -f " .. zip_file)
		os.execute("rm -rf " .. download_dir .. "/extracted")
		
		-- 下载
		if download_file(download_url, zip_file) then
			local stat = nixio.fs.stat(zip_file)
			if stat and stat.size > 10240 then
				-- 检查是否被取消
				if check_cancelled() then
					os.execute("rm -rf " .. download_dir)
					os.execute("rm -f " .. progress_file)
					luci.http.write_json({success = false, message = i18n.translate("Download cancelled")})
					return
				end
				
				-- 解压
				local extract_dir = download_dir .. "/extracted"
				os.execute("mkdir -p " .. extract_dir)
				local unzip_result = os.execute("cd " .. extract_dir .. " && unzip -o " .. zip_file .. " >/dev/null 2>&1")
				
				if unzip_result == 0 then
					-- 检查是否被取消
					if check_cancelled() then
						os.execute("rm -rf " .. download_dir)
						os.execute("rm -f " .. progress_file)
						luci.http.write_json({success = false, message = i18n.translate("Download cancelled")})
						return
					end
					
					-- 查找解压后的目录（使用通配符）
					local find_cmd = "find " .. extract_dir .. " -maxdepth 1 -type d -name 'easytier-linux-*' 2>/dev/null | head -1"
					local handle = io.popen(find_cmd)
					local subdir = handle:read("*a"):match("^%s*(.-)%s*$")
					handle:close()
					
					if subdir and subdir ~= "" then
						core_file = subdir .. "/easytier-core"
						cli_file = subdir .. "/easytier-cli"
						web_file = subdir .. "/easytier-web-embed"
						
						local files_ok = nixio.fs.access(core_file) and nixio.fs.access(cli_file)
						if arch ~= "mips" and arch ~= "mipsel" then
							files_ok = files_ok and nixio.fs.access(web_file)
						end
						
						if files_ok then
							-- 检查是否被取消
							if check_cancelled() then
								os.execute("rm -rf " .. download_dir)
								os.execute("rm -f " .. progress_file)
								luci.http.write_json({success = false, message = i18n.translate("Download cancelled")})
								return
							end
							
							-- 先赋予执行权限，再测试程序
							local test_files = {core_file, cli_file}
							if arch ~= "mips" and arch ~= "mipsel" then
								table.insert(test_files, web_file)
							end
							
							local test_ok = true
							for _, file in ipairs(test_files) do
								os.execute("chmod +x " .. file)
								if not test_binary(file) then
									test_ok = false
									break
								end
							end
							
							if test_ok then
								download_success = true
								break
							end
						end
					end
				end
			end
		end
		
		-- 删除失败的文件，继续下一个地址
		os.execute("rm -f " .. zip_file)
	end
	
	if not download_success then
		os.execute("rm -rf " .. download_dir)
		os.execute("rm -f " .. progress_file)
		luci.http.write_json({success = false, message = i18n.translate("All download attempts failed")})
		return
	end
	
	-- 检查是否被取消（替换前）
	if check_cancelled() then
		os.execute("rm -rf " .. download_dir)
		os.execute("rm -f " .. progress_file)
		luci.http.write_json({success = false, message = i18n.translate("Download cancelled")})
		return
	end
	
	-- 3. 从UCI获取路径并安装
	local uci = require "luci.model.uci".cursor()
	local easytierbin = uci:get_first("easytier", "easytier", "easytierbin") or "/usr/bin/easytier-core"
	local easytierwebbin = uci:get_first("easytier", "easytier", "webbin") or "/usr/bin/easytier-web"
	
	local core_dir = easytierbin:match("^(.*/)[^/]+$") or "/usr/bin/"
	
	local programs = {
		{src = core_file, dest = easytierbin},
		{src = cli_file, dest = core_dir .. "easytier-cli"}
	}
	
	if arch ~= "mips" and arch ~= "mipsel" then
		table.insert(programs, {src = web_file, dest = easytierwebbin})
	end
	
	-- 安装并验证
	for _, prog in ipairs(programs) do
		local result = os.execute("cp " .. prog.src .. " " .. prog.dest .. " 2>/dev/null")
		if result ~= 0 then
			os.execute("rm -rf " .. download_dir)
			os.execute("rm -f " .. progress_file)
			luci.http.write_json({success = false, message = i18n.translate("Failed to install program") .. ": " .. prog.dest})
			return
		end
		
		os.execute("chmod +x " .. prog.dest)
		
		-- 再次验证安装后的程序
		if not test_binary(prog.dest) then
			os.execute("rm -rf " .. download_dir)
			os.execute("rm -f " .. progress_file)
			luci.http.write_json({success = false, message = i18n.translate("Program is incomplete or architecture mismatch")})
			return
		end
	end
	
	-- 7. 清理临时文件和版本缓存
	os.execute("rm -rf " .. download_dir)
	os.execute("rm -f " .. cancel_file)
	os.execute("rm -f " .. progress_file)
	nixio.fs.remove("/tmp/easytier.tag")
	nixio.fs.remove("/tmp/easytierweb.tag")
	
	luci.http.write_json({
		success = true,
		progress = 100,
		message = i18n.translate("Download and installation completed")
	})
end

function download_progress()
	luci.http.prepare_content("application/json")
	
	local progress_file = "/tmp/easytier_download_progress"
	local content = safe_read_file(progress_file)
	
	if content then
		local json = require "luci.jsonc"
		local progress_data = json.parse(content)
		if progress_data then
			luci.http.write_json({
				success = true,
				progress = progress_data.progress or 0,
				message = progress_data.message or "",
				url = progress_data.url or "",
				error = progress_data.error or false
			})
			return
		end
	end
	
	luci.http.write_json({
		success = true,
		progress = 0,
		message = i18n.translate("Preparing..."),
		url = "",
		error = false
	})
end
function cancel_download()
	luci.http.prepare_content("application/json")
	
	-- 创建取消标志文件
	os.execute("touch /tmp/easytier_download_cancel")
	
	luci.http.write_json({success = true})
end
