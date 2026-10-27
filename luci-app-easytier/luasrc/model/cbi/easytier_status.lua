m = Map("easytier", translate("EasyTier Status"))
m.description = translate("Manage services, connected devices and network diagnostics.")
m.pageaction = false

-- 状态卡片
m:section(SimpleSection).template = "easytier/easytier_status"

-- 连接信息卡片
m:section(SimpleSection).template = "easytier/easytier_cli"

return m
