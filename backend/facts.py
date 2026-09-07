# -*- coding: utf-8 -*-
"""公司域名事实单源(2026-09-07盘点①: 口径散落的治本)。

italent误标/outlook误判/档线三处同步的病根=同一批公司域名事实以不同措辞
散落在各AI通道的prompt里,改一处漏两处。本文件是唯一文本源:
- COMPANY_DOMAIN_FACTS: 公司自有域名/采购服务的客观事实(detector研判prompt
  内嵌引用,字节级等价于原SYSTEM_PROMPT 210-213行,保证研判行为零变化);
- SCAN_CALIBER_FACTS: 上述事实 + 招聘侧确认事实,供 domain_scan(域名定性)/
  daygate(漏报巡检)等外围AI通道注入——它们历史上看不到这些口径。

改公司域名事实只动这里;【人工白名单/判例口径】仍在 casebase.caliber_text()
(人工字典真源,TTL渲染),两者职责不同。
"""

# 公司域名/采购服务客观事实——detector.SYSTEM_PROMPT 内嵌引用(勿在prompt里另写副本)
COMPANY_DOMAIN_FACTS = (
    "例外: OneDrive(storage.live.com/onedrive.live.com等)是公司采购的M365组件,不算网盘违规 → normal_work。\n"
    "公司OA/费控平台xft.cmbchina.com是内部业务系统: 向其发送发票/报销/订单文件属正常办公(推断为报销流程),不判外发。\n"
    "微软基础设施域(login.mso.msidentity.com/ak.privatelink.msidentity.com/windowsupdate*/cloud.microsoft/office.com的登录与更新流量)是公司M365与操作系统组件,不是个人邮箱,判normal_work。outlook.live.com是本公司邮箱网页版地址(2026-08-28确认),login.live.com是其登录跳转域——访问它们或经此通道发送附件属公司邮件通道,判normal_work,严禁写成『个人邮箱』或据此判policy_violation/外发;个人邮箱仅指gmail/qq/163/sina等消费者邮箱服务。Teams是公司办公通讯软件,使用/会议/文件共享一律正常;outlook.cloud.microsoft/outlook.office.com网页版等企业邮箱发送附件属公司邮件通道,不判外发。\n"
    "公司自有域名规则(2026-08-26): huashen.bio 与 helixon.com 是公司主域,其任何子域、任何端口都是公司内部系统(如eln.=ELN电子实验记录本、lab.=实验平台、sftp.=内网传输、huashen.certara.net=仿真平台租户、prod-bioengine.cluster.helixon.com=内部集群、helixoncn*.sharepoint.com=公司M365)——向这些系统上传实验数据/文档一律 normal_work,严禁判外发/网盘违规/'未经授权上传'。判断公司系统看主域后缀,不要枚举记忆。helixoncn-my.sharepoint.com/personal/用户名_helixon_com/ 路径=公司M365个人OneDrive(Teams聊天附件存此处),是公司系统;onedrive.live.com/storage.live.com=公司M365 OneDrive(2026-08-26管理员确认加白),向其同步/上传文件属正常办公。\n"
)

# 外围AI通道(domain_scan/daygate)注入版: 域名事实 + 招聘侧公司确认事实。
# italent事故(2026-09-04)根因即定性AI不知道"italent=北森HR系统"——此行补上。
SCAN_CALIBER_FACTS = COMPANY_DOMAIN_FACTS + (
    "领英(linkedin)与苏州人才网(hrss.suzhou)经公司确认属正常业务行为,不算求职风险;italent.cn/icube.cn是北森招聘管理系统(HR岗位工作用,不是求职网站,更不是猎聘)——这些域名定性为正常办公,严禁标招聘求职。\n"
)

# 公司业务画像(2026-09-07盘点②): 字节级等价于 detector 条款C04 的原文,
# detector.C04 与 massops(批量删除分析)共同引用——改画像只动这里。
BUSINESS_PROFILE_FACTS = (
    "【公司业务画像——所有判定按此校准】公司是生物医药研发企业:核心数据资产=实验记录(ELN)/细胞株与序列等实验材料/临床试验文件(方案·IB·知情同意书·研究报告)/注册专利与合同客户资料。日常文档大量含项目编号(HX/HXN/CBL/DLL等开头)属研发工作常态,有编号≠敏感——敏感看内容性质: 临床/注册/合同/原始数据 > 研究过程稿(PPT/报告草稿) > 行政办公。物业水电单/签证护照/个人简历/安装包缓存等生活行政文件与公司数据资产无关,外发删除均按低敏感处理。\n"
)

# 业务确认政策(2026-09-07盘点②): 域名扫描建议通道(api._rules_scan_core)引用,
# 防止把已确认非风险的类别建议进监控字典(detector C14/C33 研判侧同口径)。
VPN_POLICY_FACTS = "翻墙/VPN工具经公司业务确认不算风险,勿建议纳入风险监控(研判口径=normal_work)。"

# 文件敏感性分级口径(2026-09-07盘点②): massops 外发内容定性引用;detector C35
# 研判侧为带语境完整版(字节锁定),蒸馏轮再统一措辞。
SENSITIVITY_TIER_FACTS = (
    "文件敏感性分级: high=实验/临床/项目数据(试验报告/测序/序列/数据包/文库)/合同财务/数据库导出/设计源文件"
    "(须文件名本身含明确证据,严禁『可能包含』式抬高);mid=办公文档但含项目编号或内部术语;"
    "none=临时缓存/系统文件/私人生活文件(无语义默认名如SendPhotoes/微信图片/截图一律none)。"
)
