# -*- coding: utf-8 -*-
import io

p = "backend/static/index.html"
src = io.open(p, encoding="utf-8").read()

old1 = '{key:\'rawlogs\',label:<span><i className="fa-solid fa-file-lines"></i><span>原始日志</span></span>},'
new1 = '{key:\'pipe\',label:<span><i className="fa-solid fa-diagram-project"></i><span>数据链路</span></span>},\n              ' + old1
assert src.count(old1) == 1, "nav"
src = src.replace(old1, new1)

old2 = "          {key==='rawlogs' && <RawLogs/>}"
new2 = "          {key==='pipe' && <PipePage/>}\n" + old2
assert src.count(old2) == 1, "mount"
src = src.replace(old2, new2)

old3 = "function RawLogs(){"
page = '''function PipePage(){
  const [ov,setOv]=useState(null);
  const [q,setQ]=useState('');
  const [tr,setTr]=useState(null);
  const [tloading,setTloading]=useState(false);
  const funnelRef=useRef();
  useEffect(()=>{ const load=()=>GET('/api/pipeline/overview').then(setOv); load(); const t=setInterval(load,30000); return ()=>clearInterval(t); },[]);
  useEffect(()=>{
    if(!ov||!funnelRef.current) return;
    const c=echarts.init(funnelRef.current);
    const st=ov.stat||{}, raw=ov.raw&&ov.raw.today||0;
    const noise=(st.noise_or_merged||0), cross=(st.cross_dedup||0);
    const ev=ov.events&&ov.events.today||0, vd=ov.verdicts&&ov.verdicts.today||0, al=ov.alerts_today||0;
    const names=['原始报文','降噪/去重压掉','入库事件','送AI研判','产生告警'];
    const vals=[raw,noise+cross,ev,vd,al];
    c.setOption({tooltip:{trigger:'item',formatter:function(p){return names[p.dataIndex]+': '+vals[p.dataIndex];}},
      series:[{type:'funnel',left:'6%',width:'88%',top:8,bottom:8,minSize:'22%',sort:'descending',gap:3,
        label:{show:true,position:'inside',fontSize:11,color:'#fff',formatter:function(p){return p.name;}},
        itemStyle:{borderColor:'#fff',borderWidth:1},
        data:[{name:'原始报文 '+raw,value:Math.max(raw,1),itemStyle:{color:'#6366f1'}},
              {name:'降噪/去重后 '+(raw-noise-cross>0?raw-noise-cross:1),value:Math.max(raw-noise-cross,1),itemStyle:{color:'#818cf8'}},
              {name:'入库事件 '+ev,value:Math.max(ev,1),itemStyle:{color:'#a5b4fc'}},
              {name:'送AI研判 '+vd,value:Math.max(vd,1),itemStyle:{color:'#f59e0b'}},
              {name:'产生告警 '+al,value:Math.max(al,1),itemStyle:{color:'#ef4444'}}]}]});
  },[ov]);
  const doTrace=()=>{ if(q.trim().length<2)return; setTloading(true); setTr(null);
    GET('/api/pipeline/trace?q='+encodeURIComponent(q.trim())).then(r=>{setTr(r);}).finally(()=>setTloading(false)); };
  const st=ov&&ov.stat||{};
  const ent=o=>Object.entries(o||{}).map(kv=>kv[0]+':'+kv[1]).join(' · ')||'—';
  const STAGES=[
    {t:'① 双源接收',d:'深信服(上网行为)+IPG(文档/进程/搜索)的syslog实时进入UDP 8514,原始报文留存7天。同域名10分钟内两源重复互丢(今日去重'+(st.cross_dedup||0)+'条)。'},
    {t:'② 降噪聚合',d:'证书/CDN/静态资源/广告域名丢弃;网页访问按 员工×域名×10分钟桶 合并计数(今日压缩'+(st.noise_or_merged||0)+'条),桶内保留标题与URL样本供AI判断"打开vs上传"。'},
    {t:'③ 建窗',d:'同员工行为间隔≤60分钟切一个窗口;访客(纯数字)与忽略名单不入库。'},
    {t:'④ 是否送AI(五信号闸门)',d:'真实外发(SEND/UPLOAD/打印/USB) / 禁止类访问(个人邮箱·网盘·文件助手·招聘,访问即触发) / 远程控制+深夜 / 搜索词 / 深夜真实浏览≥3条·频次异常。无信号整窗丢弃零AI成本。今日抑制: 已判过'+(st.sup_已判过||0)+'窗·6小时去重'+(st.sup_6小时去重||0)+'窗。'},
    {t:'⑤ AI研判+锚点分工',d:'AI只定意图和写说明,分数由程序锚点统一算(违规75/外发80/稀有通道85+频次深夜修正);公司白名单(Teams/M365/ELN等)不进外发语境。'},
    {t:'⑥ 输出与复核',d:'≥50分成告警(同员工同场景合并);凌晨1点N+1复核全天视野,误报自动关闭;聚合检测(蚂蚁搬家/压缩外发/改名掩盖)10分钟级扫描。'},
  ];
  return (<div>
    <div className="sec-title">数据链路 · 从原始日志到告警的全过程可视 <span style={{fontSize:11,color:'var(--ink3)'}}>每30秒刷新</span></div>
    <Row gutter={16}>
      <Col span={10}><Card className="card" size="small" title={<span><span className="brand-bar"></span>今日漏斗</span>}>
        <div ref={funnelRef} style={{height:250}}></div>
      </Card></Col>
      <Col span={14}><Card className="card" size="small" title={<span><span className="brand-bar"></span>双源实况</span>}>
        <Row gutter={12}>
          <Col span={8}><Statistic title="近5分钟报文" value={(ov&&ov.raw&&ov.raw.last5min)!=null?ov.raw.last5min:'—'} valueStyle={{fontSize:22}}/></Col>
          <Col span={8}><Statistic title="今日原始报文" value={(ov&&ov.raw&&ov.raw.today)!=null?ov.raw.today:'—'} valueStyle={{fontSize:22}}/></Col>
          <Col span={8}><Statistic title="今日事件(降噪后)" value={(ov&&ov.events&&ov.events.today)!=null?ov.events.today:'—'} valueStyle={{fontSize:22}}/></Col>
        </Row>
        <div style={{marginTop:10,fontSize:11,color:'var(--ink2)',lineHeight:1.9}}>
          <div>按类型: {ent(ov&&ov.raw&&ov.raw.by_type)}</div>
          <div>事件构成: {ent(ov&&ov.events&&ov.events.by_cat)}</div>
          <div>研判意图: {Object.entries((ov&&ov.verdicts&&ov.verdicts.by_intent)||{}).map(kv=>(INTENT[kv[0]]||kv[0])+':'+kv[1]).join(' · ')||'—'}</div>
          <div>N+1复核(最近一轮): {ent(ov&&ov.n1_last)}</div>
        </div>
      </Card></Col>
    </Row>
    <Row gutter={16} style={{marginTop:14}}>
      {STAGES.map(s2=>(<Col span={8} key={s2.t} style={{marginBottom:12}}><Card className="card" size="small" style={{height:'100%'}}>
        <div style={{fontWeight:700,fontSize:12.5,marginBottom:6,color:'var(--ink)'}}>{s2.t}</div>
        <div style={{fontSize:11,color:'var(--ink2)',lineHeight:1.8}}>{s2.d}</div>
      </Card></Col>))}
    </Row>
    <Card className="card" size="small" title={<span><span className="brand-bar"></span>单条日志全链路追踪 · 输入员工名或域名,看它经历了什么</span>} style={{marginTop:4}}>
      <Space.Compact style={{width:'100%',maxWidth:520}}>
        <Input placeholder="员工名(如 田纪元) 或 域名(如 filehelper.weixin.qq.com)" value={q} onChange={e=>setQ(e.target.value)} onPressEnter={doTrace} prefix={<i className="fa-solid fa-magnifying-glass" style={{color:'var(--ink4)'}}></i>}/>
        <Button type="primary" loading={tloading} onClick={doTrace}>追踪</Button>
      </Space.Compact>
      {tr&&tr.hint&&<div style={{marginTop:10,color:'var(--ink3)',fontSize:12}}>{tr.hint}</div>}
      {tr&&!tr.hint&&(<div style={{marginTop:12}}>
        <div style={{fontSize:11,fontWeight:700,color:'var(--ink3)',margin:'8px 0 4px'}}>① 原始报文(raw_logs)</div>
        {((tr.stages&&tr.stages.raw)||[]).length?tr.stages.raw.map((r,i)=>(<div key={i} style={{fontSize:11,color:'var(--ink2)',fontFamily:'monospace',background:'var(--bg)',padding:'4px 8px',borderRadius:6,marginBottom:4}}>[{r.type}] {r.ts} {r.user} | {r.msg}</div>)):<div style={{fontSize:11,color:'var(--ink4)'}}>近7天无匹配报文(可能已过保留期)</div>}
        <div style={{fontSize:11,fontWeight:700,color:'var(--ink3)',margin:'8px 0 4px'}}>② 聚合事件(近3天,×N为10分钟桶合并计数)</div>
        {((tr.stages&&tr.stages.events)||[]).map((e,i)=>(<div key={i} style={{fontSize:11,color:'var(--ink2)',background:'var(--bg)',padding:'4px 8px',borderRadius:6,marginBottom:4}}>{e.ts} [{e.cat}/{e.act}] ×{e.count} {e.domain||e.target} {e.titles&&e.titles.length?('《'+e.titles[0]+'》'):''}</div>))}
        {!((tr.stages&&tr.stages.events)||[]).length&&<div style={{fontSize:11,color:'var(--ink4)'}}>无事件</div>}
        <div style={{fontSize:11,fontWeight:700,color:'var(--ink3)',margin:'8px 0 4px'}}>③④ 送AI的窗口样例与研判结论</div>
        {tr.stages&&tr.stages.ai_input?(<div>
          <pre style={{fontSize:10.5,background:'var(--bg)',padding:8,borderRadius:6,maxHeight:200,overflow:'auto',whiteSpace:'pre-wrap',color:'var(--ink2)'}}>{tr.stages.ai_input.window}</pre>
          <div style={{fontSize:11,marginTop:4}}>研判: <Tag color={tr.stages.ai_input.verdict.score>=76?'red':tr.stages.ai_input.verdict.score>=50?'orange':'green'}>{tr.stages.ai_input.verdict.score}分 {INTENT[tr.stages.ai_input.verdict.intent]||tr.stages.ai_input.verdict.intent}</Tag>
            <span style={{color:'var(--ink2)'}}>{tr.stages.ai_input.verdict.explain}</span></div>
          {tr.stages.output&&tr.stages.output.alert?(<div style={{fontSize:11,marginTop:4}}>告警: [{tr.stages.output.alert.id}] {tr.stages.output.alert.score}分 状态{tr.stages.output.alert.status} | {tr.stages.output.alert.summary}</div>):<div style={{fontSize:11,color:'var(--ink4)',marginTop:4}}>未成告警(分数低于50或同场景已有合并告警)</div>}
        </div>):<div style={{fontSize:11,color:'var(--ink4)'}}>近3天该对象无研判记录(未触发五信号闸门,或被6小时去重抑制)</div>}
      </div>)}
    </Card>
  </div>);
}
function RawLogs(){'''
assert src.count(old3) == 1, "RawLogs anchor"
src = src.replace(old3, page)
io.open(p, "w", encoding="utf-8", newline="\n").write(src)
print("PipePage注入完成")
