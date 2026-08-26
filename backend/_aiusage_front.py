# -*- coding: utf-8 -*-
import io

p = "backend/static/index.html"
src = io.open(p, encoding="utf-8").read()

anchor = '''    <Row gutter={[16,16]} style={{marginTop:16}} align="stretch">
        <Col span={17}>
        <div style={{marginBottom:10}}><span className="brand-bar"></span><b style={{fontSize:14}}>告警日趋势</b>'''
assert src.count(anchor) == 1, "trend anchor"

card = '''    <Card className="card" size="small" style={{marginBottom:16}} title={<span><span className="brand-bar"></span><TH t="AI 平台使用分析" tip="近7天员工使用外部AI平台的情况:各平台活跃时段数(有访问的10分钟桶)、使用人数、重度用户;『主要用AI做什么』由本地AI按页面标题语义归纳;向AI上传文件=公司数据进入外部AI,单独列出。" /> <span style={{fontSize:11,color:'var(--ink3)',fontWeight:400}}>(近7天 · 5分钟缓存)</span></span>}>
      {(()=>{ const [au,setAu]=useState(null); const [ins,setIns]=useState(null); const [iloading,setIloading]=useState(false);
      useEffect(()=>{ fetch('/api/ai-usage',{headers:_authHdr()}).then(r=>r.json()).then(setAu).catch(()=>{}); },[]);
      const genIns=()=>{ setIloading(true); fetch('/api/ai-usage/insight',{headers:_authHdr()}).then(r=>r.json()).then(r=>setIns(r.summary||'')).finally(()=>setIloading(false)); };
      if(!au) return <div style={{padding:20,textAlign:'center',color:'var(--ink3)',fontSize:12}}>加载中...</div>;
      const mx=(au.platforms||[])[0]?.buckets||1;
      return (<div>
        <Row gutter={16}>
          <Col span={14}>
            <div style={{fontSize:11,color:'var(--ink3)',marginBottom:6}}>平台活跃度(时段数 · 使用人数)</div>
            {(au.platforms||[]).slice(0,6).map(p2=>(<div key={p2.name} style={{display:'flex',alignItems:'center',gap:8,marginBottom:5}}>
              <span style={{width:64,fontSize:11.5,fontWeight:600,color:'var(--ink2)'}}>{p2.name}</span>
              <div style={{flex:1,height:14,background:'var(--ink4)',borderRadius:7,overflow:'hidden'}}><div style={{height:'100%',width:Math.round(100*p2.buckets/mx)+'%',background:'linear-gradient(90deg,#6366f1,#818cf8)',borderRadius:7}}></div></div>
              <span className="num" style={{width:56,textAlign:'right',fontSize:11,color:'var(--ink2)'}}>{p2.buckets}时段</span>
              <span style={{width:40,textAlign:'right',fontSize:11,color:'var(--ink3)'}}>{p2.users}人</span>
            </div>))}
            <div style={{fontSize:11,color:'var(--ink3)',marginTop:8,fontWeight:600}}>重度用户</div>
            <div style={{fontSize:11,color:'var(--ink2)',lineHeight:1.9,marginTop:2}}>
              {(au.top_users||[]).slice(0,5).map(u=>(<span key={u.employee} style={{marginRight:12}}><a className="uname" onClick={()=>goProfile(u.employee)}>{EMP_D(u.employee)}</a> <b style={{color:'var(--ink)'}}>{u.buckets}</b>时段</span>))}
            </div>
          </Col>
          <Col span={10}>
            <div style={{fontSize:11,color:'var(--ink3)',marginBottom:6}}>主要用AI做什么 <Button size="small" loading={iloading} onClick={genIns} style={{marginLeft:8}}>{ins?'重新分析':'AI归纳用途'}</Button></div>
            <div style={{background:'var(--bg)',borderRadius:8,padding:'8px 10px',fontSize:11.5,color:'var(--ink2)',lineHeight:1.85,minHeight:60,maxHeight:180,overflow:'auto',whiteSpace:'pre-wrap'}}>
              {ins||(au.platforms||[]).slice(0,4).map(p2=>`【${p2.name}】${(p2.top_titles||[]).slice(0,3).join('; ')||'—'}`).join('\n')}
            </div>
            {(au.uploads&&au.uploads.length)?(<div style={{marginTop:8}}>
              <div style={{fontSize:11,color:'#ef4444',fontWeight:600}}><i className="fa-solid fa-triangle-exclamation"></i> 向AI上传文件(数据进入外部AI)</div>
              {au.uploads.slice(0,3).map(u=>(<div key={u.employee} style={{fontSize:11,color:'var(--ink2)',marginTop:3}}>
                <a className="uname" onClick={()=>goProfile(u.employee)}>{EMP_D(u.employee)}</a> {u.n}次/{u.mb}MB: {(u.files||[]).slice(0,2).join('; ')}
              </div>))}
            </div>):<div style={{marginTop:8,fontSize:11,color:'#16a34a'}}><i className="fa-solid fa-circle-check"></i> 近7天无向AI上传文件行为</div>}
          </Col>
        </Row>
      </div>); })()}
    </Card>
'''

src = src.replace(anchor, card + anchor)
io.open(p, "w", encoding="utf-8", newline="\n").write(src)
print("AI使用分析卡片注入")
