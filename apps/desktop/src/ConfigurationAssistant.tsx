import React,{useEffect,useRef,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import type {SetupReport} from './SetupAssistant';
import type {Settings,Snapshot} from './types';
import {useConfigurationSession,type ConfigurationSession,type ConfigurationOutcome} from './configurationSession';
import {RuleChanges,type RuleChange} from './RuleChanges';
type Plan={id:string;changes:string[];steps:string[];blockers:string[];reconnect:boolean;scope?:string;rule_changes?:RuleChange[]};
type Outcome=ConfigurationOutcome;
type Patch=Partial<Settings>;
const selects:{key:keyof Settings;label:string;values:[string,string][]}[]=[
 {key:'mode',label:'Маршрутизация',values:[['smart','Российские сайты напрямую'],['vpn','Всё через VPN'],['direct','Напрямую'],['custom','Пользовательские правила']]},
 {key:'dns_provider',label:'Провайдер DNS',values:[['cloudflare','Cloudflare'],['google','Google'],['quad9','Quad9']]},
 {key:'dns_transport',label:'Транспорт DNS',values:[['https','HTTPS'],['tls','TLS'],['local','Системный DNS']]},
 {key:'strategy',label:'Выбор сервера',values:[['balanced','Сбалансированный'],['latency','Минимальная задержка'],['speed','По сохранённой скорости'],['stability','По стабильности'],['random','Случайный']]},
 {key:'subscription_interval',label:'Обновление подписок',values:[['0','Никогда'],['3600','Каждый час'],['21600','Каждые 6 часов'],['43200','Каждые 12 часов'],['86400','Раз в сутки']]},
];
const booleans:{key:keyof Settings;label:string;platform?:'macos'|'windows'}[]=[
 {key:'kill_switch',label:'Защита при обрыве',platform:'macos'},
 {key:'windows_proxy_auto',label:'Автоматически настраивать прокси Windows',platform:'windows'},
 {key:'dns_protection',label:'Защита DNS'},{key:'restore',label:'Восстанавливать соединение'},
 {key:'failover',label:'Использовать резервные серверы'},{key:'favorites_only',label:'Выбирать только избранные'},
 {key:'auto_connect',label:'Подключаться при запуске foxVPN'},{key:'start_minimized',label:'Свёрнутый запуск'},
 {key:'auto_metrics',label:'Автоматические замеры'},
];
export function ConfigurationAssistant({report,locked=false,onDone,session}:{report:SetupReport|null;locked?:boolean;onDone:()=>Promise<void>;session?:ConfigurationSession}){
 const [platform,setPlatform]=useState(''),[currentTun,setCurrentTun]=useState(true),[patch,setPatch]=useState<Patch>({}),[rules,setRules]=useState('');
 const [replaceRules,setReplaceRules]=useState(false),[selectRecommended,setSelectRecommended]=useState(true),[connectAfter,setConnectAfter]=useState(true);
 const [plan,setPlan]=useState<Plan|null>(null);
 const localSession=useConfigurationSession();
 const {result,setResult,phase,setPhase,message,setMessage,operationId,setOperationId}=session??localSession;
 const busy=phase!==null;
 const [confirm,setConfirm]=useState<'apply'|'undo'|null>(null);
 const initialized=useRef(false);
 useEffect(()=>{let alive=true;void invoke<Snapshot>('snapshot').then(s=>{if(alive){setPlatform(s.platform??'macos');setCurrentTun(s.profile?.settings.tun??true);if(!initialized.current){initialized.current=true;if(s.platform==='windows')setPatch(p=>({windows_proxy_auto:true,...p}))}}}).catch(()=>{});return()=>{alive=false}},[report?.check_id]);
 useEffect(()=>{setPlan(null);setConfirm(null)},[report?.check_id]);
 function change(key:keyof Settings,value:unknown){setPatch(p=>{const next={...p};if(value===undefined)delete next[key];else (next as Record<string,unknown>)[key]=value;return next});setPlan(null)}
 async function prepare(){if(!report?.check_id)return;setPhase('preview');setMessage('');try{
  const customRules=replaceRules?rules.split('\n').filter(v=>v.trim()).map(line=>{const [domain,route,...rest]=line.trim().split(/\s+/);if(!domain||!['vpn','direct'].includes(route)||rest.length)throw new Error('Правило: домен и маршрут vpn или direct');return {domain,route}}):undefined;
  setPlan(await invoke<Plan>('prepare_setup_plan',{checkId:report.check_id,options:{patch,rules:customRules,select_recommended:selectRecommended,connect_after:connectAfter}}));
 }catch(e){setMessage(String(e))}finally{setOperationId(null);setPhase(null)}}
 async function apply(){if(!plan)return;setConfirm(null);setOperationId(plan.id);setPhase('apply');setMessage('');try{
  const value=await invoke<Outcome>('apply_setup_plan',{planId:plan.id,approved:true});setResult(value);setPlan(null);setMessage(value.message);setPhase('checking');await onDone();
 }catch(e){setMessage(String(e));await onDone().catch(()=>{})}finally{setOperationId(null);setPhase(null)}}
 async function undo(){if(!result)return;setConfirm(null);setOperationId(result.undo_id);setPhase('undo');setMessage('');try{
  await invoke('undo_setup_plan',{undoId:result.undo_id,approved:true});setResult(null);setMessage('Прежние настройки возвращены');setPhase('checking');await onDone();
 }catch(e){setResult(null);setMessage(String(e))}finally{setOperationId(null);setPhase(null)}}
 const disabled=locked||busy;
 const systemScope=platform==='macos'&&(patch.tun??currentTun);
 async function cancel(){try{await invoke('cancel_setup_plan',{operationId});setMessage('Запрошена отмена. Дождитесь остановки и возврата настроек.')}catch(e){setMessage(String(e))}}
 return <div className="configuration-assistant">
  <h4>Настроить подключение с помощником</h4><p className="footnote">Помощник подготовит конкретный план по результатам проверки. После вашего подтверждения foxVPN применит параметры и проверит подключение. При ошибке попробует вернуть прежние настройки. Модель объясняет диагностику; команды выполняет проверенный код приложения.</p>
  <label>Что настроить<select aria-label="Цель настройки" disabled={disabled} defaultValue="repair" onChange={e=>{const presets:Record<string,Patch>={repair:{},smart:{mode:'smart'},vpn:{mode:'vpn',dns_protection:true,dns_transport:'https'},latency:{strategy:'latency'},stability:{strategy:'stability',restore:true,failover:true}};const preset=presets[e.target.value];setPatch(previous=>({...preset,...(platform==='windows'?{windows_proxy_auto:previous.windows_proxy_auto??true}:{}),...(previous.tun!==undefined?{tun:previous.tun}:{}),...(previous.kill_switch!==undefined?{kill_switch:previous.kill_switch}:{})}));setPlan(null)}}><option value="repair">Исправить подключение</option><option value="smart">Российские сайты напрямую, остальные через VPN</option><option value="vpn">{systemScope?'Весь трафик Mac через VPN':'Трафик приложений с поддержкой прокси через VPN'}</option><option value="latency">Подобрать сервер с меньшей задержкой</option><option value="stability">Настроить стабильное соединение</option></select></label>
  {platform==='macos'&&<><label>Охват подключения<select aria-label="Охват подключения" disabled={disabled} value={patch.tun===undefined?'':patch.tun?'system':'proxy'} onChange={e=>change('tun',e.target.value===''?undefined:e.target.value==='system')}><option value="">Сохранить: {currentTun?'системный VPN':'локальный прокси'}</option><option value="system">Системный VPN всего Mac</option><option value="proxy">Локальный прокси для настроенных приложений</option></select></label><p className="footnote">При переходе с системного VPN на прокси отдельно выберите отключение защиты при обрыве. Все изменения появятся в плане. Для системного VPN нужен сетевой компонент.</p></>}
  <label><input type="checkbox" checked={selectRecommended} disabled={disabled} onChange={e=>{setSelectRecommended(e.target.checked);setPlan(null)}}/> Выбрать рабочий сервер из проверенных</label>
  <label><input type="checkbox" checked={connectAfter} disabled={disabled} onChange={e=>{setConnectAfter(e.target.checked);setPlan(null)}}/> Подключить и проверить результат</label>
  <details><summary>Какие параметры настроить</summary><p className="footnote">«Сохранить» оставляет ваш текущий выбор. Скорость оценивается по сохранённым измерениям; нового большого теста скорости не будет. Проверка выбирает только из проверенной части списка.</p>
   <div className="settings-selects">{selects.map(field=><label key={field.key}>{field.label}<select aria-label={field.label} disabled={disabled} value={String(patch[field.key]??'')} onChange={e=>change(field.key,e.target.value===''?undefined:field.key==='subscription_interval'?Number(e.target.value):e.target.value)}><option value="">Сохранить</option>{field.values.map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>)}</div>
   <div className="settings-selects">{booleans.filter(v=>!v.platform||v.platform===platform).map(field=><label key={field.key}>{field.label}<select aria-label={field.label} disabled={disabled} value={patch[field.key]===undefined?'':String(patch[field.key])} onChange={e=>change(field.key,e.target.value===''?undefined:e.target.value==='true')}><option value="">Сохранить</option><option value="true">Включить</option><option value="false">Отключить</option></select></label>)}</div>
   <div className="settings-selects">{[{key:'proxy_port' as const,label:'Локальный порт',min:1024,max:65535},{key:'health_interval' as const,label:'Проверять соединение каждые, секунд',min:10,max:3600},{key:'metric_interval' as const,label:'Интервал замеров, секунд',min:60,max:3600}].map(field=><label key={field.key}>{field.label}<input aria-label={field.label} disabled={disabled} type="number" min={field.min} max={field.max} placeholder="Сохранить" value={patch[field.key]??''} onChange={e=>change(field.key,e.target.value===''?undefined:Number(e.target.value))}/></label>)}</div>
   <label><input type="checkbox" checked={replaceRules} disabled={disabled} onChange={e=>{setReplaceRules(e.target.checked);setPlan(null)}}/> Заменить пользовательские правила</label>
   {replaceRules&&<label>Правила маршрутизации<textarea aria-label="Правила плана" disabled={disabled} value={rules} onChange={e=>{setRules(e.target.value);setPlan(null)}} placeholder={'example.com vpn\n*.example.ru direct'}/></label>}
  </details>
  {!report?.check_id&&<p className="footnote">Сначала нажмите «Проверить и настроить».</p>}
  <div className="bottom-toolbar"><button className="primary" disabled={disabled||!report?.check_id||report.changed} onClick={()=>void prepare()}>Подготовить план настройки</button>
   {result&&<button className="secondary" disabled={disabled} onClick={()=>setConfirm('undo')}>Вернуть прежние настройки</button>}</div>
  {busy&&<p role="status">Выполняем настройку и проверяем результат… {!session&&(phase==='apply'||phase==='undo')&&<button className="secondary" onClick={()=>void cancel()}>Отменить настройку</button>}</p>}{message&&<p role="status">{message}</p>}
  {plan&&<div className="ai-answer"><b>План настройки</b>{plan.scope&&<p><strong>Охват:</strong> {plan.scope}</p>}{plan.changes.length?<ul>{plan.changes.map((v,i)=><li key={i}>{v}</li>)}</ul>:<p>Параметры сохраняются. Будет проверено подключение.</p>}<RuleChanges changes={plan.rule_changes??[]}/><ol>{plan.steps.map((v,i)=><li key={i}>{v}</li>)}</ol>{plan.blockers.map((v,i)=><p role="alert" key={i}>{v}</p>)}<button className="primary" disabled={disabled||plan.blockers.length>0} onClick={()=>setConfirm('apply')}>Применить план</button></div>}
  {confirm&&<div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-label="Подтверждение плана настройки"><h2>{confirm==='apply'?'Применить этот план?':'Вернуть прежние настройки?'}</h2>
   {confirm==='apply'&&plan?<>{plan.scope&&<p><strong>Охват:</strong> {plan.scope}</p>}<RuleChanges changes={plan.rule_changes??[]}/><ul>{plan.changes.map((v,i)=><li key={i}>{v}</li>)}</ul><ol>{plan.steps.map((v,i)=><li key={i}>{v}</li>)}</ol></>:<p>foxVPN остановит текущее подключение, вернёт сохранённые прежние настройки и восстановит прежнее соединение, если оно было подключено. Если вы уже изменили настройки или состояние, возврат будет отменён.</p>}
   <p>На Mac установка сетевого компонента и системные разрешения подтверждаются отдельно в macOS. Для Windows настраивается локальный прокси; системный TUN недоступен.</p>
   <div className="modal-actions"><button className="secondary" disabled={disabled} onClick={()=>setConfirm(null)}>Отмена</button><button className="primary" disabled={disabled} onClick={()=>void(confirm==='apply'?apply():undo())}>Подтвердить план</button></div>
  </section></div>}
 </div>;
}
