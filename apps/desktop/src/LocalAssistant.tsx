import React,{useEffect,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import type {SetupReport} from './SetupAssistant';

type Info={model:string;available:boolean;phase:'idle'|'download'|'thinking';downloaded:number;total:number};
type Answer={text:string;advice:string;elapsed_ms:number};
type Progress={stage:string;downloaded:number;total:number};
export function LocalAssistant({report,locked=false}:{report:SetupReport|null;locked?:boolean}){
 const [info,setInfo]=useState<Info|null>(null),[answer,setAnswer]=useState<Answer|null>(null);
 const [busy,setBusy]=useState(false),[confirm,setConfirm]=useState(false),[message,setMessage]=useState('');
 const [progress,setProgress]=useState<Progress|null>(null);
 useEffect(()=>{let alive=true;let dispose:(()=>void)|undefined;
  void invoke<Info>('ai_state').then(v=>{if(alive&&typeof v.available==='boolean')setInfo(v)}).catch(()=>{});
  void listen<Progress>('ai-progress',e=>{if(alive)setProgress(e.payload)}).then(stop=>{if(alive)dispose=stop;else stop()}).catch(()=>{});
  return()=>{alive=false;dispose?.()};
 },[]);
 useEffect(()=>{setAnswer(null);setMessage('')},[report?.check_id]);
 useEffect(()=>{if(!busy&&info?.phase!=='download'&&info?.phase!=='thinking')return;
  let alive=true;const timer=setInterval(()=>{void invoke<Info>('ai_state').then(v=>{if(alive)setInfo(v)}).catch(()=>{})},1000);
  return()=>{alive=false;clearInterval(timer)};
 },[busy,info?.phase]);
 async function refresh(){setInfo(await invoke<Info>('ai_state'))}
 async function download(){setConfirm(false);setBusy(true);setMessage('');setProgress({stage:'download',downloaded:0,total:639446688});
  try{await invoke('ai_download',{consent:true});setMessage('Модель скачана и проверена. Теперь запустите проверку подключения и попросите объяснение.')}
  catch(e){setMessage(String(e))}finally{setBusy(false);setProgress(null);await refresh().catch(()=>{})}
 }
 async function explain(){if(!report?.check_id)return;setBusy(true);setMessage('');setAnswer(null);setProgress({stage:'thinking',downloaded:0,total:639446688});
  try{setAnswer(await invoke<Answer>('ai_explain',{checkId:report.check_id}))}catch(e){setMessage(String(e))}
  finally{setBusy(false);setProgress(null);await refresh().catch(()=>{})}
 }
 const running=busy||(info!==null&&info.phase!=='idle');
 const stage=progress?.stage??info?.phase;
 const count=progress?.downloaded??info?.downloaded??0;
 const total=progress?.total??info?.total??639446688;
 const downloading=running&&(stage==='download'||stage==='verify');
 return <div className="local-assistant">
  <h4>Локальный ИИ-помощник</h4>
  <p className="footnote">Объяснит результаты проверки простыми словами. Работает на вашем устройстве, без отправки диагностики в интернет. Исправления выполняются кнопками foxVPN ниже, с вашим подтверждением.</p>
  <p className="footnote">Qwen3‑0.6B · отдельная загрузка около 640 МБ · запускается только по запросу и освобождает память после ответа.</p>
  {!info&&<p className="footnote">Помощник доступен в установленном приложении foxVPN.</p>}
  <div className="bottom-toolbar">
   {info&&!info.available&&<button className="secondary" disabled={locked||running} onClick={()=>setConfirm(true)}>Скачать ИИ-помощника</button>}
   {info?.available&&<>
    <button className="secondary" disabled={locked||running||!report?.check_id||report.changed} onClick={()=>void explain()}>Объяснить результаты с ИИ</button>
    <button className="secondary" disabled={locked||running} onClick={()=>setConfirm(true)}>Проверить или скачать модель повторно</button>
   </>}
   {running&&<button className="secondary" onClick={()=>{void invoke('ai_cancel').then(()=>setMessage('Останавливаем помощника…')).catch(e=>setMessage(String(e)))}}>Отменить действие ИИ</button>}
  </div>
  {info?.available&&!report&&<p className="footnote">Сначала нажмите «Проверить и настроить».</p>}
  {downloading&&<div role="status"><progress aria-label="Загрузка модели" value={Math.min(count,total)} max={total}/><p>{stage==='verify'?'Проверяем модель…':`Скачано ${Math.round(count/1000000)} из ${Math.round(total/1000000)} МБ`}</p></div>}
  {running&&!downloading&&<p role="status">Помощник готовит объяснение…</p>}
  {message&&<p role="status">{message}</p>}
  {answer&&<div className="ai-answer" aria-live="polite"><b>Объяснение ИИ</b><p className="ai-text">{answer.text}</p>
   <p className="footnote">Ответ модели может быть неточным. Она не изменяла настройки.</p><b>Проверенный следующий шаг</b><p>{answer.advice}</p></div>}
  {confirm&&<div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-label="Загрузка ИИ-помощника">
   <h2>Скачать локальную модель?</h2><p>foxVPN скачает около 640 МБ с Hugging Face, из официального репозитория Qwen, и проверит файл перед запуском. Для сохранения потребуется свободное место на устройстве. Диагностика, серверы и ключи доступа при загрузке не передаются.</p>
   <p>Модель необязательна: обычная проверка и настройка работают без неё. На время ответа возможна дополнительная нагрузка на процессор и память.</p>
   <div className="modal-actions"><button className="secondary" onClick={()=>setConfirm(false)}>Не сейчас</button><button className="primary" disabled={locked||running} onClick={()=>void download()}>Скачать модель</button></div>
  </section></div>}
 </div>;
}
