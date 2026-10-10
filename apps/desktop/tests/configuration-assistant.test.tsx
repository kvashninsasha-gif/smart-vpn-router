import React,{useState} from 'react';
import {useConfigurationSession} from '../src/configurationSession';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn()}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
import {ConfigurationAssistant} from '../src/ConfigurationAssistant';
import type {SetupReport} from '../src/SetupAssistant';
const report:SetupReport={items:[],action:'windows_proxy',selected:'private-id',recommendation:null,tested:2,total:4,changed:false,check_id:'checked-backend'};
const plan={id:'opaque-plan',changes:['Настроить прокси Windows'],steps:['Переподключить и проверить HTTPS'],blockers:[],reconnect:true};
beforeEach(()=>{ipc.invoke.mockImplementation(async(c:string)=>{if(c==='snapshot')return {platform:'windows'};if(c==='prepare_setup_plan')return plan;if(c==='apply_setup_plan')return {connected:true,verified:true,undo_id:'undo',message:'Подключение проверено'};if(c==='undo_setup_plan')return;throw new Error(c)})});
afterEach(()=>{cleanup();vi.clearAllMocks()});
async function prepare(){fireEvent.click(screen.getByRole('button',{name:'Подготовить план настройки'}));await screen.findByText('План настройки')}
it('plan preview changes nothing; cancel has no effects and apply sends only opaque token and consent',async()=>{
 const done=vi.fn(async()=>{});render(<ConfigurationAssistant report={report} onDone={done}/>);
 await waitFor(()=>expect(screen.getByRole('combobox',{name:'Автоматически настраивать прокси Windows'})).toBeTruthy());
 await prepare();expect(ipc.invoke.mock.calls.some(([c])=>c==='apply_setup_plan')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));expect(screen.getByRole('dialog')).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Отмена'}));expect(ipc.invoke.mock.calls.some(([c])=>c==='apply_setup_plan')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));
 await screen.findByText('Подключение проверено');expect(ipc.invoke).toHaveBeenCalledWith('apply_setup_plan',{planId:'opaque-plan',approved:true});expect(done).toHaveBeenCalledTimes(1);
 expect(ipc.invoke.mock.calls.some(([c])=>['save_settings','prepare_proxy','connect','stop'].includes(c))).toBe(false);
});
it('unsupported platform controls are absent and explicit goals create typed patches',async()=>{
 render(<ConfigurationAssistant report={report} onDone={vi.fn(async()=>{})}/>);
 await screen.findByRole('combobox',{name:'Автоматически настраивать прокси Windows'});
 expect(screen.queryByRole('combobox',{name:'VPN всего Mac'})).toBeNull();
 fireEvent.change(screen.getByRole('combobox',{name:'Цель настройки'}),{target:{value:'vpn'}});await prepare();
 const args=ipc.invoke.mock.calls.find(([c])=>c==='prepare_setup_plan')?.[1];
 expect(args.options.patch).toEqual({windows_proxy_auto:true,mode:'vpn',dns_protection:true,dns_transport:'https'});expect(args.checkId).toBe('checked-backend');
});
it('blockers disable application and stale report clears the prepared plan',async()=>{
 ipc.invoke.mockImplementation(async(c:string)=>c==='snapshot'?{platform:'macos'}:{...plan,blockers:['Сначала установите компонент']});
 const view=render(<ConfigurationAssistant report={report} onDone={vi.fn(async()=>{})}/>);await prepare();
 expect(screen.getByRole('button',{name:'Применить план'}).hasAttribute('disabled')).toBe(true);
 view.rerender(<ConfigurationAssistant report={{...report,check_id:'new-check'}} onDone={vi.fn(async()=>{})}/>);
 await waitFor(()=>expect(screen.queryByText('План настройки')).toBeNull());
});
it('failed application does not claim success and requests a fresh check',async()=>{
 ipc.invoke.mockImplementation(async(c:string)=>{if(c==='snapshot')return {platform:'windows'};if(c==='prepare_setup_plan')return plan;throw new Error('Проверка не прошла. Прежние настройки возвращены')});
 const done=vi.fn(async()=>{});render(<ConfigurationAssistant report={report} onDone={done}/>);await prepare();
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));
 await screen.findByText(/Проверка не прошла/);expect(screen.queryByText('Подключение проверено')).toBeNull();expect(done).toHaveBeenCalledTimes(1);
});
it('undo is separately consented and uses only the receipt token',async()=>{
 const done=vi.fn(async()=>{});render(<ConfigurationAssistant report={report} onDone={done}/>);await prepare();
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));await screen.findByText('Подключение проверено');
 fireEvent.click(screen.getByRole('button',{name:'Вернуть прежние настройки'}));expect(ipc.invoke.mock.calls.some(([c])=>c==='undo_setup_plan')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));await screen.findByText('Прежние настройки возвращены');
 expect(ipc.invoke).toHaveBeenCalledWith('undo_setup_plan',{undoId:'undo',approved:true});expect(done).toHaveBeenCalledTimes(2);
});

it('Mac proxy and system scope are explicit and final preview shows the backend scope',async()=>{
 ipc.invoke.mockImplementation(async(c:string)=>c==='snapshot'?{platform:'macos',profile:{settings:{tun:false}}}:{...plan,scope:'Системный VPN всего Mac'});
 render(<ConfigurationAssistant report={report} onDone={vi.fn(async()=>{})}/>);
 await screen.findByRole('combobox',{name:'Охват подключения'});
 expect(screen.queryByRole('option',{name:'Весь трафик Mac через VPN'})).toBeNull();
 fireEvent.change(screen.getByRole('combobox',{name:'Охват подключения'}),{target:{value:'system'}});
 expect(screen.getByRole('option',{name:'Весь трафик Mac через VPN'})).toBeTruthy();
 fireEvent.change(screen.getByRole('combobox',{name:'Цель настройки'}),{target:{value:'vpn'}});
 await prepare();expect(screen.getByText('Охват:').parentElement?.textContent).toContain('Системный VPN всего Mac');
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));
 expect(screen.getByRole('dialog').textContent).toContain('Системный VPN всего Mac');
 const args=ipc.invoke.mock.calls.find(([c])=>c==='prepare_setup_plan')?.[1];expect(args.options.patch.tun).toBe(true);
});
it('routing confirmation displays domains, routes, additions, removals and priority',async()=>{
 const rules=[{domain:'example.com',previous_route:'vpn',next_route:'direct',previous_position:1,next_position:2},{domain:'*.example.ru',previous_route:null,next_route:'vpn',previous_position:null,next_position:1},{domain:'old.example.com',previous_route:'direct',next_route:null,previous_position:2,next_position:null}];
 ipc.invoke.mockImplementation(async(c:string)=>c==='snapshot'?{platform:'windows'}:{...plan,rule_changes:rules});
 render(<ConfigurationAssistant report={report} onDone={vi.fn(async()=>{})}/>);await prepare();
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));const text=screen.getByRole('dialog').textContent;
 expect(text).toContain('example.com');expect(text).toContain('Через VPN → Напрямую');expect(text).toContain('приоритет 1 → 2');expect(text).toContain('*.example.ru');expect(text).toContain('добавить');expect(text).toContain('old.example.com');expect(text).toContain('удалить');
});
it('receipt survives changing the visible page and still requires separate consent',async()=>{
 function Pages(){const session=useConfigurationSession();const [visible,setVisible]=useState(true);return <><button onClick={()=>setVisible(v=>!v)}>Сменить страницу</button>{visible&&<ConfigurationAssistant session={session} report={report} onDone={vi.fn(async()=>{})}/>}</>}
 render(<Pages/>);await prepare();fireEvent.click(screen.getByRole('button',{name:'Применить план'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));await screen.findByText('Подключение проверено');
 fireEvent.click(screen.getByRole('button',{name:'Сменить страницу'}));fireEvent.click(screen.getByRole('button',{name:'Сменить страницу'}));
 fireEvent.click(screen.getByRole('button',{name:'Вернуть прежние настройки'}));expect(ipc.invoke.mock.calls.some(([c])=>c==='undo_setup_plan')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));await screen.findByText('Прежние настройки возвращены');expect(ipc.invoke).toHaveBeenCalledWith('undo_setup_plan',{undoId:'undo',approved:true});
});
it('cancellation requests stop the pending operation and never claim success',async()=>{
 let reject:(reason:unknown)=>void=()=>{};
 ipc.invoke.mockImplementation(async(c:string)=>{if(c==='snapshot')return {platform:'windows'};if(c==='prepare_setup_plan')return plan;if(c==='apply_setup_plan')return new Promise((_,r)=>{reject=r});if(c==='cancel_setup_plan')return;throw new Error(c)});
 const done=vi.fn(async()=>{});render(<ConfigurationAssistant report={report} onDone={done}/>);await prepare();fireEvent.click(screen.getByRole('button',{name:'Применить план'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));
 fireEvent.click(await screen.findByRole('button',{name:'Отменить настройку'}));await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('cancel_setup_plan',{operationId:'opaque-plan'}));
 reject('Действие отменено. Прежние настройки возвращены');await screen.findByText('Действие отменено. Прежние настройки возвращены');expect(screen.queryByRole('button',{name:'Вернуть прежние настройки'})).toBeNull();
});

it('completed application hides cancellation while refreshing the diagnostic report',async()=>{
 let finish:()=>void=()=>{};const done=vi.fn(()=>new Promise<void>(resolve=>{finish=resolve}));
 render(<ConfigurationAssistant report={report} onDone={done}/>);await prepare();
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить план'}));
 await screen.findByText('Подключение проверено');expect(screen.queryByRole('button',{name:'Отменить настройку'})).toBeNull();
 expect(screen.getByRole('button',{name:'Вернуть прежние настройки'}).hasAttribute('disabled')).toBe(true);finish();
 await waitFor(()=>expect(screen.getByRole('button',{name:'Вернуть прежние настройки'}).hasAttribute('disabled')).toBe(false));
});
