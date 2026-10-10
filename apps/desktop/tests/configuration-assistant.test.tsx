import React from 'react';
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
