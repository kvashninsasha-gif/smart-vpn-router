import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {SetupAssistant,type SetupReport} from '../src/SetupAssistant';
const report:SetupReport={items:[{label:'Текущее соединение',ok:true,message:'HTTPS проверен'}],action:'windows_proxy',selected:'test',recommendation:null,tested:0,total:1,changed:false};
beforeEach(()=>{ipc.invoke.mockResolvedValue(structuredClone(report))});
afterEach(()=>{cleanup();vi.clearAllMocks()});
it('Windows repair requires explicit confirmation and cancel makes no changes',async()=>{
 const action=vi.fn(async()=>{});render(<SetupAssistant onAction={action} active/>);
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 fireEvent.click(await screen.findByRole('button',{name:'Настроить Windows автоматически'}));
 expect(action).not.toHaveBeenCalled();expect(screen.getByRole('dialog')).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Отмена'}));expect(action).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:'Настроить Windows автоматически'}));
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить настройку'}));
 await waitFor(()=>expect(action).toHaveBeenCalledWith('windows_proxy',expect.objectContaining({selected:'test'})));
 expect(ipc.invoke.mock.calls.map(([command])=>command)).toEqual(['ai_state','setup_check']);
});
it('macOS installer is offered as a consented action, never started by the check',async()=>{
 ipc.invoke.mockResolvedValue({...report,action:'helper'});const action=vi.fn(async()=>{});render(<SetupAssistant onAction={action}/>);
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 fireEvent.click(await screen.findByRole('button',{name:'Установить или обновить компонент macOS'}));
 expect(action).not.toHaveBeenCalled();expect(screen.getByText(/Установка может перезапустить VPN/)).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить настройку'}));await waitFor(()=>expect(action).toHaveBeenCalledWith('helper',expect.anything()));
});
it('active sessions cannot select another server and changed reports cannot recommend it',async()=>{
 ipc.invoke.mockResolvedValue({...report,action:'none',recommendation:{id:'other',name:'Проверенный',latency_ms:40}});
 render(<SetupAssistant onAction={vi.fn()} active/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 expect((await screen.findByRole('button',{name:'Выбрать рекомендуемый сервер'})).hasAttribute('disabled')).toBe(true);
 cleanup();ipc.invoke.mockResolvedValue({...report,action:'none',changed:true,recommendation:{id:'other',name:'Устаревший',latency_ms:40}});
 render(<SetupAssistant onAction={vi.fn()}/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));await screen.findByText(/HTTPS проверен/);
 expect(screen.queryByRole('button',{name:'Выбрать рекомендуемый сервер'})).toBeNull();
});
it('backend failure does not claim successful diagnostics or perform repairs',async()=>{
 ipc.invoke.mockRejectedValue(new Error('Проверка недоступна'));const action=vi.fn();render(<SetupAssistant onAction={action}/>);
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));await screen.findByText(/Проверка недоступна/);
 expect(action).not.toHaveBeenCalled();expect(screen.queryByText('HTTPS проверен')).toBeNull();
});
