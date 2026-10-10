import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {LocalAssistant} from '../src/LocalAssistant';
import type {SetupReport} from '../src/SetupAssistant';
const info={model:'Qwen3-0.6B',available:false,phase:'idle',downloaded:0,total:639446688};
const report:SetupReport={items:[],action:'connect',selected:'PRIVATE_SERVER_ID',recommendation:null,tested:1,total:2,changed:false,check_id:'opaque-backend-check'};
beforeEach(()=>{ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?info:undefined)});
afterEach(()=>{cleanup();vi.clearAllMocks()});
it('never downloads or starts inference automatically, and download cancellation makes no request',async()=>{
 render(<LocalAssistant report={null}/>);fireEvent.click(await screen.findByRole('button',{name:'Скачать ИИ-помощника'}));
 expect(screen.getByRole('dialog')).toBeTruthy();expect(ipc.invoke.mock.calls.map(c=>c[0])).toEqual(['ai_state']);
 fireEvent.click(screen.getByRole('button',{name:'Не сейчас'}));expect(ipc.invoke.mock.calls.map(c=>c[0])).toEqual(['ai_state']);
});
it('downloads only after explicit consent',async()=>{
 render(<LocalAssistant report={null}/>);fireEvent.click(await screen.findByRole('button',{name:'Скачать ИИ-помощника'}));
 fireEvent.click(screen.getByRole('button',{name:'Скачать модель'}));
 await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('ai_download',{consent:true}));
 expect(ipc.invoke.mock.calls.some(c=>c[0]==='ai_explain')).toBe(false);
});
it('sends only backend check ID and displays model output as text without performing repairs',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?{...info,available:true}:{text:'<script>run_shell()</script>',advice:'Проверьте подключение',elapsed_ms:123});
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Объяснить результаты с ИИ'}));
 await screen.findByText('<script>run_shell()</script>');
 expect(ipc.invoke).toHaveBeenCalledWith('ai_explain',{checkId:'opaque-backend-check'});
 expect(JSON.stringify(ipc.invoke.mock.calls)).not.toContain('PRIVATE_SERVER_ID');
 expect(document.querySelector('.ai-answer script')).toBeNull();
 expect(ipc.invoke.mock.calls.every(c=>['ai_state','ai_explain'].includes(c[0]))).toBe(true);
});
it('disables explanation for changed or missing diagnostics and respects application lock',async()=>{
 ipc.invoke.mockResolvedValue({...info,available:true});
 const view=render(<LocalAssistant report={{...report,changed:true}}/>);
 expect((await screen.findByRole('button',{name:'Объяснить результаты с ИИ'})).hasAttribute('disabled')).toBe(true);
 view.rerender(<LocalAssistant report={null}/>);expect(screen.getByRole('button',{name:'Объяснить результаты с ИИ'}).hasAttribute('disabled')).toBe(true);
 view.rerender(<LocalAssistant report={report} locked/>);expect(screen.getByRole('button',{name:'Объяснить результаты с ИИ'}).hasAttribute('disabled')).toBe(true);
});
it('allows cancellation while model download is in progress',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?{...info,phase:'download'}:undefined);
 render(<LocalAssistant report={null}/>);fireEvent.click(await screen.findByRole('button',{name:'Отменить действие ИИ'}));
 await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('ai_cancel'));
 expect(screen.getByRole('button',{name:'Скачать ИИ-помощника'}).hasAttribute('disabled')).toBe(true);
});
it('failed inference preserves ordinary diagnostic actions and claims no successful repair',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>{if(command==='ai_state')return {...info,available:true};throw new Error('Результаты устарели')});
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Объяснить результаты с ИИ'}));
 await screen.findByText(/Результаты устарели/);expect(screen.queryByText('Объяснение ИИ')).toBeNull();
});
