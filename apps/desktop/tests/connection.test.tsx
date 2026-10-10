import React from 'react';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{}),enabled:vi.fn(async()=>false)}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
vi.mock('@tauri-apps/plugin-autostart',()=>({isEnabled:ipc.enabled,enable:vi.fn(),disable:vi.fn()}));
vi.mock('@tauri-apps/plugin-clipboard-manager',()=>({readText:vi.fn(),writeText:vi.fn()}));
vi.mock('@tauri-apps/plugin-dialog',()=>({open:vi.fn(),save:vi.fn()}));
import {App} from '../src/App';
import ru from '../../../locales/ru.json';
import type {Snapshot} from '../src/types';
let snapshot:Snapshot;
function fixture():Snapshot{return{status:'disconnected',proxy_port:null,core_version:'1.14.2',connection_plan:'needs_proxy_consent',logs:[],profile:{version:1,selected:'test',subscriptions:[],rules:[],servers:[{id:'test',name:'Тестовый сервер',address:'example.com',port:443,uuid:'public-test-fixture',transport:'tcp',security:'tls',params:{},favorite:false,group:'Основные',subscription:null,latency_ms:88,download_mbps:16.4,status:'available',successes:1,failures:0,last_error:null}],settings:{mode:'smart',tun:true,kill_switch:true,proxy_acknowledged:false,proxy_port:2080,dns_protection:true,dns_provider:'cloudflare',dns_transport:'https',auto_connect:false,start_minimized:false,restore:true,health_interval:30,failover:true,favorites_only:false,strategy:'balanced',subscription_interval:21600}}}}
beforeEach(()=>{snapshot=fixture();ipc.listen.mockImplementation(async()=>()=>{});ipc.invoke.mockReset();ipc.invoke.mockImplementation(async(command:string,args:any)=>{if(command==='snapshot')return structuredClone(snapshot);if(command==='prepare_proxy'){snapshot.profile.settings.tun=false;snapshot.profile.settings.kill_switch=false;snapshot.profile.settings.proxy_acknowledged=true;if(args?.windowsProxyAuto!==undefined)snapshot.profile.settings.windows_proxy_auto=args.windowsProxyAuto;snapshot.connection_plan='ready';return;}if(command==='connect'){snapshot.status='connected';snapshot.proxy_port=2080;return 2080;}throw new Error('Unexpected command '+command);});});
afterEach(cleanup);
async function ready(){render(<App/>);await screen.findByText('Тестовый сервер');}
describe('connection setup regression',()=>{
 it('Windows main app exposes local AI without applying its suggested proxy repair',async()=>{
  snapshot.platform='windows';snapshot.status='connected';snapshot.connection_plan='ready';
  const original=ipc.invoke.getMockImplementation()!;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{
   if(command==='ai_state')return {model:'Qwen3-0.6B',available:true,phase:'idle',downloaded:639446688,total:639446688};
   if(command==='setup_check')return {items:[{label:'Прокси Windows',ok:false,message:'Проверка завершена'}],action:'windows_proxy',selected:'test',recommendation:null,tested:0,total:1,changed:false,check_id:'windows-backend-check'};
   if(command==='ai_explain')return {text:'Параметры прокси требуют проверки.',advice:'Настройте Windows проверенной кнопкой.',elapsed_ms:50};
   return original(command,args);
  });
  await ready();
  const explain=await screen.findByRole('button',{name:'Объяснить результаты с ИИ'});
  expect(explain.hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
  await waitFor(()=>expect(explain.hasAttribute('disabled')).toBe(false));
  fireEvent.click(explain);await screen.findByText('Параметры прокси требуют проверки.');
  expect(ipc.invoke).toHaveBeenCalledWith('ai_explain',{checkId:'windows-backend-check'});
  expect(ipc.invoke.mock.calls.some(([c])=>['stop','connect','prepare_proxy','install_network_helper'].includes(c))).toBe(false);
  expect(snapshot.status).toBe('connected');
  expect(screen.queryByRole('button',{name:'Установить или обновить компонент macOS'})).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'Настроить Windows автоматически'}));
  expect(screen.getByRole('dialog',{name:'Подтверждение настройки'})).toBeTruthy();
  expect(ipc.invoke.mock.calls.some(([c])=>c==='prepare_proxy')).toBe(false);
  fireEvent.click(screen.getByRole('button',{name:'Отмена'}));
  expect(snapshot.status).toBe('connected');
 });
 it('Windows main app downloads optional AI only after consent without changing connection settings',async()=>{
  snapshot.platform='windows';const original=ipc.invoke.getMockImplementation()!;let available=false;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{
   if(command==='ai_state')return {model:'Qwen3-0.6B',available,phase:'idle',downloaded:0,total:639446688};
   if(command==='ai_download'){available=true;return;}
   return original(command,args);
  });
  await ready();fireEvent.click(await screen.findByRole('button',{name:'Скачать ИИ-помощника'}));
  expect(screen.getByRole('dialog',{name:'Загрузка ИИ-помощника'})).toBeTruthy();
  expect(ipc.invoke.mock.calls.some(([c])=>c==='ai_download')).toBe(false);
  fireEvent.click(screen.getByRole('button',{name:'Не сейчас'}));
  expect(ipc.invoke.mock.calls.some(([c])=>c==='ai_download')).toBe(false);
  fireEvent.click(screen.getByRole('button',{name:'Скачать ИИ-помощника'}));
  fireEvent.click(screen.getByRole('button',{name:'Скачать модель'}));
  await screen.findByRole('button',{name:'Объяснить результаты с ИИ'});
  expect(ipc.invoke).toHaveBeenCalledWith('ai_download',{consent:true});
  expect(ipc.invoke.mock.calls.some(([c])=>['connect','stop','prepare_proxy','save_settings','install_network_helper'].includes(c))).toBe(false);
  expect(snapshot.status).toBe('disconnected');
 });
 it('guided connect never toggles a connection that became active after the check',async()=>{
  const original=ipc.invoke.getMockImplementation()!;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{if(command==='setup_check')return {items:[],action:'connect',selected:'test',recommendation:null,tested:1,total:1,changed:false};return original(command,args)});
  await ready();fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
  await screen.findByRole('button',{name:'Перейти к подключению'});snapshot.status='connected';
  fireEvent.click(screen.getByRole('button',{name:'Перейти к подключению'}));
  await waitFor(()=>expect(screen.getAllByText(/Состояние подключения изменилось/).length).toBeGreaterThan(0));
  expect(ipc.invoke.mock.calls.some(([command])=>command==='connect'||command==='stop')).toBe(false);
 });

 it('Windows manual choice does not consent to changing OS proxy',async()=>{snapshot.platform='windows';await ready();fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Подключить только локальный прокси',exact:true}));await waitFor(()=>expect(snapshot.status).toBe('connected'));expect(snapshot.profile.settings.windows_proxy_auto).toBe(false);expect(ipc.invoke.mock.calls.find(([command])=>command==='prepare_proxy')?.[1]).toEqual({expectedSelected:'test',windowsProxyAuto:false});});

 it('Windows offers explicit proxy consent and hides unsupported macOS controls',async()=>{
  snapshot.platform='windows';await ready();
  expect(screen.getAllByText(/Windows: в этой сборке/).length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));
  expect(ipc.invoke.mock.calls.some(([command])=>command==='connect')).toBe(false);
  fireEvent.click(screen.getByRole('button',{name:'Подключить и настроить Windows',exact:true}));
  expect(ipc.invoke.mock.calls.find(([command])=>command==='prepare_proxy')?.[1]).toEqual({expectedSelected:'test',windowsProxyAuto:true});
  await waitFor(()=>expect(snapshot.status).toBe('connected'));
  expect(snapshot.profile.settings.tun).toBe(false);
  expect(snapshot.profile.settings.kill_switch).toBe(false);
  fireEvent.click(screen.getAllByRole('button',{name:'Настройки',exact:true})[0]);
  expect(screen.queryByRole('button',{name:'Установить сетевой компонент'})).toBeNull();
  expect(screen.queryByRole('button',{name:'Проверить компонент'})).toBeNull();
  expect(screen.queryByRole('button',{name:'Проверить защиту при обрыве'})).toBeNull();
  expect(screen.getByRole('button',{name:'Проверить сборку'})).toBeTruthy();
 });
 it('never position disables persisted auto measurements and retains last interval',async()=>{
  const original=ipc.invoke.getMockImplementation()!;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{if(command==='set_metric_settings'){snapshot.profile.settings.auto_metrics=args.enabled;snapshot.profile.settings.metric_interval=args.intervalSeconds;return;}return original(command,args)});
  await ready();const slider=screen.getByRole('slider',{name:'Обновлять показатели каждые'});
  fireEvent.change(slider,{target:{value:'61'}});fireEvent.keyUp(slider,{key:'End'});
  await screen.findByRole('button',{name:'Возобновить замеры'});
  expect(snapshot.profile.settings.auto_metrics).toBe(false);expect(snapshot.profile.settings.metric_interval).toBe(600);
  expect(slider.getAttribute('aria-valuetext')).toBe('Никогда');
 });
 it('offers one-minute interval and pauses readings without stopping VPN',async()=>{
  const original=ipc.invoke.getMockImplementation()!;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{if(command==='set_metric_settings'){snapshot.profile.settings.auto_metrics=args.enabled;snapshot.profile.settings.metric_interval=args.intervalSeconds;return;}return original(command,args)});
  snapshot.status='connected';snapshot.connection_plan='ready';await ready();
  const interval=screen.getByRole('slider',{name:'Обновлять показатели каждые'});
  expect((interval as HTMLInputElement).value).toBe('10');
  fireEvent.change(interval,{target:{value:'1'}});
  expect(ipc.invoke.mock.calls.some(([command])=>command==='set_metric_settings')).toBe(false);
  fireEvent.keyUp(interval,{key:'ArrowLeft'});
  await waitFor(()=>expect(snapshot.profile.settings.metric_interval).toBe(60));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Приостановить замеры'}).hasAttribute('disabled')).toBe(false));
  fireEvent.click(screen.getByRole('button',{name:'Приостановить замеры'}));
  await screen.findByRole('button',{name:'Возобновить замеры'});
  expect(snapshot.profile.settings.auto_metrics).toBe(false);
  expect(snapshot.status).toBe('connected');
  expect(ipc.invoke.mock.calls.some(([command])=>command==='stop')).toBe(false);
 });
 it('minute metric events update readings without resetting unsaved settings',async()=>{
  let update:((event:{payload:string})=>void)|undefined;
  ipc.listen.mockImplementation(async(event:string,callback:any)=>{if(event==='metrics-updated')update=callback;return ()=>{}});
  snapshot.status='connected';snapshot.connection_plan='ready';await ready();
  fireEvent.click(screen.getAllByRole('button',{name:'Настройки',exact:true})[0]);
  const port=screen.getByRole('spinbutton',{name:'Порт локального прокси'});
  fireEvent.change(port,{target:{value:'2090'}});
  await waitFor(()=>expect(update).toBeDefined());snapshot.profile.servers[0].latency_ms=99;
  update!({payload:''});await waitFor(()=>expect((port as HTMLInputElement).value).toBe('2090'));
  fireEvent.click(screen.getByRole('button',{name:'Обзор',exact:true}));await screen.findByText('99 мс');
 });
 it('file import invokes a native backend picker without accepting a WebView path',async()=>{const original=ipc.invoke.getMockImplementation()!;ipc.invoke.mockImplementation(async(command:string,...args:unknown[])=>{if(command==='import_file')return {added:1,duplicates:0,errors:[]};return original(command,...args)});await ready();fireEvent.click(screen.getByRole('button',{name:'Добавить сервер',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Из файла',exact:true}));await waitFor(()=>expect(ipc.invoke.mock.calls.some(([command])=>command==='import_file')).toBe(true));const call=ipc.invoke.mock.calls.find(([command])=>command==='import_file')!;expect(call[1]).toBeUndefined();});
 it('unknown helper state offers stop, and a rejected stop does not claim disconnection',async()=>{snapshot.status='unknown';snapshot.connection_plan='ready';const original=ipc.invoke.getMockImplementation()!;ipc.invoke.mockImplementation(async(command:string,...args:unknown[])=>{if(command==='stop')throw new Error('Остановка VPN не подтверждена');return original(command,...args)});await ready();expect(screen.getAllByText('Состояние VPN неизвестно').length).toBeGreaterThan(0);fireEvent.click(screen.getByRole('button',{name:'Отключиться',exact:true}));await screen.findByText('Остановка VPN не подтверждена');expect(ipc.invoke.mock.calls.some(([command])=>command==='stop')).toBe(true);expect(ipc.invoke.mock.calls.some(([command])=>command==='connect')).toBe(false);expect(screen.queryByText('Отключено')).toBeNull();});
 it('opens an explanation instead of sending the failing connect command',async()=>{await ready();fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));expect(screen.getByRole('dialog')).toBeTruthy();expect(screen.getByText(/Защиты при обрыве VPN нет/)).toBeTruthy();expect(ipc.invoke.mock.calls.some(([command])=>command==='connect'||command==='prepare_proxy')).toBe(false);});
 it('cancel keeps the existing protection settings and server intact',async()=>{await ready();const before=structuredClone(snapshot);fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Отмена',exact:true}));expect(screen.queryByRole('dialog')).toBeNull();expect(snapshot).toEqual(before);expect(ipc.invoke.mock.calls.some(([command])=>command==='prepare_proxy')).toBe(false);});
 it('explicit proxy selection prepares settings before connecting',async()=>{await ready();fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Подключить локальный прокси',exact:true}));await waitFor(()=>expect(ipc.invoke.mock.calls.some(([command])=>command==='connect')).toBe(true));const changes=ipc.invoke.mock.calls.filter(([command])=>command==='prepare_proxy'||command==='connect');expect(changes.map(([command])=>command)).toEqual(['prepare_proxy','connect']);expect(changes[0][1]).toEqual({expectedSelected:'test'});await screen.findByText('127.0.0.1:2080');});
 it('unsupported features are visibly unavailable rather than active switches',async()=>{await ready();fireEvent.click(screen.getAllByRole('button',{name:'Настройки',exact:true})[0]);expect(screen.getAllByText('Установите сетевой компонент foxVPN для VPN на всём ноутбуке.')).toHaveLength(2);expect(screen.queryByRole('checkbox',{name:/Блокировать защищаемый/})).toBeNull();});
 it('does not interrupt active TUN when automatic restoration is disabled',async()=>{snapshot.status='connected';snapshot.proxy_port=2080;snapshot.helper_available=true;snapshot.connection_plan='ready';snapshot.profile.settings.restore=false;await ready();fireEvent.click(screen.getAllByRole('button',{name:'Настройки',exact:true})[0]);const diagnostic=screen.getByRole('button',{name:'Проверить защиту при обрыве',exact:true});expect(diagnostic.hasAttribute('disabled')).toBe(true);fireEvent.click(diagnostic);expect(ipc.invoke.mock.calls.some(([command])=>command==='test_recovery')).toBe(false);});
 it('a previously accepted proxy mode connects without requesting consent again',async()=>{snapshot.profile.settings.tun=false;snapshot.profile.settings.kill_switch=false;snapshot.profile.settings.proxy_acknowledged=true;snapshot.connection_plan='ready';await ready();fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));await waitFor(()=>expect(ipc.invoke.mock.calls.some(([command])=>command==='connect')).toBe(true));expect(screen.queryByRole('dialog')).toBeNull();expect(ipc.invoke.mock.calls.some(([command])=>command==='prepare_proxy')).toBe(false);});
 it('clears an automatic recovery error after the connection is restored',async()=>{
  let callback:((event:{payload:string})=>void)|undefined;
  let status='reconnecting';
  ipc.listen.mockImplementation(async(event:string,handler:any)=>{if(event==='connection-error')callback=handler;return ()=>{}});
  const original=ipc.invoke.getMockImplementation()!;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{if(command==='runtime')return {status,proxy_port:null,logs:null,connection_error:null};if(command==='traffic')return {upload:0,download:0,vpn_upload:0,vpn_download:0,direct_upload:0,direct_download:0,connections:[]};return original(command,args)});
  snapshot.platform='windows';snapshot.connection_plan='ready';await ready();
  await waitFor(()=>expect(callback).toBeDefined());callback!({payload:'Тестовый сбой восстановления'});
  await screen.findByText('Тестовый сбой восстановления');status='connected';document.dispatchEvent(new Event('visibilitychange'));
  await waitFor(()=>expect(screen.queryByText('Тестовый сбой восстановления')).toBeNull());
 });
 it('clears a stale connect failure notice once the tunnel is up',async()=>{
  const failure='Не удалось подключиться к серверу. Подробности доступны в диагностике';
  let runtimeStatus='disconnected';
  const original=ipc.invoke.getMockImplementation()!;
  ipc.invoke.mockImplementation(async(command:string,args:any)=>{
   if(command==='runtime')return {status:runtimeStatus,proxy_port:null,logs:null,connection_error:null};
   if(command==='connect')throw new Error(failure);
   if(command==='traffic')return {upload:0,download:0,vpn_upload:0,vpn_download:0,direct_upload:0,direct_download:0,connections:[]};
   return original(command,args);
  });
  snapshot.connection_plan='ready';snapshot.helper_available=true;
  await ready();
  fireEvent.click(screen.getByRole('button',{name:'Подключиться',exact:true}));
  await screen.findByText(failure);
  runtimeStatus='connected';
  document.dispatchEvent(new Event('visibilitychange'));
  await waitFor(()=>expect(screen.queryByText(failure)).toBeNull());
 });
});
it('background server refresh keeps local edits and saving preserves new untouched fields',async()=>{
 let serverUpdate:((e:{payload:string})=>void)|undefined;
 ipc.listen.mockImplementation(async(event:string,callback:any)=>{if(event==='servers-updated')serverUpdate=callback;return ()=>{}});
 const original=ipc.invoke.getMockImplementation()!;
 ipc.invoke.mockImplementation(async(c:string,args:any)=>{if(c==='save_settings'){snapshot.profile.settings=args.settings;return}return original(c,args)});
 await ready();fireEvent.click(screen.getAllByRole('button',{name:'Настройки',exact:true})[0]);
 const port=screen.getByRole('spinbutton',{name:'Порт локального прокси'});fireEvent.change(port,{target:{value:'2090'}});
 snapshot.profile.settings.metric_interval=1200;serverUpdate?.({payload:''});
 await waitFor(()=>expect((port as HTMLInputElement).value).toBe('2090'));
 fireEvent.click(screen.getByRole('button',{name:'Сохранить',exact:true}));
 await waitFor(()=>expect(snapshot.profile.settings.proxy_port).toBe(2090));expect(snapshot.profile.settings.metric_interval).toBe(1200);
 await waitFor(()=>expect(screen.queryByRole('button',{name:'Отменить изменения настроек'})).toBeNull());
});
it('autostart lookup failure does not prevent metric listeners from updating the screen',async()=>{
 ipc.enabled.mockRejectedValueOnce('Автозапуск запрещён');let update:((e:{payload:string})=>void)|undefined;
 ipc.listen.mockImplementation(async(event:string,callback:any)=>{if(event==='metrics-updated')update=callback;return ()=>{}});
 await ready();await waitFor(()=>expect(update).toBeDefined());snapshot.profile.servers[0].latency_ms=42;update?.({payload:''});await screen.findByText('42 мс');
});
it('editing a subscription sends its identity and preserves other records',async()=>{
 snapshot.profile.subscriptions=[{id:'sub-test',name:'Список',url:'https://example.com/old',updated_at:1,server_count:2}];
 const original=ipc.invoke.getMockImplementation()!;ipc.invoke.mockImplementation(async(c:string,args:any)=>{if(c==='edit_subscription'){snapshot.profile.subscriptions[0]={...snapshot.profile.subscriptions[0],name:args.name,url:args.url};return}return original(c,args)});
 await ready();fireEvent.click(screen.getByRole('button',{name:'Подписки',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Редактировать подписку Список'}));
 const dialog=screen.getByRole('dialog');const inputs=dialog.querySelectorAll('input');fireEvent.change(inputs[0],{target:{value:'Новый список'}});fireEvent.change(inputs[1],{target:{value:'https://example.com/new'}});
 fireEvent.click(screen.getByRole('button',{name:'Сохранить',exact:true}));await screen.findByText('Новый список');
 expect(ipc.invoke).toHaveBeenCalledWith('edit_subscription',{id:'sub-test',name:'Новый список',url:'https://example.com/new'});expect(snapshot.profile.subscriptions).toHaveLength(1);
});
it('a Windows profile imported from Mac never presents local proxy as whole-computer VPN',async()=>{
 snapshot.platform='windows';snapshot.status='connected';snapshot.proxy_port=2080;snapshot.connection_plan='ready';snapshot.profile.settings.tun=true;
 await ready();expect(screen.queryByText(ru.tun_scope)).toBeNull();await screen.findByText('127.0.0.1:2080');
 expect(screen.getAllByText(ru.windows_proxy_scope).length).toBeGreaterThan(0);
});
