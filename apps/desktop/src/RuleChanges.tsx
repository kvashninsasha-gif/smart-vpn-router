import React from 'react';
export type RuleChange={domain:string;previous_route:string|null;next_route:string|null;previous_position:number|null;next_position:number|null};
const route=(value:string|null)=>value==='vpn'?'Через VPN':value==='direct'?'Напрямую':'Нет правила';
export function RuleChanges({changes}:{changes:RuleChange[]}){
 if(!changes.length)return null;
 return <div className="rule-changes"><b>Изменения правил ({changes.length})</b><ul>{changes.map(change=><li key={change.domain}>
  <strong>{change.domain}</strong>: {route(change.previous_route)} → {route(change.next_route)}
  {change.next_route===null?<span> · удалить</span>:change.previous_route===null?<span> · добавить, позиция {change.next_position}</span>:change.previous_position!==change.next_position?<span> · приоритет {change.previous_position} → {change.next_position}</span>:null}
 </li>)}</ul></div>;
}
