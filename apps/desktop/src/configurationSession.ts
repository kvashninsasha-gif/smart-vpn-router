import {useState} from 'react';
export type ConfigurationOutcome={connected:boolean;verified:boolean;undo_id:string;message:string};
export function useConfigurationSession(){
 const [result,setResult]=useState<ConfigurationOutcome|null>(null);
 const [phase,setPhase]=useState<'preview'|'apply'|'undo'|'checking'|null>(null);
 const [message,setMessage]=useState('');
 const [operationId,setOperationId]=useState<string|null>(null);
 return {result,setResult,phase,setPhase,message,setMessage,operationId,setOperationId};
}
export type ConfigurationSession=ReturnType<typeof useConfigurationSession>;
