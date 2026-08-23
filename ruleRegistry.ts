export interface SecurityRuleDefinition {id:string;name:string;category:string;severity:string;cwe:string;confidence:string;description:string;remediation:string;}
export const SECURITY_RULES:SecurityRuleDefinition[]=[
{id:"SAST-DANGEROUS-EVAL",name:"Uso de eval()",category:"Dangerous Functions",severity:"CRITICAL",cwe:"CWE-95",confidence:"high",description:"Execução dinâmica de código pode permitir execução não confiável.",remediation:"Evite eval()."},
{id:"SAST-COMMAND-INJECTION",name:"Possível Command Injection",category:"Injection",severity:"HIGH",cwe:"CWE-78",confidence:"medium",description:"Comando construído com entrada dinâmica pode ser injetado.",remediation:"Use APIs de processo com argumentos separados."},
{id:"SAST-WEAK-HASH",name:"Algoritmo de hash fraco",category:"Cryptography",severity:"HIGH",cwe:"CWE-327",confidence:"high",description:"MD5/SHA-1 são inadequados para determinados usos de segurança.",remediation:"Use primitivas modernas adequadas ao objetivo."},
{id:"SAST-SQL-INJECTION",name:"Possível SQL Injection",category:"Injection",severity:"CRITICAL",cwe:"CWE-89",confidence:"medium",description:"SQL dinâmico pode permitir manipulação da consulta.",remediation:"Use queries parametrizadas."}
];
export function getSecurityRule(id:string){return SECURITY_RULES.find(r=>r.id===id);}
