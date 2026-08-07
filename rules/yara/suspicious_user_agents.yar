rule Suspicious_Scanner_UserAgent
{
    meta:
        description = "Detecta User-Agents de ferramentas de scanning conhecidas"
        severity = "medium"

    strings:
        $sqlmap = "sqlmap" nocase
        $nikto = "Nikto" nocase
        $nmap = "Nmap Scripting Engine" nocase
        $dirbuster = "DirBuster" nocase
        $masscan = "masscan" nocase

    condition:
        any of them
}