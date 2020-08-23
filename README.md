# DInvokeProcessHollowing
This repository is an implementation of process hollowing shellcode injection using DInvoke from SharpSploit. DInvoke allows operators to use unmanaged code while avoiding suspicious imports or API hooking.

The project contains an XOR encoded Calc.exe payload from msfvenom. If you'd like to use your own shellcode then it must be XOR encoded. This can done using the following program: https://github.com/passthehashbrowns/XorShellcode

# References
Original process hollowing implementation: https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
SharpSploit: https://github.com/cobbr/SharpSploit
DInvoke: https://thewover.github.io/Dynamic-Invoke/
Process Injection With DInvoke: https://rastamouse.me/blog/process-injection-dinvoke/
