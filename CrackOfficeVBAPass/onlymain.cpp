//֧��office2003 32λ, office2007 32λ, office2010/2013/2016 32/64λ

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>


int Fuckit(HANDLE hProcess, MODULEENTRY32* me32, DWORD offset)
{
	BYTE datasig[3] = { 0x85,0xc0,0x75 };
	BYTE newbyte = 0x74;
	SIZE_T bytesread = 0, byteswrite = 0;
	BYTE databackup[3] = { 0 };

	ReadProcessMemory(hProcess, (LPCVOID)(me32->modBaseAddr + offset), databackup, 3, &bytesread);
	if (bytesread != 3)
	{
		printf("ReadProcessMemory Failed\n");
	}
	if (!memcmp(databackup, datasig, 3))
	{
		WriteProcessMemory(hProcess, (LPVOID)(me32->modBaseAddr + offset + 2), &newbyte, 1, &byteswrite);
		if (byteswrite == 1)
		{
			return TRUE;
		}
	}
	return FALSE;
}



int main(int argc, char** argv)
{
	//ָ��office����pid
	int nPID = 0;
	printf("\nUsage:CrackOfficeVBAPass.exe <PID> ||| �÷�:CrackOfficeVBAPass.exe <office����ID>\n");

	if (argc == 1)
	{
		printf("input target PID(decimal) |||  ����Ŀ�����ID(ʮ����)\n");
		scanf_s("%d", &nPID);
	}
	else if (argc > 2)
	{
		printf("only 1 parameter accepted ||| ��֧��һ������\n");
		return 0;
	}
	else
	{
		nPID = atoi(argv[1]);
		if (nPID == 0)
		{
			printf("PID must be digits ||| ��������ȫΪ����\n");
			return 0;
		}
	}
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ| PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, nPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("open process handle failed ||| ��Ŀ�����ʧ��\n");
	}
	BOOL bIs32 = FALSE;
	IsWow64Process(hProcess, &bIs32);

	HANDLE hSnap = (HANDLE)-1;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	if (bIs32)
	{
		hSnap = (HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, nPID);
	}
	else
	{
		hSnap = (HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, nPID);
	}
	Module32First(hSnap, &me32);

	BOOL fucked = FALSE;
	do 
	{
		_strlwr_s(me32.szModule);
		if ((!strcmp(me32.szModule, "vbe7.dll"))|| (!strcmp(me32.szModule, "vbe6.dll")))
		{
			//printf("lib found\n");
			switch (me32.modBaseSize)
			{
				case 0x26'4000: //2003 32
				{
					fucked = Fuckit(hProcess, &me32, 0x11f406);
					break;
				}
				case 0x27'8000: //2007 32
				{
					fucked = Fuckit(hProcess, &me32, 0x10aede);
					break;
				}
				case 0x28'd000: //2010 32
				{
					fucked = Fuckit(hProcess, &me32, 0x163bb5);
					break;
				}
				case 0x37'c000: //2010 64
				{
					fucked = Fuckit(hProcess, &me32, 0x1918E9);
					break;
				}
				case 0x27'd000: //2013 32
				{
					fucked = Fuckit(hProcess, &me32, 0x163ab2);
					break;
				}
				case 0x35'7000: //2013 64
				{
					fucked = Fuckit(hProcess, &me32, 0x19a9ff);
					break;
				}
				case 0x29'2000: //2016 32
				{
					fucked = Fuckit(hProcess, &me32, 0x165f09);
					break;
				}
				case 0x43'1000: //2016 64
				{
					fucked = Fuckit(hProcess, &me32, 0x21267f);
					break;
				}
				default:
				{
					printf("Unknown Office Version ||| δ֪office�汾\n");
					break;
				}
			}
		}
		if (fucked)
		{
			printf("Success ||| �ɹ�\n");
			break;
		}
	} while (Module32Next(hSnap,&me32));

	printf("Quit\n");
	system("pause");
	return 0;
}