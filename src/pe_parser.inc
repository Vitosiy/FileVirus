PeParser struct

    filename 	cword      ?   ;��� �����

    fd          HANDLE  ?   ;����� ��������� �����
    mapd        HANDLE  ?   ;����� �������� ��������
    mem	        cword   ?   ;��������� �� ������ ���������������� �����
    filesize    cword   ?   ;������ ��������������� ����� �����

    doshead     cword   ?   ;��������� �� DOS ���������
    nthead      cword   ?   ;��������� �� NT ���������

    impdir      cword   ?   ;��������� �� ������ ������������ ������� �������
    sizeImpdir  DWORD   ?   ;������ ������� �������
    countImpdes DWORD   ?   ;���������� ��������� � ������� �������

    expdir      cword   ?   ;��������� �� ������� ��������
    sizeExpdir  DWORD   ?   ;������ ������� ��������

    sections    cword   ?   ;��������� �� ������� ������ (�� ������ �������)
    countSec    DWORD   ?   ;���������� ������

PeParser ends


Space struct
    startRVA	DWORD	?
    endRVA		DWORD	?
    startRAW	DWORD	?
    endRAW		DWORD	?
    isize		DWORD	?
Space ends